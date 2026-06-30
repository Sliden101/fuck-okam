"""
OKAM Camera Session Manager
============================
High-level API for connecting to OKAM cameras through the P2P relay.

Uses replay-based signaling (valid signatures from pcap) to query the
P2P signaling server, then connects to the relay via UDP PPPP to
authenticate and receive H.264 video.

Usage:
    camera = OKAMCamera('VE3326855YITZ', 'admin', '888888')
    camera.connect()
    for frame in camera.stream():
        # frame is H.264 NAL data
        pass
    camera.close()
"""

import socket
import struct
import time
import threading
import json
import logging
import sys
import os
from typing import Optional, Iterator, Callable

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pppp import (
    create_psk_hash, pppp_encrypt, pppp_decrypt,
    parse_pppp_packet, parse_drw_packet, parse_cgi_response, parse_cgi_result,
    build_pppp_packet, build_drw_packet, build_cgi_command,
    OP_KEEPALIVE, OP_CONTROL, OP_IDENTIFY, OP_MSG_DRW, OP_MSG_DRW_ACK,
    OP_MSG_ALIVE, OP_MSG_ALIVE_ACK, OP_MSG_CLOSE,
    CHANNEL_COMMAND, CHANNEL_VIDEO, VIDEO_MARKER,
)

log = logging.getLogger(__name__)


# Replay signatures from pcap captures (both old and fresh)
REPLAY_SIGNATURES = {
    # Old pcap (joebiden.pcapng)
    ('getDeviceInfo', 'VE3326855YITZ', '1782759886'): ('2976', 'cra5eLkjxiO2Ce908ud91NjA6RQ='),
    ('getDeviceInfo', 'ADG0259097RGBG', '1782759886'): ('8530', 'pU3ijk5VsQksJnmCpS8LbTmJFU4='),
    ('register', '', '1782759887'): ('5951', 'L2BsWLGpRJkj6uQQ52rzD3GF5Bk='),
    # Fresh pcap (joebiden2.pcapng)
    ('getDeviceInfo', 'VE3326855YITZ', '1782815528'): ('9210', 'jDzKSz7TLwRHee7rBAuzvyesPiE='),
    ('getDeviceInfo', 'ADG0259097RGBG', '1782815528'): ('6025', 'xdiUifvagu/gTP2SVJA7tPOVZTM='),
    ('register', '', '1782815529'): ('2300', 'k9j2npfFIC+GJBamytCKn+YjtVk='),
    ('toDevice', 'ADG0259097RGBG', '1782815529'): ('799', 'cREz+NJ2LFyMdBhY9+ideytgvqk='),
    ('getStatus', 'ADG0259097RGBG', '1782815529'): ('7281', 'SOb6BMAOcixq1DWNygjEup45W24='),
}

# Default servers
SIGNALING_SERVERS = [
    ('47.91.201.49', 32320),
    ('198.11.174.54', 12320),
]

DEFAULT_ACCESS_KEY = 'k3cTHvusdOyyrTKp'
DEFAULT_PSK = 'vstarcam2019'


class OKAMCamera:
    """High-level OKAM camera client."""
    
    def __init__(self, did: str, username: str = 'admin', password: str = '888888',
                 access_key: str = DEFAULT_ACCESS_KEY):
        self.did = did
        self.username = username
        self.password = password
        self.access_key = access_key
        
        self.key4 = create_psk_hash(DEFAULT_PSK)
        self.relay_ip = None
        self.relay_port = None
        
        self._sock = None
        self._connected = False
        self._authenticated = False
        self._streaming = False
        self._drw_index = 0
        
        self._running = False
        self._recv_thread = None
        
        # Video frame buffer
        self._frame_buffer = bytearray()
        self._frame_boundaries = []
        self._latest_frame = None
        self._frame_lock = threading.Lock()
        self._frame_event = threading.Event()
    
    def _build_replay_message(self, event: str) -> dict:
        """Build a signaling message with a replay signature.
        
        Args:
            event: Event type ('getDeviceInfo', 'register', etc.)
        
        Returns:
            Dictionary ready for JSON serialization
        """
        # Use fresh timestamps from joebiden2.pcapng
        base = {
            'event': event,
            'AccessKey': self.access_key,
            'timestamp': '1782815529' if event == 'register' else '1782815528',
        }
        
        if self.did:
            base['did'] = self.did
        
        # Find matching replay signature
        sig_key = (event, self.did if 'Info' in event else '', base['timestamp'])
        if sig_key in REPLAY_SIGNATURES:
            base['sign'], base['signature'] = REPLAY_SIGNATURES[sig_key]
        
        return base
    
    def _send_signaling(self, sock: socket.socket, message: dict) -> Optional[dict]:
        """Send a signaling message and receive response.
        
        Args:
            sock: TCP socket to signaling server
            message: Dictionary to send as JSON
        
        Returns:
            Response dictionary, or None on error
        """
        json_data = json.dumps(message, separators=(', ', ': '))
        json_bytes = json_data.encode('utf-8')
        sock.sendall(struct.pack('>I', len(json_bytes)) + json_bytes)
        
        # Read response length
        len_data = sock.recv(4)
        if len(len_data) != 4:
            return None
        
        resp_len = struct.unpack('>I', len_data)[0]
        resp_data = b''
        while len(resp_data) < resp_len:
            chunk = sock.recv(resp_len - len(resp_data))
            if not chunk:
                break
            resp_data += chunk
        
        if not resp_data:
            return None
        
        return json.loads(resp_data.decode('utf-8'))
    
    def get_relay_assignment(self) -> Optional[tuple]:
        """Get relay IP:port assignment from signaling server.
        
        Returns:
            (ip, port) tuple, or None on failure
        """
        log.info('Querying signaling server for relay assignment...')
        
        for host, port in SIGNALING_SERVERS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((host, port))
                
                # Register first (if on register server)
                if host == '198.11.174.54':
                    msg = self._build_replay_message('register')
                    resp = self._send_signaling(sock, msg)
                    if not resp or 'event' not in resp:
                        sock.close()
                        continue
                    log.debug(f'Register response: {resp}')
                
                # Get device info
                msg = self._build_replay_message('getDeviceInfo')
                resp = self._send_signaling(sock, msg)
                sock.close()
                
                if resp and resp.get('ret') == 0:
                    ip = resp.get('node_ip')
                    port = resp.get('node_port')
                    if ip and port:
                        log.info(f'Relay assignment: {ip}:{port}')
                        return (ip, port)
                
                log.debug(f'Signaling response: {resp}')
                
            except Exception as e:
                log.debug(f'Signaling error ({host}:{port}): {e}')
                continue
        
        log.warning('Failed to get relay assignment')
        return None
    
    def _register_session(self) -> bool:
        """Register our session with the relay infrastructure.
        Must be called before connecting to the relay.
        
        Returns:
            True if registered on at least one server
        """
        registered = False
        
        # Register on 119.23.227.151:32320 (relay hub)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(('119.23.227.151', 32320))
            
            # Use fresh register signature (from joebiden2.pcapng)
            reg_msg = {
                'event': 'register',
                'AccessKey': self.access_key,
                'timestamp': '1782815529',
                'sign': '2300',
                'signature': 'k9j2npfFIC+GJBamytCKn+YjtVk=',
            }
            resp = self._send_signaling(sock, reg_msg)
            if resp and resp.get('event') == 'register':
                log.info('Registered on relay hub 119.23.227.151:32320')
                registered = True
            sock.close()
        except Exception as e:
            log.debug(f'Register on 119.23.227.151 failed: {e}')
        
        # Register on 198.11.174.54:12320 (registration server)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(('198.11.174.54', 12320))
            
            reg_msg = {
                'event': 'register',
                'AccessKey': self.access_key,
                'timestamp': '1782815529',
                'sign': '2300',
                'signature': 'k9j2npfFIC+GJBamytCKn+YjtVk=',
            }
            resp = self._send_signaling(sock, reg_msg)
            if resp and resp.get('event') == 'register':
                log.info('Registered on 198.11.174.54:12320')
                registered = True
            sock.close()
        except Exception as e:
            log.debug(f'Register on 198.11.174.54 failed: {e}')
        
        return registered
    
    def get_relay_candidates(self) -> list:
        """Get all relay IP:port candidates from signaling + discovery + known list.
        
        Returns:
            List of (ip, port) tuples, best candidates first
        """
        candidates = []
        
        # 1. From signaling server (replay)
        assignment = self._get_signaling_assignment()
        if assignment:
            candidates.append(assignment)
            # Also try common PPPP ports on the relay host
            for port in [32100, 32108, 3993, 6582, 12320]:
                if (assignment[0], port) not in candidates:
                    candidates.append((assignment[0], port))
        
        # 2. From PPPP discovery servers (port 32100)
        discovery_ips = self._get_discovery_relays()
        for ip in discovery_ips:
            for port in [32100, 32108, 3993, 6582, 20000, 32320, 12320]:
                if (ip, port) not in candidates:
                    candidates.append((ip, port))
        
        # 3. Known relay IPs from pcap captures - try these FIRST
        KNOWN_RELAYS = [
            ('119.15.90.42', 3993),      # Fresh pcap video relay
            ('119.15.90.42', 6582),      # Old pcap video relay
            ('119.15.90.42', 32100),     # Discovery port
            ('119.23.227.151', 32320),   # Signaling relay
            ('119.23.227.151', 32100),   # Discovery port
        ]
        for ip, port in KNOWN_RELAYS:
            if (ip, port) not in candidates:
                candidates.insert(0, (ip, port))  # Prepend - try first
        
        return candidates
    
    def _get_signaling_assignment(self) -> Optional[tuple]:
        """Get relay assignment from signaling server."""
        for host, port in SIGNALING_SERVERS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((host, port))
                
                msg = self._build_replay_message('getDeviceInfo')
                resp = self._send_signaling(sock, msg)
                sock.close()
                
                if resp and resp.get('ret') == 0:
                    ip = resp.get('node_ip')
                    port = resp.get('node_port')
                    if ip and port:
                        return (ip, port)
            except:
                continue
        return None
    
    def _get_discovery_relays(self) -> list:
        """Query PPPP discovery servers and return list of relay IPs."""
        ips = []
        hello = build_pppp_packet(0x00, b'', self.key4)  # MSG_HELLO
        
        for server in ['150.109.181.22', '161.117.10.18', '47.254.241.56']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                sock.bind(('0.0.0.0', 0))
                sock.sendto(hello, (server, 32100))
                
                data, addr = sock.recvfrom(4096)
                dec = pppp_decrypt(self.key4, data)
                
                if len(dec) >= 12:
                    # Format: f1 01 00 10 0002 XXXX YYYY.YYYY 0000...
                    # Bytes 6-9 are relay IP (4 bytes, network order)
                    a, b, c, d = struct.unpack('BBBB', dec[6:10])
                    ip = f'{a}.{b}.{c}.{d}'
                    if ip not in ips:
                        ips.append(ip)
                        log.debug(f'Discovery {server} -> relay IP {ip}')
                
                sock.close()
            except socket.timeout:
                pass
            except Exception as e:
                log.debug(f'Discovery {server} error: {e}')
        
        return ips
    
    def connect(self) -> bool:
        """Connect to the camera through the P2P relay.
        Registers our session, then tries all relay candidates.
        
        Returns:
            True if connected successfully
        """
        # Step 0: Register our session with relay infrastructure
        log.info('Registering session...')
        self._register_session()
        
        # Step 1: Get relay candidates
        candidates = self.get_relay_candidates()
        log.info(f'Trying {len(candidates)} relay candidates...')
        
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(2.0)
            self._sock.bind(('0.0.0.0', 0))
            
            # Build IDENTIFY with DID (from pcap decryption)
            did_prefix = b'VSTL\x00\x00\x00\x00'
            did_serial = struct.pack('>I', 896293)
            did_check = b'CRMVN\x00\x00\x00'
            identify_payload = did_prefix + did_serial + did_check
            while len(identify_payload) < 28:
                identify_payload += b'\x00'
            identify = build_pppp_packet(OP_IDENTIFY, identify_payload[:28], self.key4)
            keepalive = build_pppp_packet(OP_KEEPALIVE, b'', self.key4)
            
            for ip, port in candidates:
                log.debug(f'Trying {ip}:{port}...')
                
                # Send IDENTIFY first (phone does this), then KEEPALIVE
                self._sock.sendto(identify, (ip, port))
                time.sleep(0.05)
                self._sock.sendto(keepalive, (ip, port))
                
                for _ in range(3):  # 3 quick retries
                    try:
                        data, addr = self._sock.recvfrom(4096)
                        parsed = parse_pppp_packet(data, self.key4)
                        
                        if parsed:
                            opname = parsed['opcode_name']
                            log.info(f'{ip}:{port} -> {opname} ({len(data)}B)')
                            
                            if opname in ('CONTROL', 'IDENTIFY', 'KEEPALIVE'):
                                self.relay_ip = ip
                                self.relay_port = port
                                self._connected = True
                                self._sock.settimeout(5.0)
                                log.info(f'Connected to relay {ip}:{port}')
                                return True
                            
                    except socket.timeout:
                        break  # Try next candidate
            
            log.warning('No relay responded')
            return False
            
        except Exception as e:
            log.error(f'Connection failed: {e}')
            self._sock = None
            return False
    
    def authenticate(self) -> bool:
        """Authenticate with the camera.
        
        Returns:
            True if authenticated successfully
        """
        if not self._connected:
            return False
        
        log.info('Authenticating...')
        
        cgi = (
            f'/get_status.cgi?'
            f'loginuse={self.username}'
            f'&loginpas=ac0b2702856222'
            f'&user={self.username}'
            f'&pwd={self.password}'
        )
        
        self._send_command(cgi)
        
        # Wait for auth response
        start_time = time.time()
        while time.time() - start_time < 15.0:
            data = self._recv_packet(3.0)
            if not data:
                continue
            
            parsed = parse_pppp_packet(data, self.key4)
            if not parsed or parsed['opcode'] != OP_MSG_DRW:
                continue
            
            drw = parse_drw_packet(parsed['payload'])
            if not drw or drw['channel'] != CHANNEL_COMMAND:
                continue
            
            self._send_ack(drw['channel'], drw['index'])
            
            text = parse_cgi_response(drw['data'])
            if not text:
                continue
            
            log.debug(f'Auth response: {text[:100]}')
            result = parse_cgi_result(text)
            
            if result and result.get('result') == 0:
                log.info(f'Authenticated! deviceid={result.get("deviceid")}')
                self._authenticated = True
                return True
        
        log.warning('Authentication timeout')
        return False
    
    def start_stream(self) -> bool:
        """Start the video stream.
        
        Returns:
            True if stream started
        """
        if not self._authenticated:
            return False
        
        log.info('Starting video stream...')
        
        # Eye4 authentication
        cgi = (
            f'/eye4_authentication.cgi?'
            f'loginAccount=207455122'
            f'&loginToken=J6SG3%2BCcjgZzjqPFbReMyIWXpeGLqEQ2GOy2QgA9hHuenM%2FXVNdAM%2BE9Iyzo3uMsVo97N0th9s3sDhGu20z%2FSg%3D%3D'
            f'&loginuse={self.username}'
            f'&loginpas=ac0b2702856222'
        )
        self._send_command(cgi)
        
        # Wait for video data on channel 1
        start_time = time.time()
        while time.time() - start_time < 15.0:
            data = self._recv_packet(3.0)
            if not data:
                continue
            
            parsed = parse_pppp_packet(data, self.key4)
            if not parsed or parsed['opcode'] != OP_MSG_DRW:
                continue
            
            drw = parse_drw_packet(parsed['payload'])
            if not drw:
                continue
            
            self._send_ack(drw['channel'], drw['index'])
            
            if drw['channel'] == CHANNEL_VIDEO:
                log.info('Video stream started')
                self._streaming = True
                self._handle_video(drw['data'])
                return True
        
        log.warning('Stream start timeout')
        return False
    
    def _send_command(self, cgi_path: str):
        """Send CGI command to camera over the relay."""
        cmd_data = build_cgi_command(cgi_path)
        drw_payload = build_drw_packet(CHANNEL_COMMAND, self._drw_index, cmd_data)
        self._drw_index += 1
        packet = build_pppp_packet(OP_MSG_DRW, drw_payload, self.key4)
        self._sock.sendto(packet, (self.relay_ip, self.relay_port))
    
    def _send_ack(self, channel: int, index: int):
        """Send DRW acknowledgment."""
        ack = struct.pack('>BBH', 0xD1, channel, 1, index)
        packet = build_pppp_packet(OP_MSG_DRW_ACK, ack, self.key4)
        self._sock.sendto(packet, (self.relay_ip, self.relay_port))
    
    def _send_keepalive(self):
        """Send keepalive to maintain connection."""
        packet = build_pppp_packet(OP_MSG_ALIVE_ACK, b'', self.key4)
        self._sock.sendto(packet, (self.relay_ip, self.relay_port))
    
    def _recv_packet(self, timeout: float = 5.0) -> Optional[bytes]:
        """Receive a packet from the relay."""
        if not self._sock:
            return None
        try:
            self._sock.settimeout(timeout)
            data, addr = self._sock.recvfrom(8192)
            return data
        except socket.timeout:
            return None
        except OSError:
            return None
    
    def _handle_video(self, data: bytes):
        """Process video data from channel 1."""
        # Check for video frame marker
        if data[:4] == VIDEO_MARKER:
            self._frame_boundaries.append(len(self._frame_buffer))
            video_data = data[32:]  # Skip 32-byte header
        else:
            video_data = data
        
        self._frame_buffer.extend(video_data)
        
        # Extract complete frames
        while len(self._frame_boundaries) >= 2:
            start = self._frame_boundaries[0]
            end = self._frame_boundaries[1]
            frame_data = bytes(self._frame_buffer[start:end])
            
            with self._frame_lock:
                self._latest_frame = frame_data
            
            self._frame_event.set()
            
            # Remove processed data
            self._frame_buffer = self._frame_buffer[end:]
            self._frame_boundaries = [b - end for b in self._frame_boundaries[1:]]
    
    def stream(self) -> Iterator[bytes]:
        """Generator that yields H.264 video frames.
        
        Must call connect() + authenticate() + start_stream() first.
        
        Yields:
            H.264 frame data (bytes)
        """
        self._running = True
        last_keepalive = time.time()
        
        while self._running:
            data = self._recv_packet(5.0)
            
            if data:
                parsed = parse_pppp_packet(data, self.key4)
                
                if parsed and parsed['opcode'] == OP_MSG_DRW:
                    drw = parse_drw_packet(parsed['payload'])
                    if drw:
                        self._send_ack(drw['channel'], drw['index'])
                        
                        if drw['channel'] == CHANNEL_VIDEO:
                            self._handle_video(drw['data'])
                        
                        elif drw['channel'] == CHANNEL_COMMAND:
                            text = parse_cgi_response(drw['data'])
                            if text:
                                log.debug(f'CMD: {text[:100]}')
                
                elif parsed and parsed['opcode'] == OP_MSG_ALIVE:
                    self._send_keepalive()
                
                elif parsed and parsed['opcode'] == OP_MSG_CLOSE:
                    log.warning('Relay closed connection')
                    break
            
            # Send periodic keepalive
            if time.time() - last_keepalive > 30.0:
                self._send_keepalive()
                last_keepalive = time.time()
            
            # Yield any new frames
            with self._frame_lock:
                if self._latest_frame:
                    frame = self._latest_frame
                    self._latest_frame = None
                    self._frame_event.clear()
                    yield frame
    
    def snapshot(self, timeout: float = 15.0) -> Optional[bytes]:
        """Get a single video frame.
        
        Args:
            timeout: Maximum time to wait for a frame
        
        Returns:
            H.264 frame data, or None on timeout
        """
        self._frame_event.clear()
        
        if self._frame_event.wait(timeout):
            with self._frame_lock:
                return self._latest_frame
        
        return None
    
    def close(self):
        """Close connection and cleanup."""
        self._running = False
        
        if self._sock:
            try:
                close_pkt = build_pppp_packet(OP_MSG_CLOSE, b'', self.key4)
                for _ in range(3):
                    self._sock.sendto(close_pkt, (self.relay_ip, self.relay_port))
                    time.sleep(0.1)
                self._sock.close()
            except:
                pass
            self._sock = None
        
        self._connected = False
        self._authenticated = False
        self._streaming = False
        log.info('Disconnected')
    
    @property
    def is_connected(self) -> bool:
        return self._connected
    
    @property
    def is_streaming(self) -> bool:
        return self._streaming


def main():
    """CLI entry point for testing."""
    import sys
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')
    
    did = sys.argv[1] if len(sys.argv) > 1 else 'VE3326855YITZ'
    user = sys.argv[2] if len(sys.argv) > 2 else 'admin'
    pwd = sys.argv[3] if len(sys.argv) > 3 else '888888'
    
    camera = OKAMCamera(did, user, pwd)
    
    if camera.connect():
        if camera.authenticate():
            if camera.start_stream():
                log.info('Streaming! Press Ctrl+C to stop.')
                try:
                    for i, frame in enumerate(camera.stream()):
                        if i % 30 == 0:
                            log.info(f'Frame {i}: {len(frame)} bytes')
                        # In production, pipe to ffmpeg here
                except KeyboardInterrupt:
                    pass
            else:
                log.error('Failed to start stream')
        else:
            log.error('Authentication failed')
    else:
        log.error('Failed to connect (camera offline?)')
    
    camera.close()


if __name__ == '__main__':
    main()
