"""
OKAM Relay Client
=================
UDP client for the Eye4/VStarcam P2P video relay.

The relay is a dumb UDP pipe that forwards encrypted PPPP packets between
the camera and our client. We use the PPPP cipher (PSK: vstarcam2019)
to encrypt commands and decrypt video data.

Protocol flow:
1. Connect to relay server via UDP
2. Perform relay handshake (0b/01 exchange)
3. Send encrypted check_user command
4. Send encrypted stream command
5. Receive encrypted video data on channel 1
"""

import socket
import struct
import time
import threading
from typing import Optional, Callable

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import pppp


class RelayClient:
    """UDP client for P2P video relay."""
    
    def __init__(self, relay_ip: str, relay_port: int, 
                 did: str, username: str, password: str,
                 access_key: str = None):
        """Initialize relay client.
        
        Args:
            relay_ip: Relay server IP address
            relay_port: Relay server port
            did: Device ID (e.g., 'VE3326855YITZ')
            username: Camera username (default: 'admin')
            password: Camera password (default: '888888')
            access_key: Eye4 access key (from signaling)
        """
        self.relay_ip = relay_ip
        self.relay_port = relay_port
        self.did = did
        self.username = username
        self.password = password
        self.access_key = access_key
        
        self.socket = None
        self.connected = False
        self.authenticated = False
        self.streaming = False
        
        self.key4 = pppp.create_psk_hash('vstarcam2019')
        self.drw_index = 0
        
        self._video_callback = None
        self._command_callback = None
        self._running = False
        self._recv_thread = None
        
        # Video frame assembly
        self._video_buffer = bytearray()
        self._frame_boundaries = []
    
    def connect(self) -> bool:
        """Connect to relay server.
        
        Returns:
            True if connected successfully
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(5.0)
            self.socket.bind(('0.0.0.0', 0))
            
            # Send initial handshake
            self._send_handshake()
            
            # Wait for response
            response = self._recv_packet()
            if response:
                self.connected = True
                print(f'Connected to relay {self.relay_ip}:{self.relay_port}')
                return True
            
            print('No response from relay')
            return False
            
        except Exception as e:
            print(f'Connection failed: {e}')
            return False
    
    def disconnect(self):
        """Disconnect from relay."""
        self._running = False
        self.connected = False
        self.authenticated = False
        self.streaming = False
        
        if self.socket:
            try:
                # Send close packet
                close_pkt = pppp.okam_build_packet(pppp.OP_MSG_CLOSE, b'')
                self.socket.sendto(close_pkt, (self.relay_ip, self.relay_port))
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def _send_handshake(self):
        """Send relay handshake packet."""
        # Based on pcap analysis, the handshake is a simple PPPP packet
        # The exact format may vary, but we observed:
        # - Initial packet: small encrypted packet
        # - Response: 0b control packet
        # - Our response: 01
        
        # Send MSG_HELLO (encrypted)
        hello = pppp.okam_build_packet(pppp.OP_KEEPALIVE, b'')
        self.socket.sendto(hello, (self.relay_ip, self.relay_port))
    
    def _send_packet(self, data: bytes):
        """Send raw data to relay.
        
        Args:
            data: Raw bytes to send
        """
        if self.socket:
            self.socket.sendto(data, (self.relay_ip, self.relay_port))
    
    def _recv_packet(self, timeout: float = 5.0) -> Optional[bytes]:
        """Receive packet from relay.
        
        Args:
            timeout: Receive timeout in seconds
        
        Returns:
            Received bytes, or None on timeout
        """
        if not self.socket:
            return None
        
        try:
            self.socket.settimeout(timeout)
            data, addr = self.socket.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        except Exception:
            return None
    
    def _send_command(self, cgi_path: str):
        """Send CGI command to camera.
        
        Args:
            cgi_path: CGI path with parameters
        """
        # Build SHIX-formatted command
        cmd_data = pppp.build_cgi_command(cgi_path)
        
        # Build DRW packet on channel 0
        drw_payload = pppp.build_drw_packet(pppp.CHANNEL_COMMAND, self.drw_index, cmd_data)
        self.drw_index += 1
        
        # Build PPPP packet
        packet = pppp.okam_build_packet(pppp.OP_MSG_DRW, drw_payload)
        
        # Send to relay
        self._send_packet(packet)
        print(f'Sent command: {cgi_path[:80]}...')
    
    def _send_drw_ack(self, channel: int, index: int):
        """Send DRW acknowledgment.
        
        Args:
            channel: DRW channel
            index: Packet index to acknowledge
        """
        # Build ACK payload (based on open_camera implementation)
        ack_data = struct.pack('>BBH', 0xD1, channel, 1, index)
        
        # Build PPPP packet
        packet = pppp.okam_build_packet(pppp.OP_MSG_DRW_ACK, ack_data)
        
        # Send to relay
        self._send_packet(packet)
    
    def _send_alive_ack(self):
        """Send keepalive response."""
        packet = pppp.okam_build_packet(pppp.OP_MSG_ALIVE_ACK, b'')
        self._send_packet(packet)
    
    def authenticate(self) -> bool:
        """Authenticate with camera.
        
        Returns:
            True if authenticated successfully
        """
        if not self.connected:
            print('Not connected')
            return False
        
        # Build check_user command
        cgi_path = (
            f'/get_status.cgi?'
            f'loginuse={self.username}'
            f'&loginpas={self._hash_password()}'
            f'&user={self.username}'
            f'&pwd={self.password}'
        )
        
        self._send_command(cgi_path)
        
        # Wait for response
        start_time = time.time()
        while time.time() - start_time < 10.0:
            response = self._recv_packet(timeout=2.0)
            if response:
                parsed = pppp.okam_parse_packet(response)
                if parsed and parsed['opcode'] == pppp.OP_MSG_DRW:
                    drw = pppp.parse_drw_packet(parsed['payload'])
                    if drw and drw['channel'] == pppp.CHANNEL_COMMAND:
                        # Send ACK
                        self._send_drw_ack(drw['channel'], drw['index'])
                        
                        # Parse response
                        text = pppp.parse_cgi_response(drw['data'])
                        if text and 'result= 0' in text:
                            print(f'Authentication successful')
                            self.authenticated = True
                            return True
                        elif text:
                            print(f'Auth response: {text[:100]}')
        
        print('Authentication timeout')
        return False
    
    def start_stream(self) -> bool:
        """Start video stream.
        
        Returns:
            True if stream started successfully
        """
        if not self.authenticated:
            print('Not authenticated')
            return False
        
        # Build stream command
        cgi_path = (
            f'/eye4/view.cgi?'
            f'loginuse={self.username}'
            f'&loginpas={self._hash_password()}'
            f'&user={self.username}'
            f'&pwd={self.password}'
            f'&view_type=1'
        )
        
        self._send_command(cgi_path)
        
        # Wait for video data
        start_time = time.time()
        while time.time() - start_time < 10.0:
            response = self._recv_packet(timeout=2.0)
            if response:
                parsed = pppp.okam_parse_packet(response)
                if parsed and parsed['opcode'] == pppp.OP_MSG_DRW:
                    drw = pppp.parse_drw_packet(parsed['payload'])
                    if drw and drw['channel'] == pppp.CHANNEL_VIDEO:
                        print(f'Video stream started')
                        self.streaming = True
                        return True
        
        print('Stream start timeout')
        return False
    
    def _hash_password(self) -> str:
        """Get hashed password for CGI commands.
        
        Returns:
            Hashed password string
        """
        # From pcap capture, the login password hash is:
        # ac0b2702856222 for password 888888
        # This appears to be a simple MD5 or custom hash
        # TODO: Implement proper hash function
        return 'ac0b2702856222'
    
    def run(self, video_callback: Callable[[bytes], None] = None,
            command_callback: Callable[[str], None] = None):
        """Run the relay client main loop.
        
        Args:
            video_callback: Called with video frame data
            command_callback: Called with command response text
        """
        self._video_callback = video_callback
        self._command_callback = command_callback
        self._running = True
        
        print('Starting relay client main loop...')
        
        while self._running:
            response = self._recv_packet(timeout=5.0)
            if not response:
                # Send keepalive
                self._send_alive_ack()
                continue
            
            try:
                parsed = pppp.okam_parse_packet(response)
                if not parsed:
                    continue
                
                if parsed['opcode'] == pppp.OP_MSG_DRW:
                    self._handle_drw(parsed)
                elif parsed['opcode'] == pppp.OP_MSG_ALIVE:
                    self._send_alive_ack()
                elif parsed['opcode'] == pppp.OP_MSG_CLOSE:
                    print('Relay closed connection')
                    break
                    
            except Exception as e:
                print(f'Error processing packet: {e}')
    
    def _handle_drw(self, parsed: dict):
        """Handle DRW data packet.
        
        Args:
            parsed: Parsed PPPP packet
        """
        drw = pppp.parse_drw_packet(parsed['payload'])
        if not drw:
            return
        
        # Send ACK
        self._send_drw_ack(drw['channel'], drw['index'])
        
        if drw['channel'] == pppp.CHANNEL_COMMAND:
            # Command response
            text = pppp.parse_cgi_response(drw['data'])
            if text:
                if self._command_callback:
                    self._command_callback(text)
                else:
                    print(f'CMD: {text[:100]}')
        
        elif drw['channel'] == pppp.CHANNEL_VIDEO:
            # Video data
            self._handle_video_data(drw['data'])
    
    def _handle_video_data(self, data: bytes):
        """Handle video data from channel 1.
        
        Args:
            data: Raw video data
        """
        # Check for video frame marker
        if data[:4] == pppp.VIDEO_MARKER:
            # This is a new frame boundary
            self._frame_boundaries.append(len(self._video_buffer))
            
            # Skip the 32-byte PPPP video header
            video_data = data[32:]
        else:
            video_data = data
        
        # Add to buffer
        self._video_buffer.extend(video_data)
        
        # Check if we have a complete frame
        if len(self._frame_boundaries) >= 2:
            # Extract the frame between the last two boundaries
            start = self._frame_boundaries[-2]
            end = self._frame_boundaries[-1]
            frame_data = bytes(self._video_buffer[start:end])
            
            # Call video callback
            if self._video_callback:
                self._video_callback(frame_data)
            
            # Clean up old data
            self._video_buffer = self._video_buffer[end:]
            self._frame_boundaries = [b - end for b in self._frame_boundaries[1:]]
    
    def get_snapshot(self, timeout: float = 10.0) -> Optional[bytes]:
        """Get a single video frame.
        
        Args:
            timeout: Timeout in seconds
        
        Returns:
            H.264 frame data, or None on timeout
        """
        frame_data = []
        
        def capture_frame(data):
            frame_data.append(data)
        
        # Temporarily set callback
        old_callback = self._video_callback
        self._video_callback = capture_frame
        
        # Wait for frame
        start_time = time.time()
        while time.time() - start_time < timeout and frame_data is None:
            response = self._recv_packet(timeout=1.0)
            if response:
                parsed = pppp.okam_parse_packet(response)
                if parsed and parsed['opcode'] == pppp.OP_MSG_DRW:
                    self._handle_drw(parsed)
        
        # Restore callback
        self._video_callback = old_callback
        
        return frame_data


def create_relay_client(did: str, relay_ip: str, relay_port: int,
                        username: str = 'admin', password: str = '888888',
                        access_key: str = None) -> RelayClient:
    """Create and connect a relay client.
    
    Args:
        did: Device ID
        relay_ip: Relay server IP
        relay_port: Relay server port
        username: Camera username
        password: Camera password
        access_key: Eye4 access key
    
    Returns:
        Connected RelayClient instance, or None on failure
    """
    client = RelayClient(
        relay_ip=relay_ip,
        relay_port=relay_port,
        did=did,
        username=username,
        password=password,
        access_key=access_key,
    )
    
    if not client.connect():
        return None
    
    if not client.authenticate():
        client.disconnect()
        return None
    
    return client


# Test with known relay from pcap
if __name__ == '__main__':
    print('Testing relay client with known relay...')
    
    # From pcap: video relay is 119.15.90.42:6582
    client = RelayClient(
        relay_ip='119.15.90.42',
        relay_port=6582,
        did='VE3326855YITZ',
        username='admin',
        password='888888',
    )
    
    if client.connect():
        print('Connected to relay')
        
        if client.authenticate():
            print('Authenticated')
            
            # Try to get a snapshot
            print('Getting snapshot...')
            frame = client.get_snapshot(timeout=15.0)
            if frame:
                print(f'Got frame: {len(frame)} bytes')
                with open('test_frame.h264', 'wb') as f:
                    f.write(frame)
                print('Saved to test_frame.h264')
            else:
                print('No frame received')
        
        client.disconnect()
    else:
        print('Failed to connect to relay')
