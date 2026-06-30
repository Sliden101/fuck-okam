#!/usr/bin/env python3
"""
OKAM Passive Sniffer
====================
Sniffs PPPP-encrypted UDP traffic while OKAM Pro is streaming,
auto-detects the relay, decrypts with vstarcam2019, extracts H.264,
and serves on HTTP.

Usage:
    python -m okam.passive_sniffer

Requirements:
    pip install scapy
    Npcap (already installed on your Windows machine)

How it works:
    1. Sniffs ALL UDP traffic on the machine
    2. Tries decrypting each packet with vstarcam2019 PSK
    3. First valid PPPP packet identifies the relay
    4. Continuously decrypts relay traffic, extracts H.264
    5. Serves raw H.264 on http://localhost:8080/stream.h264
"""

import os
import sys
import time
import struct
import threading
import logging
import queue
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from io import BytesIO


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a separate thread."""
    daemon_threads = True

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.pppp import create_psk_hash, pppp_decrypt, SHUFFLE_TABLE

log = logging.getLogger('sniffer')

OKAM_KEY4 = create_psk_hash('vstarcam2019')

# PPPP constants
MAGIC_UNENCRYPTED = 0xF1
OP_MSG_DRW = 0xD0
CHANNEL_COMMAND = 0
CHANNEL_VIDEO = 1
VIDEO_MARKER = b'\x55\xAA\x15\xA8'


class H264Extractor:
    """Extract H.264 frames from PPPP DRW channel 1 data."""

    def __init__(self, frame_callback=None):
        self.frame_callback = frame_callback
        self._buffer = bytearray()
        self._boundaries = []
        self._frame_count = 0
        self._latest_frame = None
        self._lock = threading.Lock()
        self._sps = None
        self._pps = None
        self._has_idr = False

    def _find_nal_units(self, data: bytes) -> list:
        """Find all NAL units in H.264 data. Returns list of (offset, nal_type, nal_unit)."""
        units = []
        pos = 0
        while pos < len(data) - 4:
            if data[pos:pos+4] == b'\x00\x00\x00\x01':
                nal_type = data[pos+4] & 0x1F
                end = pos + 4
                while end < len(data) - 4:
                    if data[end:end+4] == b'\x00\x00\x00\x01' or data[end:end+3] == b'\x00\x00\x01':
                        break
                    end += 1
                units.append((pos, nal_type, data[pos:end]))
                pos = end
            else:
                pos += 1
        return units

    def _extract_sps_pps(self, data: bytes):
        """Extract SPS and PPS NAL units from H.264 data."""
        for _, nal_type, nal_unit in self._find_nal_units(data):
            if nal_type == 7:
                self._sps = nal_unit
            elif nal_type == 8:
                self._pps = nal_unit

    def _has_idr_frame(self, data: bytes) -> bool:
        """Check if data contains an IDR (keyframe) NAL unit."""
        for _, nal_type, _ in self._find_nal_units(data):
            if nal_type == 5:  # IDR slice
                return True
        return False

    def feed(self, data: bytes):
        """Feed raw video data from DRW channel 1."""
        if data[:4] == VIDEO_MARKER:
            self._boundaries.append(len(self._buffer))
            video_data = data[32:]
        else:
            video_data = data

        self._buffer.extend(video_data)

        while len(self._boundaries) >= 2:
            start = self._boundaries[0]
            end = self._boundaries[1]
            frame = bytes(self._buffer[start:end])

            self._extract_sps_pps(frame)
            if self._has_idr_frame(frame):
                self._has_idr = True

            with self._lock:
                self._latest_frame = frame
            self._frame_count += 1

            if self.frame_callback:
                self.frame_callback(frame)

            self._buffer = self._buffer[end:]
            self._boundaries = [b - end for b in self._boundaries[1:]]

    @property
    def latest_frame(self) -> bytes:
        with self._lock:
            return self._latest_frame

    @property
    def frame_count(self) -> int:
        return self._frame_count

    @property
    def ready(self) -> bool:
        """True when we have SPS+PPS and at least one IDR frame (VLC can play)."""
        return self._sps is not None and self._pps is not None and self._has_idr

    def reset_ready(self):
        """Reset IDR flag so next VLC client waits for a fresh keyframe."""
        self._has_idr = False

    def get_header(self) -> bytes:
        """Return SPS+PPS header bytes (send once at stream start)."""
        h = bytearray()
        if self._sps:
            h.extend(self._sps)
        if self._pps:
            h.extend(self._pps)
        return bytes(h)


class PassiveSniffer:
    """Sniff PPPP-encrypted UDP traffic and extract H.264 video."""

    def __init__(self):
        self.relay_ip = None
        self.relay_port = None
        self.extractor = H264Extractor()
        self.running = False
        self.packet_count = 0
        self.video_packet_count = 0

    def _try_decrypt(self, raw: bytes) -> bytes:
        """Try to decrypt raw bytes with OKAM PSK. Returns decrypted data or None."""
        try:
            if len(raw) < 4:
                return None
            dec = pppp_decrypt(OKAM_KEY4, raw)
            if dec[0] == MAGIC_UNENCRYPTED:
                return dec
        except:
            pass
        return None

    def _process_pppp_packet(self, decrypted: bytes):
        """Process a decrypted PPPP packet."""
        if len(decrypted) < 4:
            return

        opcode = decrypted[1]
        payload_len = struct.unpack('>H', decrypted[2:4])[0]
        payload = decrypted[4:4 + payload_len] if payload_len > 0 else b''

        if opcode == OP_MSG_DRW and len(decrypted) >= 8:
            channel = decrypted[5]
            if channel == CHANNEL_VIDEO:
                self.video_packet_count += 1
                video_data = decrypted[8:] if len(decrypted) > 8 else b''
                if video_data:
                    self.extractor.feed(video_data)

    # ---------- scapy-based sniffing ----------
    def start_scapy(self, iface=None, timeout=None):
        """Start sniffing with scapy (works on Windows with Npcap)."""
        try:
            from scapy.all import sniff, UDP, IP, Raw
        except ImportError:
            log.error('scapy not installed. Run: pip install scapy')
            log.error('Also ensure Npcap is installed from https://npcap.com')
            return False

        self.running = True
        log.info('Sniffing UDP traffic for PPPP packets...')
        log.info('Open OKAM Pro and view the camera to start the stream.')

        def process_packet(pkt):
            if not self.running:
                return True  # Stop sniffing

            if not (UDP in pkt and Raw in pkt):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            raw = bytes(pkt[Raw].load)

            dec = self._try_decrypt(raw)
            if dec is None:
                return

            self.packet_count += 1

            # Auto-detect relay (first valid PPPP packet)
            if self.relay_ip is None:
                # The relay is the remote endpoint
                if src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.16.'):
                    self.relay_ip = dst_ip
                    self.relay_port = dst_port
                else:
                    self.relay_ip = src_ip
                    self.relay_port = src_port
                log.info(f'DETECTED relay: {self.relay_ip}:{self.relay_port}')
                log.info(f'Receiving PPPP traffic...')

            # Only process packets from the detected relay
            if src_ip == self.relay_ip or dst_ip == self.relay_ip:
                self._process_pppp_packet(dec)

        log.info('Starting scapy sniff... (requires Npcap)')
        sniff(
            filter='udp',
            prn=process_packet,
            store=False,
            timeout=timeout,
            iface=iface,
        )
        self.running = False
        return True

    # ---------- raw socket sniffing (fallback, Linux only) ----------
    def start_raw_socket(self, timeout=None):
        """Fallback: sniff using raw sockets (Linux only)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except PermissionError:
            log.error('Raw socket requires admin/root. Use scapy instead.')
            return False
        except OSError as e:
            log.error(f'Raw socket failed: {e}. Use scapy on Windows.')
            return False

        self.running = True
        sock.settimeout(1.0)
        start_time = time.time()

        log.info('Sniffing with raw socket...')

        while self.running:
            if timeout and time.time() - start_time > timeout:
                break
            try:
                packet, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            # Parse IP header (20 bytes normally)
            if len(packet) < 28:
                continue
            ip_header = packet[:20]
            ip_len = (ip_header[2] << 8) | ip_header[3]
            src_ip = '.'.join(str(b) for b in ip_header[12:16])
            dst_ip = '.'.join(str(b) for b in ip_header[16:20])
            protocol = ip_header[9]

            if protocol != 17:  # UDP
                continue

            # Parse UDP header
            udp_start = 20
            udp = packet[udp_start:udp_start + 8]
            src_port = (udp[0] << 8) | udp[1]
            dst_port = (udp[2] << 8) | udp[3]
            raw = packet[udp_start + 8:]

            if len(raw) < 4:
                continue

            dec = self._try_decrypt(raw)
            if dec is None:
                continue

            self.packet_count += 1

            if self.relay_ip is None:
                if src_ip.startswith(('192.168.', '10.', '172.16.')):
                    self.relay_ip = dst_ip
                    self.relay_port = dst_port
                else:
                    self.relay_ip = src_ip
                    self.relay_port = src_port
                log.info(f'DETECTED relay: {self.relay_ip}:{self.relay_port}')

            if src_ip == self.relay_ip or dst_ip == self.relay_ip:
                self._process_pppp_packet(dec)

        sock.close()
        self.running = False
        return True

    def start(self) -> bool:
        """Start sniffing. Tries scapy first, then raw socket."""
        try:
            return self.start_scapy()
        except Exception as e:
            log.warning(f'scapy failed: {e}. Trying raw socket...')
            return self.start_raw_socket()

    def stop(self):
        """Stop sniffing."""
        self.running = False


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OKAM Sniffer</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
.header{{padding:16px 24px;border-bottom:1px solid #21262d;display:flex;justify-content:space-between;align-items:center}}
.header h1{{font-size:18px;font-weight:600}}
.main{{padding:24px;max-width:900px;margin:0 auto}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:16px}}
.card h2{{font-size:15px;margin-bottom:12px;color:#58a6ff}}
.stat{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d;font-size:13px}}
.stat:last-child{{border-bottom:none}}
.stat span:last-child{{color:#8b949e;font-family:monospace}}
.status-dot{{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:8px}}
.status-dot.active{{background:#3fb950;box-shadow:0 0 6px #3fb950}}
.status-dot.waiting{{background:#d29922;box-shadow:0 0 6px #d29922}}
.instructions{{color:#8b949e;font-size:13px;line-height:1.6}}
.instructions code{{background:#21262d;padding:2px 6px;border-radius:3px;font-size:12px}}
</style>
</head>
<body>
<div class="header">
  <h1>OKAM Passive Sniffer</h1>
  <span class="status-dot {status_class}"></span>
</div>
<div class="main">
  <div class="card">
    <h2>Status</h2>
    <div class="stat"><span>Relay</span><span>{relay}</span></div>
    <div class="stat"><span>PPP Packets</span><span>{packets}</span></div>
    <div class="stat"><span>Video Packets</span><span>{video}</span></div>
    <div class="stat"><span>Frames Extracted</span><span>{frames}</span></div>
  </div>
  <div class="card">
    <h2>How to Stream</h2>
    <div class="instructions">
      <p>1. Open <b>OKAM Pro</b> and view the camera</p>
      <p>2. The sniffer auto-detects the relay and starts capturing</p>
      <p>3. Open VLC → Media → Open Network Stream → paste:</p>
      <p><code>http://localhost:8080/stream.h264</code></p>
      <p>4. Or open this page to watch status update</p>
    </div>
  </div>
</div>
<script>
setInterval(function(){{location.reload()}},3000);
</script>
</body>
</html>"""


class SnifferHandler(BaseHTTPRequestHandler):
    sniffer = None

    def do_GET(self):
        if self.path == '/':
            self._serve_html()
        elif self.path == '/stream.h264':
            self._serve_h264()
        elif self.path == '/status':
            self._serve_status()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_html(self):
        s = self.sniffer
        ext = s.extractor
        relay = f'{s.relay_ip}:{s.relay_port}' if s.relay_ip else 'detecting...'
        ready = 'active' if ext.ready else 'waiting'

        html = HTML.format(
            relay=relay,
            packets=s.packet_count,
            video=s.video_packet_count,
            frames=ext.frame_count,
            status_class=ready,
        )
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_h264(self):
        self.send_response(200)
        self.send_header('Content-Type', 'video/h264')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        ext = self.sniffer.extractor

        # Reset IDR flag — we need a FRESH keyframe for THIS client
        ext.reset_ready()

        # Set up queue-based frame delivery for this client
        frame_queue = queue.Queue(maxsize=60)

        def on_frame(f):
            try:
                frame_queue.put_nowait(f)
            except queue.Full:
                try:
                    frame_queue.get_nowait()
                    frame_queue.put_nowait(f)
                except queue.Empty:
                    pass

        old_cb = ext.frame_callback
        ext.frame_callback = on_frame

        try:
            # Wait for SPS+PPS+FRESH IDR
            waited = 0
            while self.sniffer and self.sniffer.running and not ext.ready:
                # Drain any frames that arrived before IDR
                try:
                    frame_queue.get(timeout=0.5)
                except queue.Empty:
                    pass
                waited += 1
                if waited > 120:  # 60 second timeout
                    return

            # Send SPS+PPS header
            header = ext.get_header()
            if header:
                try:
                    self.wfile.write(header)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    return

            # Stream frames until client disconnects
            while self.sniffer and self.sniffer.running:
                try:
                    frame = frame_queue.get(timeout=1.0)
                    self.wfile.write(frame)
                    self.wfile.flush()
                except queue.Empty:
                    continue
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    break
        finally:
            ext.frame_callback = old_cb

    def _serve_status(self):
        s = self.sniffer
        import json
        status = json.dumps({
            'relay': f'{s.relay_ip}:{s.relay_port}' if s.relay_ip else None,
            'packets': s.packet_count,
            'video': s.video_packet_count,
            'frames': s.extractor.frame_count,
        })
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(status.encode())

    def log_message(self, *args):
        pass


def start_http(sniffer, host='0.0.0.0', port=8080):
    SnifferHandler.sniffer = sniffer
    server = ThreadingHTTPServer((host, port), SnifferHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    log.info(f'HTTP server at http://localhost:{port}')
    log.info(f'H.264 stream at http://localhost:{port}/stream.h264')
    log.info(f'Open VLC → Open Network Stream → http://localhost:{port}/stream.h264')
    return server


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S',
    )

    print('=' * 60)
    print(' OKAM Passive Sniffer')
    print(' Auto-detects relay + decrypts PPPP + serves H.264')
    print('=' * 60)
    print()
    print(' 1. Open OKAM Pro and view the camera')
    print(' 2. The sniffer will detect the relay automatically')
    print(' 3. Open VLC: http://localhost:8080/stream.h264')
    print()

    sniffer = PassiveSniffer()
    start_http(sniffer, port=8080)

    ok = sniffer.start()

    if not ok:
        log.error('Failed to start sniffer.')
        log.error('Make sure Npcap is installed: https://npcap.com')
        log.error('And scapy: pip install scapy')
        sys.exit(1)

    log.info('Sniffer stopped.')
    log.info(f'Total: {sniffer.packet_count} PPPP packets, {sniffer.video_packet_count} video, {sniffer.extractor.frame_count} frames')


if __name__ == '__main__':
    main()
