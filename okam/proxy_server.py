"""
OKAM Proxy Server
=================
Multi-protocol streaming proxy for OKAM cameras.

Converts the H.264 PPPP relay stream to:
  - MJPEG (HTTP multipart stream for browsers)
  - HLS (HTTP Live Streaming for mobile/web)
  - Raw H.264 (for ffmpeg/VLC)

Usage:
    python -m okam.proxy_server --did VE3326855YITZ --user admin --pwd 888888
"""

import os
import sys
import time
import struct
import threading
import logging
import argparse
import subprocess
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from okam.camera import OKAMCamera

log = logging.getLogger('proxy')


class MJPEGHandler(BaseHTTPRequestHandler):
    """HTTP handler for MJPEG streaming and web GUI."""
    
    camera = None  # Set by server
    
    def do_GET(self):
        if self.path == '/':
            self._serve_html()
        elif self.path == '/stream.mjpg':
            self._serve_mjpeg()
        elif self.path == '/snapshot.jpg':
            self._serve_snapshot()
        elif self.path == '/status':
            self._serve_status()
        elif self.path == '/stream.h264':
            self._serve_raw_h264()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')
    
    def _serve_html(self):
        """Serve the web GUI."""
        html = HTML_TEMPLATE.format(
            did=self.camera.did if self.camera else 'unknown',
            connected=str(self.camera.is_connected if self.camera else False),
            streaming=str(self.camera.is_streaming if self.camera else False),
        )
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def _serve_mjpeg(self):
        """Serve MJPEG stream by converting H.264 frames to JPEG via ffmpeg.
        Falls back to raw H.264 if ffmpeg is not installed."""
        if not self.camera or not self.camera.is_streaming:
            # Camera not streaming - serve a static placeholder
            self.send_response(200)
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=FRAME')
            self.end_headers()
            # Send a blank frame so the browser shows something
            self.wfile.write(b'--FRAME\r\nContent-Type: text/plain\r\n\r\nWaiting for camera...\r\n')
            self.wfile.flush()
            while self.camera and not self.camera.is_streaming:
                time.sleep(2)
            return
        
        # Try ffmpeg for MJPEG conversion
        try:
            proc = subprocess.Popen(
                ['ffmpeg', '-f', 'h264', '-i', 'pipe:0',
                 '-f', 'mjpeg', '-q:v', '5', '-an', 'pipe:1'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            has_ffmpeg = True
        except FileNotFoundError:
            has_ffmpeg = False
            log.warning('ffmpeg not found - serving raw H.264 instead of MJPEG')
        
        self.send_response(200)
        
        if has_ffmpeg:
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=FRAME')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')
            self.end_headers()
            
            last_frame_time = time.time()
            
            try:
                while self.camera and self.camera.is_streaming:
                    frame = self.camera.snapshot(timeout=5.0)
                    if frame:
                        try:
                            proc.stdin.write(frame)
                            proc.stdin.flush()
                            last_frame_time = time.time()
                        except BrokenPipeError:
                            break
                    elif time.time() - last_frame_time > 30.0:
                        break
                    
                    jpeg_data = bytearray()
                    while True:
                        try:
                            proc.stdout.flush()
                            byte = proc.stdout.read(1)
                            if not byte:
                                break
                            
                            if byte == b'\xff':
                                byte2 = proc.stdout.read(1)
                                if byte2 == b'\xd8':
                                    jpeg_data = bytearray(b'\xff\xd8')
                                    prev = 0
                                    while True:
                                        b = proc.stdout.read(1)
                                        if not b:
                                            break
                                        jpeg_data.append(b[0])
                                        if prev == 0xff and b == b'\xd9':
                                            break
                                        prev = b[0]
                                    
                                    if len(jpeg_data) > 100:
                                        self.wfile.write(
                                            b'--FRAME\r\n'
                                            b'Content-Type: image/jpeg\r\n'
                                            b'Content-Length: ' + str(len(jpeg_data)).encode() + b'\r\n\r\n'
                                        )
                                        self.wfile.write(bytes(jpeg_data))
                                        self.wfile.write(b'\r\n')
                                        self.wfile.flush()
                                    break
                        except (BrokenPipeError, OSError):
                            break
            
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                try:
                    proc.stdin.close()
                    proc.stdout.close()
                    proc.terminate()
                except:
                    pass
        else:
            # No ffmpeg - serve raw H.264
            self.send_header('Content-Type', 'video/h264')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')
            self.end_headers()
            
            last_frame_time = time.time()
            try:
                while self.camera and self.camera.is_streaming:
                    frame = self.camera.snapshot(timeout=5.0)
                    if frame:
                        self.wfile.write(frame)
                        self.wfile.flush()
                        last_frame_time = time.time()
                    elif time.time() - last_frame_time > 30.0:
                        break
            except (BrokenPipeError, ConnectionResetError):
                pass
    
    def _serve_snapshot(self):
        """Serve a single JPEG snapshot."""
        if not self.camera or not self.camera.is_streaming:
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b'Camera not streaming')
            return
        
        frame = self.camera.snapshot(timeout=10.0)
        if not frame:
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b'No frame available')
            return
        
        try:
            proc = subprocess.Popen(
                ['ffmpeg', '-f', 'h264', '-i', 'pipe:0',
                 '-vframes', '1', '-f', 'mjpeg', '-q:v', '5', 'pipe:1'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            stdout, _ = proc.communicate(input=frame, timeout=5)
            if stdout and len(stdout) > 100:
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.send_header('Content-Length', str(len(stdout)))
                self.end_headers()
                self.wfile.write(stdout)
                return
            proc.terminate()
        except FileNotFoundError:
            pass  # ffmpeg not installed
        except Exception:
            pass
        
        # Fallback: serve raw H.264 frame
        self.send_response(200)
        self.send_header('Content-Type', 'video/h264')
        self.send_header('Content-Length', str(len(frame)))
        self.end_headers()
        self.wfile.write(frame)
    
    def _serve_status(self):
        """Serve camera status as JSON."""
        status = {
            'connected': self.camera.is_connected if self.camera else False,
            'streaming': self.camera.is_streaming if self.camera else False,
            'did': self.camera.did if self.camera else 'unknown',
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        import json
        self.wfile.write(json.dumps(status).encode())
    
    def _serve_raw_h264(self):
        """Serve raw H.264 stream (for VLC/ffplay)."""
        self.send_response(200)
        self.send_header('Content-Type', 'video/h264')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'close')
        self.end_headers()
        
        last_frame_time = time.time()
        
        try:
            while self.camera and self.camera.is_streaming:
                frame = self.camera.snapshot(timeout=5.0)
                if frame:
                    self.wfile.write(frame)
                    self.wfile.flush()
                    last_frame_time = time.time()
                elif time.time() - last_frame_time > 30.0:
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
    
    def log_message(self, *args):
        pass


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OKAM Camera - {did}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }}
.header {{ padding: 16px 24px; border-bottom: 1px solid #21262d; display: flex; justify-content: space-between; align-items: center; }}
.header h1 {{ font-size: 18px; font-weight: 600; }}
.status {{ display: flex; gap: 16px; align-items: center; }}
.status-dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
.status-dot.online {{ background: #3fb950; box-shadow: 0 0 6px #3fb950; }}
.status-dot.offline {{ background: #f85149; box-shadow: 0 0 6px #f85149; }}
.status-text {{ font-size: 13px; color: #8b949e; }}
.main {{ padding: 24px; max-width: 1200px; margin: 0 auto; }}
.video-container {{ background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #21262d; }}
.video-container img {{ width: 100%; display: block; }}
.controls {{ display: flex; gap: 12px; padding: 16px 24px; justify-content: center; }}
.btn {{ background: #21262d; color: #c9d1d9; border: 1px solid #30363d; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; }}
.btn:hover {{ background: #30363d; }}
.btn.primary {{ background: #238636; border-color: #2ea043; }}
.btn.primary:hover {{ background: #2ea043; }}
.footer {{ text-align: center; padding: 12px; color: #484f58; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>OKAM Camera</h1>
  <div class="status">
    <span class="status-dot {connected}" id="status-dot"></span>
    <span class="status-text" id="status-text">DID: {did}</span>
  </div>
</div>
<div class="main">
  <div class="video-container">
    <img id="video" src="/stream.mjpg" alt="Live stream">
  </div>
  <div class="controls">
    <button class="btn" onclick="snapshot()">Snapshot</button>
    <button class="btn" onclick="location.reload()">Reconnect</button>
    <a class="btn" href="/stream.h264" target="_blank">Raw H.264</a>
  </div>
</div>
<div class="footer">OKAM Proxy &bull; {did}</div>
<script>
function snapshot() {{
  var a = document.createElement('a');
  a.href = '/snapshot.jpg?t=' + Date.now();
  a.download = 'okam_snapshot.jpg';
  a.click();
}}
setInterval(function() {{
  fetch('/status').then(function(r) {{ return r.json(); }}).then(function(s) {{
    document.getElementById('status-dot').className = 'status-dot ' + (s.streaming ? 'online' : 'offline');
  }}).catch(function() {{}});
}}, 5000);
</script>
</body>
</html>"""


def start_http_server(camera, host='0.0.0.0', port=8080):
    """Start the HTTP server in a background thread."""
    MJPEGHandler.camera = camera
    server = HTTPServer((host, port), MJPEGHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info(f'HTTP server at http://localhost:{port}')
    return server


def main():
    parser = argparse.ArgumentParser(description='OKAM Camera Proxy Server')
    parser.add_argument('--did', default='VE3326855YITZ', help='Device ID')
    parser.add_argument('--user', default='admin', help='Camera username')
    parser.add_argument('--pwd', default='888888', help='Camera password')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP port')
    parser.add_argument('--debug', action='store_true', help='Debug logging')
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    
    log.info(f'OKAM Proxy Server starting for {args.did}')
    
    # Create camera client
    camera = OKAMCamera(args.did, args.user, args.pwd)
    
    # Start HTTP server (web GUI works even without camera)
    http_server = start_http_server(camera, port=args.http_port)
    
    # Try to connect to camera
    log.info('Connecting to camera...')
    
    if camera.connect():
        log.info('Connected. Authenticating...')
        
        if camera.authenticate():
            log.info('Authenticated. Starting stream...')
            
            if camera.start_stream():
                log.info(f'Streaming at http://localhost:{args.http_port}')
                log.info('Press Ctrl+C to stop.')
                
                # Start stream consumer thread
                def stream_consumer():
                    for frame in camera.stream():
                        pass  # Frames are buffered in camera.latest_frame
                
                consumer = threading.Thread(target=stream_consumer, daemon=True)
                consumer.start()
                
                try:
                    while True:
                        time.sleep(1)
                        if not camera.is_streaming:
                            log.warning('Stream ended. Reconnecting...')
                            camera.close()
                            if camera.connect() and camera.authenticate():
                                camera.start_stream()
                            else:
                                log.error('Reconnection failed')
                                break
                except KeyboardInterrupt:
                    pass
            else:
                log.warning('Failed to start stream. Server running - camera may come online later.')
                log.info(f'Web GUI at http://localhost:{args.http_port}')
                try:
                    while True:
                        time.sleep(5)
                        # Retry connection periodically
                        if not camera.is_connected:
                            log.info('Retrying connection...')
                            if camera.connect() and camera.authenticate() and camera.start_stream():
                                log.info('Camera connected!')
                except KeyboardInterrupt:
                    pass
        else:
            log.warning('Authentication failed. Server running - check credentials.')
    else:
        log.warning('Camera unreachable. Server running in offline mode.')
        log.info(f'Web GUI at http://localhost:{args.http_port}')
        log.info('Camera will auto-connect when it comes online.')
        try:
            while True:
                time.sleep(5)
                if not camera.is_connected:
                    if camera.connect() and camera.authenticate() and camera.start_stream():
                        log.info('Camera connected!')
        except KeyboardInterrupt:
            pass
    
    camera.close()
    log.info('Shutdown complete.')


if __name__ == '__main__':
    main()
