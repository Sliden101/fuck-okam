#!/usr/bin/env python3
"""
Try to connect to OKAM camera without knowing the signature algorithm.

Two approaches:
  A) Direct UDP relay connection (119.15.90.42:6582) - dumb pipe, may skip auth
  B) TCP signaling without valid signature - some servers don't validate
"""

import socket
import struct
import sys
import time
import json

sys.path.insert(0, '.')

from core.pppp import (
    create_psk_hash, pppp_encrypt, pppp_decrypt,
    parse_pppp_packet, parse_drw_packet, parse_cgi_response, parse_cgi_result,
    build_pppp_packet, build_drw_packet, build_cgi_command,
    OP_KEEPALIVE, OP_CONTROL, OP_IDENTIFY, OP_MSG_DRW, OP_MSG_DRW_ACK,
    OP_MSG_ALIVE, OP_MSG_ALIVE_ACK, OP_MSG_CLOSE,
    CHANNEL_COMMAND, CHANNEL_VIDEO,
)

OKAM_KEY4 = create_psk_hash('vstarcam2019')
RELAY_IP = '119.15.90.42'
RELAY_PORT = 6582
CAMERA_USER = 'admin'
CAMERA_PWD = '888888'
CAMERA_DID = 'VE3326855YITZ'
ACCESS_KEY = 'k3cTHvusdOyyrTKp'
SIGNALING_HOST = '47.91.201.49'
SIGNALING_PORT = 32320


def try_direct_relay():
    """Option A: Connect directly to the video relay via UDP."""
    print('=' * 60)
    print('OPTION A: Direct relay connection')
    print('=' * 60)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.bind(('0.0.0.0', 0))
    local_port = sock.getsockname()[1]
    print(f'Local port: {local_port}')
    
    # Step 1: Send KEEPALIVE (matching pcap frame 565)
    keepalive = build_pppp_packet(OP_KEEPALIVE, b'', OKAM_KEY4)
    print(f'\n[1] Sending KEEPALIVE (4 bytes encrypted: {keepalive.hex()})...')
    sock.sendto(keepalive, (RELAY_IP, RELAY_PORT))
    
    try:
        data, addr = sock.recvfrom(4096)
        print(f'    Received {len(data)} bytes from {addr}')
        parsed = parse_pppp_packet(data, OKAM_KEY4)
        if parsed:
            print(f'    Response: opcode={parsed["opcode_name"]} payload_len={parsed["payload_len"]}')
            if parsed['opcode'] == OP_CONTROL:
                print('    Got CONTROL response - relay accepted our packet!')
                return True, sock
            else:
                print(f'    Unexpected opcode: 0x{parsed["opcode"]:02x}')
                return True, sock  # Still, got a response
        else:
            print(f'    Raw data: {data.hex()}')
    except socket.timeout:
        print('    No response (timeout)')
    except Exception as e:
        print(f'    Error: {e}')
    
    sock.close()
    return False, None


def try_signaling_no_signature():
    """Option B: Try signaling server with blank/dummy signature."""
    print('\n' + '=' * 60)
    print('OPTION B: Signaling without valid signature')
    print('=' * 60)
    
    # Try different signature strategies
    strategies = [
        ('no_sign_fields', lambda e, d, t: {
            'event': e, 'did': d, 'AccessKey': ACCESS_KEY, 'timestamp': t,
        }),
        ('blank_sign', lambda e, d, t: {
            'event': e, 'did': d, 'AccessKey': ACCESS_KEY, 'timestamp': t,
            'sign': '', 'signature': '',
        }),
        ('zero_sign', lambda e, d, t: {
            'event': e, 'did': d, 'AccessKey': ACCESS_KEY, 'timestamp': t,
            'sign': '0', 'signature': '',
        }),
        ('dummy_sign', lambda e, d, t: {
            'event': e, 'did': d, 'AccessKey': ACCESS_KEY, 'timestamp': t,
            'sign': '1234', 'signature': 'dGVzdA==',
        }),
    ]
    
    for strategy_name, build_msg in strategies:
        print(f'\n  Trying strategy: {strategy_name}')
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((SIGNALING_HOST, SIGNALING_PORT))
            
            # Send getDeviceInfo
            ts = str(int(time.time()))
            msg = build_msg('getDeviceInfo', CAMERA_DID, ts)
            json_data = json.dumps(msg, separators=(', ', ': '))
            json_bytes = json_data.encode('utf-8')
            
            # 4-byte BE length prefix
            length_prefix = struct.pack('>I', len(json_bytes))
            sock.sendall(length_prefix + json_bytes)
            print(f'    Sent: {json_data[:120]}')
            
            # Read response
            try:
                len_data = b''
                while len(len_data) < 4:
                    chunk = sock.recv(4 - len(len_data))
                    if not chunk:
                        break
                    len_data += chunk
                
                if len(len_data) == 4:
                    resp_len = struct.unpack('>I', len_data)[0]
                    resp_data = b''
                    while len(resp_data) < resp_len:
                        chunk = sock.recv(resp_len - len(resp_data))
                        if not chunk:
                            break
                        resp_data += chunk
                    
                    if resp_data:
                        resp = json.loads(resp_data.decode('utf-8'))
                        print(f'    Response: {json.dumps(resp)}')
                        sock.close()
                        
                        if resp.get('ret') == 0:
                            print(f'    SUCCESS! Relay: {resp.get("node_ip")}:{resp.get("node_port")}')
                            return True, resp
                        else:
                            print(f'    Server rejected: ret={resp.get("ret")}')
                    else:
                        print('    Empty response')
                else:
                    print('    Connection closed before length read')
            except socket.timeout:
                print('    Timeout waiting for response')
            
            sock.close()
        except ConnectionRefusedError:
            print(f'    Connection refused to {SIGNALING_HOST}:{SIGNALING_PORT}')
        except socket.timeout:
            print(f'    Connection timeout')
        except Exception as e:
            print(f'    Error: {e}')
    
    return False, None


def try_full_relay_flow(sock):
    """If relay responds, try full auth + stream flow."""
    print('\n' + '=' * 60)
    print('Trying full relay auth flow...')
    print('=' * 60)
    
    drw_index = 0
    
    def send_packet(data):
        sock.sendto(data, (RELAY_IP, RELAY_PORT))
    
    def recv_packet(timeout=5.0):
        sock.settimeout(timeout)
        try:
            data, addr = sock.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None
    
    def send_command(cgi_path):
        nonlocal drw_index
        cmd_data = build_cgi_command(cgi_path)
        drw_payload = build_drw_packet(CHANNEL_COMMAND, drw_index, cmd_data)
        drw_index += 1
        packet = build_pppp_packet(OP_MSG_DRW, drw_payload, OKAM_KEY4)
        send_packet(packet)
        print(f'    Sent CGI: {cgi_path[:80]}...')
    
    def send_drw_ack(channel, index):
        ack = struct.pack('>BBH', 0xD1, channel, 1, index)
        packet = build_pppp_packet(OP_MSG_DRW_ACK, ack, OKAM_KEY4)
        send_packet(packet)
    
    # Step 1: Send check_user
    print('\n[1] Authenticating...')
    cgi = f'/get_status.cgi?loginuse={CAMERA_USER}&loginpas=ac0b2702856222&user={CAMERA_USER}&pwd={CAMERA_PWD}'
    send_command(cgi)
    
    # Wait for auth response
    for attempt in range(5):
        data, addr = recv_packet(5.0)
        if not data:
            print(f'    Attempt {attempt+1}: timeout')
            continue
        
        parsed = parse_pppp_packet(data, OKAM_KEY4)
        if not parsed:
            continue
        
        if parsed['opcode'] == OP_MSG_DRW:
            drw = parse_drw_packet(parsed['payload'])
            if drw and drw['channel'] == CHANNEL_COMMAND:
                send_drw_ack(drw['channel'], drw['index'])
                text = parse_cgi_response(drw['data'])
                if text:
                    print(f'    Auth response: {text[:100]}')
                    result = parse_cgi_result(text)
                    if result and result.get('result') == 0:
                        print(f'    AUTHENTICATED! deviceid={result.get("deviceid")}')
                        return True
        
        elif parsed['opcode'] == OP_CONTROL:
            print(f'    Got CONTROL during auth')
    
    print('    Authentication failed')
    return False


def main():
    print('OKAM Camera Connection Attempt')
    print(f'Relay: {RELAY_IP}:{RELAY_PORT}')
    print(f'Camera: {CAMERA_DID}')
    print()
    
    # Option B first - try signaling (no side effects, fast)
    sig_success, sig_response = try_signaling_no_signature()
    
    if sig_success:
        print('\n>>> SIGNALING WORKS! Got relay:', sig_response.get('node_ip'), sig_response.get('node_port'))
    
    # Option A - try direct relay
    relay_ok, sock = try_direct_relay()
    
    if relay_ok and sock:
        # Try full flow
        auth_ok = try_full_relay_flow(sock)
        sock.close()
    else:
        print('\n>>> RELAY DID NOT RESPOND')
        print('    Relay may require a session token from signaling.')
        print('    We need the signature algorithm (or the APK).')
    
    print('\n' + '=' * 60)
    if sig_success or relay_ok:
        print('Progress! See results above.')
    else:
        print('Both approaches failed. Need APK for signature algorithm.')
    print('=' * 60)


if __name__ == '__main__':
    main()
