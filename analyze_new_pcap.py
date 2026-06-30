#!/usr/bin/env python3
"""
Quick-analyze a fresh OKAM pcap — extract relay IP, signatures, PPPP data.
Usage: python3 analyze_new_pcap.py <pcap_file>
"""

import subprocess
import struct
import sys
import os
import json
import glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.pppp import create_psk_hash, pppp_decrypt, parse_pppp_packet, parse_drw_packet, parse_cgi_response

KEY4_VSTARCAM2019 = create_psk_hash('vstarcam2019')
KNOWN_PSKS = {
    'vstarcam2019': create_psk_hash('vstarcam2019'),
    'vstarcam2018': create_psk_hash('vstarcam2018'),
    'camera': create_psk_hash('camera'),
    'SHIX': create_psk_hash('SHIX'),
}

def find_pcap():
    """Find the newest pcap file in the workspace."""
    patterns = ['*.pcapng', '*.pcap', '*.cap']
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
        files.extend(glob.glob(os.path.join('..', p)))
    
    if not files:
        # Check common names
        for name in ['okam_live.pcapng', 'capture.pcapng', 'dump.pcapng', 'stream.pcapng']:
            if os.path.exists(name):
                files.append(name)
    
    if not files:
        print('ERROR: No pcap file found. Put it in the current directory.')
        sys.exit(1)
    
    # Return newest by modification time
    return max(files, key=os.path.getmtime)


def tshark_fields(pcap, display_filter, *fields):
    """Run tshark and return parsed fields."""
    cmd = [
        'tshark', '-r', pcap,
        '-Y', display_filter,
        '-T', 'fields'
    ]
    for f in fields:
        cmd.extend(['-e', f])
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout.strip().split('\n')


def extract_signaling(pcap):
    """Extract all JSON signaling messages over TCP."""
    print('=' * 70)
    print('P2P SIGNALING MESSAGES (TCP JSON)')
    print('=' * 70)
    
    # Find all TCP conversations with data
    lines = tshark_fields(pcap, 'tcp.payload and tcp.len > 0',
                          'frame.number', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'data.data')
    
    messages = []
    for line in lines:
        parts = line.split('\t')
        if len(parts) < 6 or not parts[5]:
            continue
        frame, src, dst, sport, dport, data_hex = parts
        
        try:
            raw = bytes.fromhex(data_hex)
        except:
            continue
        
        # Check for JSON (4-byte BE length prefix)
        if len(raw) < 4:
            continue
        
        length = struct.unpack('>I', raw[:4])[0]
        if length > 0 and length < 10000 and len(raw) >= 4 + length:
            try:
                msg = json.loads(raw[4:4+length].decode('utf-8'))
                messages.append({
                    'frame': frame,
                    'src': src,
                    'dst': dst,
                    'sport': sport,
                    'dport': dport,
                    'msg': msg,
                })
            except:
                pass
    
    # Group by server
    servers = {}
    for m in messages:
        key = f"{m['dst']}:{m['dport']}" if m['msg'].get('event') else f"{m['src']}:{m['sport']}"
        if key not in servers:
            servers[key] = []
        servers[key].append(m)
    
    for server, msgs in sorted(servers.items()):
        print(f'\n--- Server: {server} ({len(msgs)} messages) ---')
        for m in msgs:
            event = m['msg'].get('event', '???')
            did = m['msg'].get('did', '')
            ts = m['msg'].get('timestamp', '')
            sign = m['msg'].get('sign', '')
            sig = m['msg'].get('signature', '')
            ret = m['msg'].get('ret', '')
            status = m['msg'].get('status', m['msg'].get('deviceStatus', ''))
            node = m['msg'].get('node_ip', '')
            nport = m['msg'].get('node_port', '')
            
            extra = ''
            if ret == 0:
                extra = f'ret=0 node={node}:{nport}'
            elif status:
                extra = f'status={status}'
            
            print('  F%s %s->%s event=%s did=%s ts=%s %s' % (
                m['frame'], m['src'], m['dst'], event, did[:15], ts, extra))
    
    return messages


def extract_relay(pcap):
    """Extract UDP relay traffic and attempt PPPP decryption."""
    print('\n' + '=' * 70)
    print('UDP RELAY TRAFFIC (PPPP)')
    print('=' * 70)
    
    # Find all UDP conversations with data
    lines = tshark_fields(pcap, 'udp.payload and udp.length > 4',
                          'frame.number', 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'udp.length', 'data.data')
    
    relays = {}
    for line in lines:
        parts = line.split('\t')
        if len(parts) < 7 or not parts[6]:
            continue
        frame, src, dst, sport, dport, length, data_hex = parts
        
        try:
            raw = bytes.fromhex(data_hex)
        except:
            continue
        
        if len(raw) < 4:
            continue
        
        # Try to decrypt with all known PSKs
        for psk_name, key4 in KNOWN_PSKS.items():
            try:
                dec = pppp_decrypt(key4, raw)
                if dec[0] == 0xF1:  # Valid PPPP magic
                    key = f'{dst}:{dport}'
                    if key not in relays:
                        relays[key] = []
                    
                    parsed = parse_pppp_packet(raw, key4)
                    info = {
                        'frame': frame,
                        'src': src,
                        'dst': dst,
                        'sport': sport,
                        'dport': dport,
                        'length': length,
                        'psk': psk_name,
                        'opcode': parsed['opcode_name'] if parsed else '???',
                        'payload_len': parsed['payload_len'] if parsed else 0,
                    }
                    
                    # For DRW packets, extract payload details
                    if parsed and parsed['opcode'] == 0xD0:
                        drw = parse_drw_packet(parsed['payload'])
                        if drw:
                            info['channel'] = drw['channel']
                            info['drw_index'] = drw['index']
                            if drw['channel'] == 0:
                                text = parse_cgi_response(drw['data'])
                                if text:
                                    info['command'] = text[:100]
                            elif drw['channel'] == 1:
                                info['video_len'] = len(drw['data'])
                                # Check for video marker
                                if drw['data'][:4] == b'\x55\xaa\x15\xa8':
                                    info['frame_marker'] = True
                    
                    relays[key].append(info)
                    break  # Found matching PSK
            except:
                continue
    
    for relay_addr, packets in sorted(relays.items()):
        psk = packets[0]['psk'] if packets else '?'
        print(f'\n--- Relay: {relay_addr} (PSK: {psk}, {len(packets)} packets) ---')
        
        # Show first 5 handshake packets
        for p in packets[:5]:
            extra = ''
            if 'channel' in p:
                if p['channel'] == 0 and 'command' in p:
                    extra = f'CMD: {p["command"]}'
                elif p['channel'] == 1:
                    extra = f'VIDEO {p.get("video_len", "?")}B' + (' [FRAME]' if p.get('frame_marker') else '')
            print(f'  F{p["frame"]} {p["src"]}->{p["dst"]} opcode={p["opcode"]} len={p["payload_len"]} {extra}')
        
        # Count video frames
        video_count = sum(1 for p in packets if p.get('channel') == 1)
        cmd_count = sum(1 for p in packets if p.get('channel') == 0)
        print(f'  Summary: {cmd_count} commands, {video_count} video packets')
    
    return relays


def extract_signatures(pcap):
    """Extract all fresh signature pairs from signaling traffic."""
    print('\n' + '=' * 70)
    print('FRESH SIGNATURES (for replay)')
    print('=' * 70)
    
    lines = tshark_fields(pcap, 'tcp.payload and tcp.len > 0',
                          'data.data')
    
    sigs = {}
    for line in lines:
        parts = line.split('\t')
        if len(parts) < 1 or not parts[0]:
            continue
        
        try:
            raw = bytes.fromhex(parts[0])
            if len(raw) < 4:
                continue
            length = struct.unpack('>I', raw[:4])[0]
            if 0 < length < 10000 and len(raw) >= 4 + length:
                msg = json.loads(raw[4:4+length].decode('utf-8'))
                event = msg.get('event', '')
                did = msg.get('did', '')
                ts = msg.get('timestamp', '')
                sign = msg.get('sign', '')
                sig = msg.get('signature', '')
                if sign and sig:
                    key = (event, did)
                    sigs[key] = (ts, sign, sig)
        except:
            pass
    
    for (event, did), (ts, sign, sig) in sorted(sigs.items()):
        print(f'  event={event:20s} did={did:20s} ts={ts} sign={sign:6s} sig={sig}')
    
    return sigs


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else find_pcap()
    print(f'Analyzing: {pcap}')
    print(f'Size: {os.path.getsize(pcap):,} bytes')
    print()
    
    # Extract everything
    signaling = extract_signaling(pcap)
    relay = extract_relay(pcap)
    sigs = extract_signatures(pcap)
    
    print('\n' + '=' * 70)
    print('SUMMARY')
    print('=' * 70)
    
    # Find relay IP:port for video
    video_relays = [r for r in relay.keys() if any(p.get('channel') == 1 for p in relay[r])]
    if video_relays:
        print(f'Video relay: {video_relays[0]}')
    else:
        print('No video relay found (no UDP traffic with video data)')
    
    # Find fresh signatures
    if sigs:
        print(f'Fresh signatures: {len(sigs)} pairs')
    else:
        print('No fresh signatures found')
    
    # Find camera credentials from commands
    for relay_addr in relay:
        for p in relay[relay_addr]:
            if 'command' in p and 'loginuse' in p['command']:
                print(f'Auth command: {p["command"][:120]}')
                break
    
    print('\nDone.')


if __name__ == '__main__':
    main()
