"""
Protocol Verification Test
==========================
Verify the PPPP protocol implementation against the pcap capture.
"""

import struct
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pppp import (
    create_psk_hash, pppp_encrypt, pppp_decrypt,
    parse_pppp_packet, parse_drw_packet, parse_cgi_response,
    OP_MSG_DRW, CHANNEL_COMMAND, CHANNEL_VIDEO, VIDEO_MARKER
)


def test_psk_derivation():
    """Test PSK key derivation."""
    print('Testing PSK key derivation...')
    
    # Test vstarcam2019
    key4 = create_psk_hash('vstarcam2019')
    assert key4 == bytes([0x2d, 0xd3, 0x61, 0x07]), f'Expected 2dd36107, got {key4.hex()}'
    print(f'  vstarcam2019: {key4.hex()} ✓')
    
    # Test camera
    key4 = create_psk_hash('camera')
    assert key4 == bytes([0x69, 0x97, 0xcc, 0x19]), f'Expected 6997cc19, got {key4.hex()}'
    print(f'  camera: {key4.hex()} ✓')
    
    print('PSK derivation tests passed!')


def test_encrypt_decrypt():
    """Test encrypt/decrypt round trip."""
    print('Testing encrypt/decrypt round trip...')
    
    key4 = create_psk_hash('vstarcam2019')
    
    # Test data
    test_data = b'Hello, PPPP World!'
    
    # Encrypt
    encrypted = pppp_encrypt(key4, test_data)
    assert encrypted != test_data, 'Encryption did not change data'
    
    # Decrypt
    decrypted = pppp_decrypt(key4, encrypted)
    assert decrypted == test_data, f'Decryption failed: {decrypted} != {test_data}'
    
    print(f'  Original:  {test_data}')
    print(f'  Encrypted: {encrypted.hex()}')
    print(f'  Decrypted: {decrypted}')
    print('Encrypt/decrypt tests passed!')


def test_magic_byte():
    """Test that encrypted magic byte matches pcap."""
    print('Testing magic byte...')
    
    key4 = create_psk_hash('vstarcam2019')
    
    # Encrypt 0xF1 (unencrypted magic)
    encrypted_magic = pppp_encrypt(key4, bytes([0xF1]))[0]
    
    # From pcap, the first byte of encrypted packets is 0xE4
    assert encrypted_magic == 0xE4, f'Expected 0xE4, got 0x{encrypted_magic:02x}'
    
    print(f'  Encrypted magic: 0x{encrypted_magic:02x} ✓')
    print('Magic byte tests passed!')


def test_packet_parsing():
    """Test PPPP packet parsing."""
    print('Testing packet parsing...')
    
    key4 = create_psk_hash('vstarcam2019')
    
    # Build a test packet
    from core.pppp import build_pppp_packet, build_drw_packet, build_cgi_command
    
    # Build a DRW command packet
    cgi_cmd = build_cgi_command('/get_status.cgi?user=admin&pwd=888888')
    drw_payload = build_drw_packet(CHANNEL_COMMAND, 0, cgi_cmd)
    packet = build_pppp_packet(OP_MSG_DRW, drw_payload, key4)
    
    # Parse it back
    parsed = parse_pppp_packet(packet, key4)
    assert parsed is not None, 'Failed to parse packet'
    assert parsed['magic'] == 0xF1, f'Wrong magic: 0x{parsed["magic"]:02x}'
    assert parsed['opcode'] == OP_MSG_DRW, f'Wrong opcode: 0x{parsed["opcode"]:02x}'
    
    # Parse DRW
    drw = parse_drw_packet(parsed['payload'])
    assert drw is not None, 'Failed to parse DRW'
    assert drw['channel'] == CHANNEL_COMMAND, f'Wrong channel: {drw["channel"]}'
    assert drw['index'] == 0, f'Wrong index: {drw["index"]}'
    
    # Parse CGI response
    text = parse_cgi_response(drw['data'])
    assert text is not None, 'Failed to parse CGI response'
    assert '/get_status.cgi' in text, f'Wrong CGI path: {text}'
    
    print(f'  Packet: {packet.hex()[:40]}...')
    print(f'  Parsed: magic=0x{parsed["magic"]:02x} opcode=0x{parsed["opcode"]:02x}')
    print(f'  DRW: channel={drw["channel"]} index={drw["index"]}')
    print(f'  CGI: {text[:50]}')
    print('Packet parsing tests passed!')


def test_pcap_decryption():
    """Test decryption against actual pcap data."""
    print('Testing pcap decryption...')
    
    # Known encrypted packet from pcap (frame 631, 194 bytes)
    encrypted_hex = 'e4db36f679207f5f55f085cb8ed376750893ea460a9e729637837d753b363384fd0d7132c11bbc255b4fca60190071604d712bbd7d7391307614d8e30672d2e96ec8bef36ab3a31953cea52859ddc29c32c9346de61e32daa82d44223a9d40fffa48ae8c0fcbdf99ec3605302633cdb74d40b49277db4351ec121786cdbeaeeb14c580fcdfa4e1927b886daee014ccaa8a107a80b26deb4d7d262be1c45b0fac656ab4c0e7b90c8c32cca784f770c6717a97c96162461dd2b3b3'
    
    key4 = create_psk_hash('vstarcam2019')
    encrypted = bytes.fromhex(encrypted_hex)
    
    # Decrypt
    decrypted = pppp_decrypt(key4, encrypted)
    
    # Check magic byte
    assert decrypted[0] == 0xF1, f'Wrong magic: 0x{decrypted[0]:02x}'
    
    # Check opcode
    assert decrypted[1] == OP_MSG_DRW, f'Wrong opcode: 0x{decrypted[1]:02x}'
    
    # Parse DRW
    payload_len = struct.unpack('>H', decrypted[2:4])[0]
    drw = parse_drw_packet(decrypted[4:4+payload_len])
    
    assert drw is not None, 'Failed to parse DRW'
    assert drw['channel'] == CHANNEL_COMMAND, f'Wrong channel: {drw["channel"]}'
    
    # Parse CGI response
    text = parse_cgi_response(drw['data'])
    assert text is not None, 'Failed to parse CGI response'
    assert 'get_status.cgi' in text, f'Wrong CGI: {text[:50]}'
    assert 'admin' in text, 'Missing admin in response'
    
    print(f'  Decrypted magic: 0x{decrypted[0]:02x} ✓')
    print(f'  Decrypted opcode: 0x{decrypted[1]:02x} ✓')
    print(f'  DRW channel: {drw["channel"]} ✓')
    print(f'  CGI response: {text[:80]}...')
    print('PCAP decryption tests passed!')


def test_video_marker():
    """Test video frame marker detection."""
    print('Testing video marker...')
    
    # Known video frame marker from pcap
    marker_hex = '55aa15a8'
    marker = bytes.fromhex(marker_hex)
    
    assert marker == VIDEO_MARKER, f'Wrong marker: {marker.hex()}'
    
    print(f'  Video marker: {marker.hex()} ✓')
    print('Video marker tests passed!')


def main():
    """Run all tests."""
    print('=' * 60)
    print('OKAM Protocol Verification Tests')
    print('=' * 60)
    print()
    
    try:
        test_psk_derivation()
        print()
        
        test_encrypt_decrypt()
        print()
        
        test_magic_byte()
        print()
        
        test_packet_parsing()
        print()
        
        test_pcap_decryption()
        print()
        
        test_video_marker()
        print()
        
        print('=' * 60)
        print('All tests passed! ✓')
        print('=' * 60)
        return 0
        
    except AssertionError as e:
        print(f'Test failed: {e}')
        return 1
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
