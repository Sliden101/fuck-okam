"""
PPPP Encryption Module
=====================
Pure Python implementation of the PPPP stream cipher used by Eye4/VStarcam/OKAM cameras.

The cipher is a stateful XOR stream cipher using a 256-byte shuffle table and a 4-byte key
derived from a PSK (Pre-Shared Key) string.

Known PSKs:
    vstarcam2019 -> key4: 2d d3 61 07 (VE, VSTJ, VSTK, VSTL, VSTM, VSTN, VSTP, VC0)
    vstarcam2018 -> key4: 1c e4 58 16 (VSTG, VSTH, ELSC)
    camera       -> key4: 69 97 cc 19 (DGOG)
    SHIX         -> key4: 3c c4 68 0a (SHIX)
    SSD@cs2-network. -> key4: 97 69 d6 5b (Server)
"""

import struct

# Standard PPPP shuffle table (256 bytes)
SHUFFLE_TABLE = bytes([
    0x7C, 0x9C, 0xE8, 0x4A, 0x13, 0xDE, 0xDC, 0xB2, 0x2F, 0x21, 0x23, 0xE4, 0x30, 0x7B, 0x3D, 0x8C,
    0xBC, 0x0B, 0x27, 0x0C, 0x3C, 0xF7, 0x9A, 0xE7, 0x08, 0x71, 0x96, 0x00, 0x97, 0x85, 0xEF, 0xC1,
    0x1F, 0xC4, 0xDB, 0xA1, 0xC2, 0xEB, 0xD9, 0x01, 0xFA, 0xBA, 0x3B, 0x05, 0xB8, 0x15, 0x87, 0x83,
    0x28, 0x72, 0xD1, 0x8B, 0x5A, 0xD6, 0xDA, 0x93, 0x58, 0xFE, 0xAA, 0xCC, 0x6E, 0x1B, 0xF0, 0xA3,
    0x88, 0xAB, 0x43, 0xC0, 0x0D, 0xB5, 0x45, 0x38, 0x4F, 0x50, 0x22, 0x66, 0x20, 0x7F, 0x07, 0x5B,
    0x14, 0x98, 0x1D, 0x9B, 0xA7, 0x2A, 0xB9, 0xA8, 0xCB, 0xF1, 0xFC, 0x49, 0x47, 0x06, 0x3E, 0xB1,
    0x0E, 0x04, 0x3A, 0x94, 0x5E, 0xEE, 0x54, 0x11, 0x34, 0xDD, 0x4D, 0xF9, 0xEC, 0xC7, 0xC9, 0xE3,
    0x78, 0x1A, 0x6F, 0x70, 0x6B, 0xA4, 0xBD, 0xA9, 0x5D, 0xD5, 0xF8, 0xE5, 0xBB, 0x26, 0xAF, 0x42,
    0x37, 0xD8, 0xE1, 0x02, 0x0A, 0xAE, 0x5F, 0x1C, 0xC5, 0x73, 0x09, 0x4E, 0x69, 0x24, 0x90, 0x6D,
    0x12, 0xB3, 0x19, 0xAD, 0x74, 0x8A, 0x29, 0x40, 0xF5, 0x2D, 0xBE, 0xA5, 0x59, 0xE0, 0xF4, 0x79,
    0xD2, 0x4B, 0xCE, 0x89, 0x82, 0x48, 0x84, 0x25, 0xC6, 0x91, 0x2B, 0xA2, 0xFB, 0x8F, 0xE9, 0xA6,
    0xB0, 0x9E, 0x3F, 0x65, 0xF6, 0x03, 0x31, 0x2E, 0xAC, 0x0F, 0x95, 0x2C, 0x5C, 0xED, 0x39, 0xB7,
    0x33, 0x6C, 0x56, 0x7E, 0xB4, 0xA0, 0xFD, 0x7A, 0x81, 0x53, 0x51, 0x86, 0x8D, 0x9F, 0x77, 0xFF,
    0x6A, 0x80, 0xDF, 0xE2, 0xBF, 0x10, 0xD7, 0x75, 0x64, 0x57, 0x76, 0xF3, 0x55, 0xCD, 0xD0, 0xC8,
    0x18, 0xE6, 0x36, 0x41, 0x62, 0xCF, 0x99, 0xF2, 0x32, 0x4C, 0x67, 0x60, 0x61, 0x92, 0xCA, 0xD3,
    0xEA, 0x63, 0x7D, 0x16, 0xB6, 0x8E, 0xD4, 0x68, 0x35, 0xC3, 0x52, 0x9D, 0x46, 0x44, 0x1E, 0x17,
])

# PPPP constants
MAGIC_UNENCRYPTED = 0xF1
MAGIC_ENCRYPTED_VSTARCAM2019 = 0xE4

# Opcodes
OP_KEEPALIVE = 0x70
OP_CONTROL = 0x73
OP_IDENTIFY = 0x83
OP_MSG_DRW = 0xD0
OP_MSG_DRW_ACK = 0xD1
OP_MSG_ALIVE = 0xE0
OP_MSG_ALIVE_ACK = 0xE1
OP_MSG_CLOSE = 0xF0

# DRW channels
CHANNEL_COMMAND = 0
CHANNEL_VIDEO = 1

# Video frame marker
VIDEO_MARKER = b'\x55\xAA\x15\xA8'


def create_psk_hash(psk: str) -> bytes:
    """Create 4-byte PSK hash from PSK string.
    
    Args:
        psk: Pre-shared key string (e.g., 'vstarcam2019')
    
    Returns:
        4-byte key for PPPP encryption
    """
    h = [0, 0, 0, 0]
    for b in psk.encode():
        h[0] = (h[0] + b) & 0xFF
        h[1] = (h[1] - b) & 0xFF
        h[2] = (h[2] + b // 3) & 0xFF
        h[3] = (h[3] ^ b) & 0xFF
    return bytes(h)


def pppp_encrypt(key4: bytes, data: bytes) -> bytes:
    """Encrypt data using PPPP stream cipher.
    
    Args:
        key4: 4-byte encryption key (from create_psk_hash)
        data: Plaintext data to encrypt
    
    Returns:
        Encrypted data
    """
    result = bytearray()
    prev = 0
    for b in data:
        idx = (key4[prev & 3] + prev) & 0xFF
        key = SHUFFLE_TABLE[idx]
        enc = (b ^ key) & 0xFF
        result.append(enc)
        prev = enc
    return bytes(result)


def pppp_decrypt(key4: bytes, data: bytes) -> bytes:
    """Decrypt data using PPPP stream cipher.
    
    Args:
        key4: 4-byte decryption key (from create_psk_hash)
        data: Encrypted data to decrypt
    
    Returns:
        Decrypted data
    """
    result = bytearray()
    prev = 0
    for b in data:
        idx = (key4[prev & 3] + prev) & 0xFF
        key = SHUFFLE_TABLE[idx]
        dec = (b ^ key) & 0xFF
        result.append(dec)
        prev = b
    return bytes(result)


def build_pppp_packet(opcode: int, payload: bytes, key4: bytes = None) -> bytes:
    """Build a PPPP packet.
    
    Args:
        opcode: PPPP opcode (e.g., OP_MSG_DRW)
        payload: Packet payload
        key4: Optional encryption key. If None, packet is unencrypted.
    
    Returns:
        Complete PPPP packet (header + encrypted payload)
    """
    header = struct.pack('>BBH', MAGIC_UNENCRYPTED, opcode, len(payload))
    packet = header + payload
    if key4:
        return pppp_encrypt(key4, packet)
    return packet


def parse_pppp_packet(data: bytes, key4: bytes = None) -> dict:
    """Parse a PPPP packet.
    
    Args:
        data: Raw packet data (encrypted or unencrypted)
        key4: Optional decryption key. If None, tries to auto-detect.
    
    Returns:
        dict with keys: magic, opcode, opcode_name, payload_len, payload
        Returns None if packet is invalid.
    """
    if key4:
        decrypted = pppp_decrypt(key4, data)
    else:
        decrypted = data
    
    if len(decrypted) < 4:
        return None
    
    magic = decrypted[0]
    opcode = decrypted[1]
    payload_len = struct.unpack('>H', decrypted[2:4])[0]
    payload = decrypted[4:4 + payload_len] if payload_len > 0 else b''
    
    opcode_names = {
        OP_KEEPALIVE: 'KEEPALIVE',
        OP_CONTROL: 'CONTROL',
        OP_IDENTIFY: 'IDENTIFY',
        OP_MSG_DRW: 'MSG_DRW',
        OP_MSG_DRW_ACK: 'MSG_DRW_ACK',
        OP_MSG_ALIVE: 'MSG_ALIVE',
        OP_MSG_ALIVE_ACK: 'MSG_ALIVE_ACK',
        OP_MSG_CLOSE: 'MSG_CLOSE',
    }
    
    return {
        'magic': magic,
        'opcode': opcode,
        'opcode_name': opcode_names.get(opcode, f'UNKNOWN_0x{opcode:02x}'),
        'payload_len': payload_len,
        'payload': payload,
    }


def parse_drw_packet(payload: bytes) -> dict:
    """Parse a DRW (Data Read/Write) payload.
    
    Args:
        payload: DRW payload from parse_pppp_packet
    
    Returns:
        dict with keys: magic, channel, index, data
    """
    if len(payload) < 4:
        return None
    
    return {
        'magic': payload[0],
        'channel': payload[1],
        'index': struct.unpack('>H', payload[2:4])[0],
        'data': payload[4:],
    }


def build_drw_packet(channel: int, index: int, data: bytes) -> bytes:
    """Build a DRW payload.
    
    Args:
        channel: DRW channel (0=command, 1=video)
        index: Packet index
        data: Payload data
    
    Returns:
        DRW payload ready for build_pppp_packet
    """
    header = struct.pack('>BBH', 0xD1, channel, index)
    return header + data


def build_cgi_command(cgi_path: str) -> bytes:
    """Build a VStarcam CGI command.
    
    Args:
        cgi_path: CGI path with parameters (e.g., '/get_status.cgi?...')
    
    Returns:
        VStarcam-formatted command bytes
    """
    # VStarcam CGI command format:
    # [01 0a 00 00] [length:4 LE] [command text]
    header = bytes([0x01, 0x0A, 0x00, 0x00])
    payload = cgi_path.encode('ascii')
    length = struct.pack('<I', len(payload))
    return header + length + payload


def parse_cgi_response(data: bytes) -> str:
    """Parse a VStarcam CGI response.
    
    Args:
        data: Response data from DRW channel 0
    
    Returns:
        Response text, or None if not a valid CGI response
    """
    # VStarcam CGI response format:
    # [01 0a 01 60] [14 09 00 01] [response text]
    # The response text starts with "result= 0;" followed by var declarations
    
    if len(data) < 8:
        return None
    
    # Check for VStarcam header
    if data[0] != 0x01 or data[1] != 0x0A:
        return None
    
    # Skip the 8-byte header
    response = data[8:]
    
    try:
        return response.decode('ascii')
    except UnicodeDecodeError:
        return None


def parse_cgi_result(response: str) -> dict:
    """Parse VStarcam CGI response text into a dictionary.
    
    Args:
        response: Response text from parse_cgi_response()
    
    Returns:
        Dictionary of parsed values, or None on error
    """
    if not response:
        return None
    
    result = {}
    
    # Parse result code
    if 'result=' in response:
        try:
            result_code = response.split('result=')[1].split(';')[0].strip()
            result['result'] = int(result_code)
        except (ValueError, IndexError):
            result['result'] = -1
    
    # Parse var declarations
    lines = response.split('\r\n')
    for line in lines:
        line = line.strip()
        if line.startswith('var '):
            try:
                # Parse "var name=value;"
                var_part = line[4:]  # Remove "var "
                if '=' in var_part:
                    name, value = var_part.split('=', 1)
                    name = name.strip()
                    value = value.rstrip(';').strip()
                    
                    # Remove quotes from string values
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    
                    # Try to convert to int
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                    
                    result[name] = value
            except (ValueError, IndexError):
                continue
    
    return result


# Known PSK keys
KNOWN_PSKS = {
    'vstarcam2019': create_psk_hash('vstarcam2019'),
    'vstarcam2018': create_psk_hash('vstarcam2018'),
    'camera': create_psk_hash('camera'),
    'SHIX': create_psk_hash('SHIX'),
    'SSD@cs2-network.': create_psk_hash('SSD@cs2-network.'),
}


def get_key4(psk: str) -> bytes:
    """Get 4-byte key for a PSK string.
    
    Args:
        psk: PSK string
    
    Returns:
        4-byte key
    """
    if psk in KNOWN_PSKS:
        return KNOWN_PSKS[psk]
    return create_psk_hash(psk)


# Convenience functions for OKAM camera (PSK: vstarcam2019)
OKAM_KEY4 = create_psk_hash('vstarcam2019')


def okam_encrypt(data: bytes) -> bytes:
    """Encrypt data with OKAM PSK (vstarcam2019)."""
    return pppp_encrypt(OKAM_KEY4, data)


def okam_decrypt(data: bytes) -> bytes:
    """Decrypt data with OKAM PSK (vstarcam2019)."""
    return pppp_decrypt(OKAM_KEY4, data)


def okam_build_packet(opcode: int, payload: bytes) -> bytes:
    """Build encrypted PPPP packet for OKAM camera."""
    return build_pppp_packet(opcode, payload, OKAM_KEY4)


def okam_parse_packet(data: bytes) -> dict:
    """Parse encrypted PPPP packet from OKAM camera."""
    return parse_pppp_packet(data, OKAM_KEY4)
