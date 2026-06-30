"""
OKAM Stream Decoder
===================
Extract H.264 video frames from PPPP relay stream.

The video stream uses PPPP DRW channel 1 with a custom framing format:
- Frame marker: 55 AA 15 A8
- 28-byte header (after marker)
- H.264 NAL units

H.264 structure:
- SPS (Sequence Parameter Set) - NAL type 7
- PPS (Picture Parameter Set) - NAL type 8
- IDR slice (keyframe) - NAL type 5
- Non-IDR slice - NAL type 1
"""

import struct
from typing import Optional, List, Tuple

# PPPP video frame marker
VIDEO_MARKER = b'\x55\xAA\x15\xA8'

# H.264 NAL unit start codes
NAL_START_CODE_4 = b'\x00\x00\x00\x01'
NAL_START_CODE_3 = b'\x00\x00\x01'

# H.264 NAL types
NAL_TYPE_NON_IDR = 1
NAL_TYPE_PARTITION_A = 2
NAL_TYPE_PARTITION_B = 3
NAL_TYPE_PARTITION_C = 4
NAL_TYPE_IDR = 5
NAL_TYPE_SEI = 6
NAL_TYPE_SPS = 7
NAL_TYPE_PPS = 8
NAL_TYPE_AUD = 9
NAL_TYPE_FILLER = 12

NAL_TYPE_NAMES = {
    NAL_TYPE_NON_IDR: 'Non-IDR slice',
    NAL_TYPE_PARTITION_A: 'Partition A',
    NAL_TYPE_PARTITION_B: 'Partition B',
    NAL_TYPE_PARTITION_C: 'Partition C',
    NAL_TYPE_IDR: 'IDR slice',
    NAL_TYPE_SEI: 'SEI',
    NAL_TYPE_SPS: 'SPS',
    NAL_TYPE_PPS: 'PPS',
    NAL_TYPE_AUD: 'AUD',
    NAL_TYPE_FILLER: 'Filler',
}


class StreamDecoder:
    """Decode H.264 video from PPPP relay stream."""
    
    def __init__(self):
        """Initialize stream decoder."""
        self._buffer = bytearray()
        self._frame_boundaries = []
        self._current_frame = None
        self._frame_count = 0
    
    def feed_packet(self, data: bytes) -> List[bytes]:
        """Feed a raw video packet from channel 1.
        
        Args:
            data: Raw video data from DRW channel 1
        
        Returns:
            List of complete H.264 frames (may be empty)
        """
        frames = []
        
        # Check for video frame marker
        if data[:4] == VIDEO_MARKER:
            # This is a new frame boundary
            self._frame_boundaries.append(len(self._buffer))
            
            # Skip the 32-byte PPPP video header
            video_data = data[32:]
        else:
            video_data = data
        
        # Add to buffer
        self._buffer.extend(video_data)
        
        # Check if we have complete frames
        while len(self._frame_boundaries) >= 2:
            start = self._frame_boundaries[0]
            end = self._frame_boundaries[1]
            
            # Extract frame
            frame_data = bytes(self._buffer[start:end])
            
            # Only return frames that contain H.264 data
            if self._contains_h264(frame_data):
                frames.append(frame_data)
                self._frame_count += 1
            
            # Remove processed data
            self._buffer = self._buffer[end:]
            self._frame_boundaries = [b - end for b in self._frame_boundaries[1:]]
        
        return frames
    
    def _contains_h264(self, data: bytes) -> bool:
        """Check if data contains H.264 NAL units.
        
        Args:
            data: Data to check
        
        Returns:
            True if H.264 data detected
        """
        # Look for NAL start codes
        return (NAL_START_CODE_4 in data or 
                NAL_START_CODE_3 in data)
    
    def get_frame_count(self) -> int:
        """Get number of frames decoded.
        
        Returns:
            Frame count
        """
        return self._frame_count
    
    def reset(self):
        """Reset decoder state."""
        self._buffer = bytearray()
        self._frame_boundaries = []
        self._current_frame = None
        self._frame_count = 0


class H264Parser:
    """Parse H.264 bitstream and extract NAL units."""
    
    @staticmethod
    def find_nal_units(data: bytes) -> List[Tuple[int, int]]:
        """Find all NAL units in H.264 data.
        
        Args:
            data: H.264 bitstream data
        
        Returns:
            List of (offset, nal_type) tuples
        """
        nal_units = []
        pos = 0
        
        while pos < len(data) - 4:
            # Check for 4-byte start code
            if data[pos:pos+4] == NAL_START_CODE_4:
                nal_type = data[pos+4] & 0x1F
                nal_units.append((pos, nal_type))
                pos += 4
            # Check for 3-byte start code
            elif data[pos:pos+3] == NAL_START_CODE_3:
                nal_type = data[pos+3] & 0x1F
                nal_units.append((pos, nal_type))
                pos += 3
            else:
                pos += 1
        
        return nal_units
    
    @staticmethod
    def extract_nal_unit(data: bytes, offset: int) -> bytes:
        """Extract a single NAL unit from H.264 data.
        
        Args:
            data: H.264 bitstream data
            offset: Offset of NAL unit start (including start code)
        
            Returns:
                NAL unit data (including start code)
        """
        # Find the start of this NAL unit
        if data[offset:offset+4] == NAL_START_CODE_4:
            start = offset
            offset += 4
        elif data[offset:offset+3] == NAL_START_CODE_3:
            start = offset
            offset += 3
        else:
            return b''
        
        # Find the start of the next NAL unit
        pos = offset
        while pos < len(data) - 4:
            if (data[pos:pos+4] == NAL_START_CODE_4 or 
                data[pos:pos+3] == NAL_START_CODE_3):
                break
            pos += 1
        
        return data[start:pos]
    
    @staticmethod
    def get_nal_type_name(nal_type: int) -> str:
        """Get human-readable name for NAL type.
        
        Args:
            nal_type: NAL unit type (0-31)
        
        Returns:
            Human-readable name
        """
        return NAL_TYPE_NAMES.get(nal_type, f'Unknown ({nal_type})')
    
    @staticmethod
    def is_keyframe(data: bytes) -> bool:
        """Check if H.264 data contains a keyframe (IDR).
        
        Args:
            data: H.264 bitstream data
        
        Returns:
            True if keyframe detected
        """
        nal_units = H264Parser.find_nal_units(data)
        
        for offset, nal_type in nal_units:
            if nal_type == NAL_TYPE_IDR:
                return True
        
        return False
    
    @staticmethod
    def extract_sps_pps(data: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Extract SPS and PPS from H.264 data.
        
        Args:
            data: H.264 bitstream data
        
        Returns:
            Tuple of (sps_data, pps_data), either may be None
        """
        nal_units = H264Parser.find_nal_units(data)
        
        sps = None
        pps = None
        
        for offset, nal_type in nal_units:
            if nal_type == NAL_TYPE_SPS:
                sps = H264Parser.extract_nal_unit(data, offset)
            elif nal_type == NAL_TYPE_PPS:
                pps = H264Parser.extract_nal_unit(data, offset)
        
        return sps, pps


def create_h264_header(sps: bytes, pps: bytes) -> bytes:
    """Create H.264 bitstream header with SPS and PPS.
    
    Args:
        sps: SPS NAL unit (with start code)
        pps: PPS NAL unit (with start code)
    
        Returns:
            H.264 header bytes
    """
    header = bytearray()
    
    if sps:
        header.extend(sps)
    if pps:
        header.extend(pps)
    
    return bytes(header)


def extract_h264_from_pcap(decoder: StreamDecoder, pcap_data: List[bytes]) -> bytes:
    """Extract complete H.264 bitstream from pcap video data.
    
    Args:
        decoder: StreamDecoder instance
        pcap_data: List of raw video packets from pcap
    
    Returns:
        Complete H.264 bitstream
    """
    h264_data = bytearray()
    
    for packet in pcap_data:
        frames = decoder.feed_packet(packet)
        for frame in frames:
            h264_data.extend(frame)
    
    return bytes(h264_data)


# Test with pcap data
if __name__ == '__main__':
    import subprocess
    
    print('Testing stream decoder with pcap data...')
    
    # Decrypt and extract video data from pcap
    SHUFFLE_TABLE = [
        0x7C,0x9C,0xE8,0x4A,0x13,0xDE,0xDC,0xB2,0x2F,0x21,0x23,0xE4,0x30,0x7B,0x3D,0x8C,
        0xBC,0x0B,0x27,0x0C,0x3C,0xF7,0x9A,0xE7,0x08,0x71,0x96,0x00,0x97,0x85,0xEF,0xC1,
        0x1F,0xC4,0xDB,0xA1,0xC2,0xEB,0xD9,0x01,0xFA,0xBA,0x3B,0x05,0xB8,0x15,0x87,0x83,
        0x28,0x72,0xD1,0x8B,0x5A,0xD6,0xDA,0x93,0x58,0xFE,0xAA,0xCC,0x6E,0x1B,0xF0,0xA3,
        0x88,0xAB,0x43,0xC0,0x0D,0xB5,0x45,0x38,0x4F,0x50,0x22,0x66,0x20,0x7F,0x07,0x5B,
        0x14,0x98,0x1D,0x9B,0xA7,0x2A,0xB9,0xA8,0xCB,0xF1,0xFC,0x49,0x47,0x06,0x3E,0xB1,
        0x0E,0x04,0x3A,0x94,0x5E,0xEE,0x54,0x11,0x34,0xDD,0x4D,0xF9,0xEC,0xC7,0xC9,0xE3,
        0x78,0x1A,0x6F,0x70,0x6B,0xA4,0xBD,0xA9,0x5D,0xD5,0xF8,0xE5,0xBB,0x26,0xAF,0x42,
        0x37,0xD8,0xE1,0x02,0x0A,0xAE,0x5F,0x1C,0xC5,0x73,0x09,0x4E,0x69,0x24,0x90,0x6D,
        0x12,0xB3,0x19,0xAD,0x74,0x8A,0x29,0x40,0xF5,0x2D,0xBE,0xA5,0x59,0xE0,0xF4,0x79,
        0xD2,0x4B,0xCE,0x89,0x82,0x48,0x84,0x25,0xC6,0x91,0x2B,0xA2,0xFB,0x8F,0xE9,0xA6,
        0xB0,0x9E,0x3F,0x65,0xF6,0x03,0x31,0x2E,0xAC,0x0F,0x95,0x2C,0x5C,0xED,0x39,0xB7,
        0x33,0x6C,0x56,0x7E,0xB4,0xA0,0xFD,0x7A,0x81,0x53,0x51,0x86,0x8D,0x9F,0x77,0xFF,
        0x6A,0x80,0xDF,0xE2,0xBF,0x10,0xD7,0x75,0x64,0x57,0x76,0xF3,0x55,0xCD,0xD0,0xC8,
        0x18,0xE6,0x36,0x41,0x62,0xCF,0x99,0xF2,0x32,0x4C,0x67,0x60,0x61,0x92,0xCA,0xD3,
        0xEA,0x63,0x7D,0x16,0xB6,0x8E,0xD4,0x68,0x35,0xC3,0x52,0x9D,0x46,0x44,0x1E,0x17,
    ]
    
    def create_psk_hash(psk):
        h = [0, 0, 0, 0]
        for b in psk.encode():
            h[0] = (h[0] + b) & 0xFF
            h[1] = (h[1] - b) & 0xFF
            h[2] = (h[2] + b // 3) & 0xFF
            h[3] = (h[3] ^ b) & 0xFF
        return h
    
    def pppp_decrypt(key4, data):
        result = bytearray()
        prev = 0
        for b in data:
            idx = (key4[prev & 3] + prev) & 0xFF
            key = SHUFFLE_TABLE[idx]
            dec = (b ^ key) & 0xFF
            result.append(dec)
            prev = b
        return bytes(result)
    
    key4 = create_psk_hash('vstarcam2019')
    
    # Extract video packets from pcap
    result = subprocess.run([
        'tshark', '-r', 'joebiden.pcapng',
        '-Y', 'ip.addr==119.15.90.42 && udp.port==6582',
        '-T', 'fields', '-e', 'frame.number', '-e', 'ip.src', '-e', 'data.data'
    ], capture_output=True, text=True, timeout=15)
    
    video_packets = []
    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) < 3 or not parts[2]:
            continue
        
        try:
            data = bytes.fromhex(parts[2])
        except:
            continue
        
        if len(data) < 4:
            continue
        
        dec = pppp_decrypt(key4, data)
        opcode = dec[1]
        
        if opcode != 0xD0 or len(dec) < 8:
            continue
        
        channel = dec[5]
        payload = dec[8:]
        
        if channel == 1:
            video_packets.append(payload)
    
    print(f'Found {len(video_packets)} video packets')
    
    # Decode with StreamDecoder
    decoder = StreamDecoder()
    h264_data = bytearray()
    
    for packet in video_packets:
        frames = decoder.feed_packet(packet)
        for frame in frames:
            h264_data.extend(frame)
    
    print(f'Decoded {decoder.get_frame_count()} frames')
    print(f'H.264 bitstream size: {len(h264_data)} bytes')
    
    # Analyze H.264 content
    parser = H264Parser()
    nal_units = parser.find_nal_units(h264_data)
    print(f'Found {len(nal_units)} NAL units')
    
    # Show first few NAL units
    for i, (offset, nal_type) in enumerate(nal_units[:10]):
        name = parser.get_nal_type_name(nal_type)
        print(f'  NAL {i}: offset={offset}, type={name}')
    
    # Save H.264 bitstream
    with open('test_stream.h264', 'wb') as f:
        f.write(h264_data)
    print(f'Saved to test_stream.h264')
    print('Play with: ffplay test_stream.h264')
