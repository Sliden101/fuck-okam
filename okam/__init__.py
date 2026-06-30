"""
OKAM Camera Package
===================
Python client for OKAM Pro cameras using the Eye4/VStarcam P2P protocol.
"""

from .signaling import SignalingClient, RelayAssignment, get_relay_assignment
from .stream_decoder import StreamDecoder, H264Parser
from .camera import OKAMCamera

__version__ = '1.0.0'
__all__ = [
    'SignalingClient',
    'RelayAssignment',
    'get_relay_assignment',
    'StreamDecoder',
    'H264Parser',
    'OKAMCamera',
]
