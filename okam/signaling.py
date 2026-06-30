"""
OKAM P2P Signaling Client
=========================
TCP client for the Eye4/VStarcam P2P signaling servers.

The signaling protocol is plaintext JSON over TCP with a 4-byte big-endian length prefix.
Used for device discovery, relay assignment, and device status queries.

Servers:
    47.91.201.49:32320  - Primary signaling (getDeviceInfo)
    198.11.174.54:12320 - Secondary signaling (register, toDevice, getStatus)
"""

import socket
import json
import time
import struct
import hashlib
import hmac
import base64


# Default signaling servers
DEFAULT_SIGNALING_SERVERS = [
    ('47.91.201.49', 32320),
    ('198.11.174.54', 12320),
]

# Default access key (from pcap capture)
DEFAULT_ACCESS_KEY = 'k3cTHvusdOyyrTKp'


class SignalingClient:
    """TCP client for P2P signaling servers."""
    
    def __init__(self, access_key: str = DEFAULT_ACCESS_KEY):
        """Initialize signaling client.
        
        Args:
            access_key: Access key for authentication (from pcap capture)
        """
        self.access_key = access_key
        self.socket = None
        self.server_host = None
        self.server_port = None
    
    def connect(self, host: str, port: int) -> bool:
        """Connect to signaling server.
        
        Args:
            host: Server hostname or IP
            port: Server port
        
        Returns:
            True if connected successfully
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5.0)
            self.socket.connect((host, port))
            self.server_host = host
            self.server_port = port
            return True
        except Exception as e:
            print(f'Connection failed: {e}')
            self.socket = None
            return False
    
    def connect_default(self) -> bool:
        """Connect to first available default signaling server.
        
        Returns:
            True if connected to any server
        """
        for host, port in DEFAULT_SIGNALING_SERVERS:
            if self.connect(host, port):
                return True
        return False
    
    def disconnect(self):
        """Disconnect from signaling server."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def _send_message(self, message: dict):
        """Send JSON message with 4-byte length prefix.
        
        Args:
            message: Dictionary to send as JSON
        """
        if not self.socket:
            raise ConnectionError('Not connected')
        
        json_data = json.dumps(message, separators=(', ', ': '))
        json_bytes = json_data.encode('utf-8')
        
        # Add 4-byte big-endian length prefix
        length_prefix = struct.pack('>I', len(json_bytes))
        self.socket.sendall(length_prefix + json_bytes)
    
    def _recv_message(self) -> dict:
        """Receive JSON message with 4-byte length prefix.
        
        Returns:
            Parsed JSON dictionary
        """
        if not self.socket:
            raise ConnectionError('Not connected')
        
        # Read 4-byte length prefix
        length_data = self._recv_exact(4)
        if not length_data:
            raise ConnectionError('Connection closed')
        
        length = struct.unpack('>I', length_data)[0]
        
        # Read JSON payload
        json_data = self._recv_exact(length)
        if not json_data:
            raise ConnectionError('Connection closed')
        
        return json.loads(json_data.decode('utf-8'))
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes.
        
        Args:
            n: Number of bytes to receive
        
        Returns:
            Received bytes, or None if connection closed
        """
        data = bytearray()
        while len(data) < n:
            try:
                chunk = self.socket.recv(n - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except socket.timeout:
                return None
            except Exception:
                return None
        return bytes(data)
    
    def _generate_signature(self, event: str, did: str, timestamp: str) -> str:
        """Generate signature for message authentication.
        
        Note: The exact signature algorithm is unknown. This is a placeholder
        that generates a plausible signature. The actual algorithm may use
        HMAC-SHA256 or a custom hash.
        
        Args:
            event: Event type (e.g., 'getDeviceInfo')
            did: Device ID
            timestamp: Unix timestamp string
        
        Returns:
            Base64-encoded signature string
        """
        # TODO: Determine exact signature algorithm from APK analysis
        # For now, use a simple HMAC that matches the observed format
        message = f'{event}{did}{timestamp}{self.access_key}'
        
        # Try HMAC-SHA256 (common in IoT devices)
        sig = hmac.new(
            self.access_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        
        return base64.b64encode(sig).decode()
    
    def _generate_sign(self, event: str, did: str, timestamp: str) -> str:
        """Generate numeric sign for message.
        
        Args:
            event: Event type
            did: Device ID
            timestamp: Unix timestamp string
        
        Returns:
            Numeric sign string
        """
        # TODO: Determine exact sign algorithm
        # Observations from pcap:
        #   getDeviceInfo VE3326855YITZ 1782759886 -> sign: "2976"
        #   getDeviceInfo ADG0259097RGBG 1782759886 -> sign: "8530"
        #   register 1782759887 -> sign: "5951"
        #   toDevice ADG0259097RGBG 1782759887 -> sign: "7282"
        #   getStatus ADG0259097RGBG 1782759887 -> sign: "645"
        
        # Simple hash-based sign (may need adjustment)
        message = f'{event}{did}{timestamp}{self.access_key}'
        hash_bytes = hashlib.md5(message.encode()).digest()
        sign_int = int.from_bytes(hash_bytes[:2], 'big')
        return str(sign_int)
    
    def get_device_info(self, did: str) -> dict:
        """Get device information and relay assignment.
        
        Args:
            did: Device ID (e.g., 'VE3326855YITZ')
        
        Returns:
            dict with keys: event, did, node_ip, node_port, ret
            Returns None on error
        """
        timestamp = str(int(time.time()))
        
        message = {
            'event': 'getDeviceInfo',
            'did': did,
            'AccessKey': self.access_key,
            'timestamp': timestamp,
            'sign': self._generate_sign('getDeviceInfo', did, timestamp),
            'signature': self._generate_signature('getDeviceInfo', did, timestamp),
        }
        
        try:
            self._send_message(message)
            response = self._recv_message()
            return response
        except Exception as e:
            print(f'getDeviceInfo failed: {e}')
            return None
    
    def register(self) -> dict:
        """Register with signaling server.
        
        Returns:
            Server response dict
        """
        timestamp = str(int(time.time()))
        
        message = {
            'event': 'register',
            'AccessKey': self.access_key,
            'timestamp': timestamp,
            'sign': self._generate_sign('register', '', timestamp),
            'signature': self._generate_signature('register', '', timestamp),
        }
        
        try:
            self._send_message(message)
            response = self._recv_message()
            return response
        except Exception as e:
            print(f'register failed: {e}')
            return None
    
    def get_status(self, did: str) -> dict:
        """Get device online status.
        
        Args:
            did: Device ID
        
        Returns:
            dict with keys: event, did, status, lastTime, offlineTime
            Returns None on error
        """
        timestamp = str(int(time.time()))
        
        message = {
            'event': 'getStatus',
            'did': did,
            'timestamp': timestamp,
            'sign': self._generate_sign('getStatus', did, timestamp),
            'signature': self._generate_signature('getStatus', did, timestamp),
        }
        
        try:
            self._send_message(message)
            response = self._recv_message()
            return response
        except Exception as e:
            print(f'getStatus failed: {e}')
            return None
    
    def to_device(self, did: str) -> dict:
        """Send command to device.
        
        Args:
            did: Device ID
        
        Returns:
            dict with keys: event, did, deviceStatus
            Returns None on error
        """
        timestamp = str(int(time.time()))
        
        message = {
            'event': 'toDevice',
            'did': did,
            'timestamp': timestamp,
            'sign': self._generate_sign('toDevice', did, timestamp),
            'signature': self._generate_signature('toDevice', did, timestamp),
        }
        
        try:
            self._send_message(message)
            response = self._recv_message()
            return response
        except Exception as e:
            print(f'toDevice failed: {e}')
            return None


class RelayAssignment:
    """Represents a relay server assignment for a camera."""
    
    def __init__(self, did: str, node_ip: str, node_port: int):
        self.did = did
        self.node_ip = node_ip
        self.node_port = node_port
    
    def __repr__(self):
        return f'RelayAssignment(did={self.did!r}, node={self.node_ip}:{self.node_port})'
    
    @classmethod
    def from_response(cls, response: dict) -> 'RelayAssignment':
        """Create RelayAssignment from getDeviceInfo response.
        
        Args:
            response: Response dict from getDeviceInfo()
        
        Returns:
            RelayAssignment instance, or None if response indicates error
        """
        if not response or response.get('ret') != 0:
            return None
        
        return cls(
            did=response.get('did', ''),
            node_ip=response.get('node_ip', ''),
            node_port=response.get('node_port', 0),
        )


def get_relay_assignment(did: str, access_key: str = DEFAULT_ACCESS_KEY) -> RelayAssignment:
    """Convenience function to get relay assignment for a device.
    
    Args:
        did: Device ID
        access_key: Access key for authentication
    
    Returns:
        RelayAssignment instance, or None if failed
    """
    client = SignalingClient(access_key)
    
    if not client.connect_default():
        return None
    
    try:
        response = client.get_device_info(did)
        return RelayAssignment.from_response(response)
    finally:
        client.disconnect()


# Test with known device from pcap
if __name__ == '__main__':
    print('Testing signaling client with known device...')
    
    client = SignalingClient()
    
    if client.connect_default():
        print(f'Connected to {client.server_host}:{client.server_port}')
        
        # Test getDeviceInfo
        response = client.get_device_info('VE3326855YITZ')
        print(f'getDeviceInfo: {response}')
        
        if response and response.get('ret') == 0:
            assignment = RelayAssignment.from_response(response)
            print(f'Relay assignment: {assignment}')
        
        client.disconnect()
    else:
        print('Failed to connect to signaling server')
