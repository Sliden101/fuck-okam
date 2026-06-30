# OKAM Pro Camera Protocol Map

## Overview

The OKAM Pro camera uses the same CS2 Network / Eye4 / VStarcam P2P infrastructure.
The protocol is fully compatible with the `vstarcam2019` PSK.

## Camera Information

| Field | Value |
|-------|-------|
| **Device ID** | `VE3326855YITZ` |
| **Device ID (internal)** | `VSTL896293CRMVN` |
| **Password** | `888888` |
| **Login Hash** | `ac0b2702856222` |
| **Eye4 Account** | `207455122` |
| **PSK** | `vstarcam2019` |
| **PSK Key4** | `2d d3 61 07` |

## Network Architecture

```
┌──────────────┐     TCP:32320      ┌──────────────────┐
│  OKAM App    │───────────────────►│  P2P Signaling   │
│  (or our     │                    │  47.91.201.49    │
│   client)    │                    └──────────────────┘
│              │
│              │     TCP:12320      ┌──────────────────┐
│              │───────────────────►│  P2P Signaling   │
│              │                    │  198.11.174.54   │
│              │                    └──────────────────┘
│              │
│              │     UDP:6582       ┌──────────────────┐
│              │───────────────────►│  Video Relay     │
│              │                    │  119.15.90.42    │
│              │                    └──────────────────┘
└──────────────┘
```

## Signaling Protocol (TCP)

### Wire Format
```
[4-byte big-endian length][JSON payload]
```

### Message Types

#### getDeviceInfo
**Request:**
```json
{
  "event": "getDeviceInfo",
  "did": "VE3326855YITZ",
  "AccessKey": "k3cTHvusdOyyrTKp",
  "timestamp": "1782759886",
  "sign": "2976",
  "signature": "cra5eLkjxiO2Ce908ud91NjA6RQ="
}
```

**Response:**
```json
{
  "event": "getDeviceInfo",
  "did": "VE3326855YITZ",
  "node_ip": "119.23.227.151",
  "node_port": 32320,
  "ret": 0
}
```

#### register
**Request:**
```json
{
  "event": "register",
  "AccessKey": "k3cTHvusdOyyrTKp",
  "timestamp": "1782759887",
  "sign": "5951",
  "signature": "L2BsWLGpRJkj6uQQ52rzD3GF5Bk="
}
```

**Response:**
```json
{"event": "register"}
```

#### toDevice
**Request:**
```json
{
  "event": "toDevice",
  "did": "ADG0259097RGBG",
  "timestamp": "1782759887",
  "sign": "7282",
  "signature": "L4gy0Zdgs7gUvWzPT9eYah7LSlU="
}
```

**Response (offline):**
```json
{
  "did": "ADG0259097RGBG",
  "event": "toDevice",
  "deviceStatus": "offline"
}
```

#### getStatus
**Request:**
```json
{
  "event": "getStatus",
  "did": "ADG0259097RGBG",
  "timestamp": "1782759887",
  "sign": "645",
  "signature": "6D3a97Ge4EJLX/AJnLVNSyrBOP8="
}
```

**Response:**
```json
{
  "did": "ADG0259097RGBG",
  "event": "getStatus",
  "status": "offline",
  "lastTime": 1782020525,
  "offlineTime": 1782020604
}
```

## PPPP Protocol (UDP Relay)

### PSK (Pre-Shared Key)
- **PSK String:** `vstarcam2019`
- **Key4 (hex):** `2d d3 61 07`
- **Key derivation:** `create_psk_hash("vstarcam2019")`

### Encryption
- **Algorithm:** Stateful XOR stream cipher with 256-byte shuffle table
- **Table:** Standard PPPP PE table (same as open_camera repo)
- **First byte:** Encrypted magic `0xe4` decrypts to `0xf1` (unencrypted magic)

### Packet Structure
```
[PPPP Header: 4 bytes][Payload: variable]
```

**Header:**
- Byte 0: Magic (0xf1 unencrypted, 0xe4 encrypted with vstarcam2019)
- Byte 1: Opcode
- Bytes 2-3: Payload length (big-endian)

### Opcodes
| Opcode | Name | Description |
|--------|------|-------------|
| 0x70 | KEEPALIVE | Keepalive ping |
| 0x73 | CONTROL | Control message |
| 0x83 | IDENTIFY | Device identification |
| 0xD0 | MSG_DRW | Data channel (commands + video) |
| 0xD1 | MSG_DRW_ACK | Data channel acknowledgment |
| 0xE0 | MSG_ALIVE | Keepalive |
| 0xE1 | MSG_ALIVE_ACK | Keepalive response |
| 0xF0 | MSG_CLOSE | Connection close |

### DRW Data Channel (Opcode 0xD0)
```
[PPPP Header: 4 bytes][DRW Header: 4 bytes][Payload]
```

**DRW Header:**
- Byte 4: Magic (0xd1)
- Byte 5: Channel (0=command, 1=video)
- Bytes 6-7: Index (big-endian)

### Command Channel (Channel 0)
Commands are HTTP CGI requests wrapped in SHIX format:

**SHIX Header:**
```
[0x06 0x0A 0xA0 0x80][4-byte LE length][JSON/CGI payload]
```

**CGI Commands:**
```
GET /get_status.cgi?loginuse=admin&loginpas=ac0b2702856222&user=admin&pwd=888888
GET /eye4_authentication.cgi?loginAccount=207455122&loginToken=...&loginuse=admin&loginpas=...
```

### Video Channel (Channel 1)
Video data is H.264 encoded with PPPP framing:

**Frame Marker:**
```
[0x55 0xAA 0x15 0xA8][28 bytes header][H.264 NAL units]
```

**H.264 Structure:**
- SPS (Sequence Parameter Set) - NAL type 7
- PPS (Picture Parameter Set) - NAL type 8
- IDR slice (keyframe) - NAL type 5
- Non-IDR slice - NAL type 1

## Servers

| Server | IP | Port | Protocol | Purpose |
|--------|-----|------|----------|---------|
| P2P Signaling | 47.91.201.49 | 32320 | TCP | Device discovery |
| P2P Signaling | 198.11.174.54 | 12320 | TCP | Registration + commands |
| Video Relay | 119.15.90.42 | 6582 | UDP | Video streaming |
| Assigned Relay | 119.23.227.151 | 32320 | TCP | Per-session relay |

## DNS Domains
- `api.eye4.cn`
- `s2.eye4.cn`
- `liteos-master.eye4.cn`
- `vuid-vp.eye4.cn`
- `s3.vstarcam.com`
- `en-download.camera666.com`

## Known Device IDs
| DID | Status | Relay Node |
|-----|--------|------------|
| VE3326855YITZ | Online | 119.23.227.151:32320 |
| ADG0259097RGBG | Offline | 198.11.174.54:12320 |
