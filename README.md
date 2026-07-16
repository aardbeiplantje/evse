# EVSE WebSocket OCPP 1.6j Analysis Tools

Tools for capturing, decrypting, and analyzing OCPP 1.6j (Open Charge Point Protocol) WebSocket traffic from electric vehicle charging stations.

## Prerequisites

```bash
sudo apt install perl libjson-perl tcpdump tshark gawk bash jq lua5.3
```

> **Note on Lua**: The bundled `ws.lua` uses a portable XOR implementation compatible with Lua 5.1–5.4. If you encounter bitwise operator errors, the script includes a fallback arithmetic implementation.

## File Descriptions

| File | Description |
|------|-------------|
| `getkey.pl` | Extract the XOR encryption key from a pcap/tcpdump file, or output plaintext messages if no encryption is detected |
| `ws.lua` | Custom Wireshark/TShark dissector for the `bcencrypt` protocol heuristic on WebSocket port 80 |
| `evse-ws-decrypt.sh` | Decrypt and display OCPP 1.6j messages using a key file |
| `evse-report.pl` | Generate a summary report of charging transactions from snoop log files |

## Usage

### 1. Capture traffic

```bash
tcpdump -i eth0 -s 65535 -w tcpdump.pcap
```

### 2. Extract XOR key

```bash
perl getkey.pl tcpdump.pcap 2>/dev/null > bc.key
```

Output the XOR key (or plaintext messages if the capture uses unencrypted WebSocket).

### 3. Decrypt and view OCPP messages

```bash
bash evse-ws-decrypt.sh tcpdump.pcap ~/bc.key 2>/dev/null
```

## How It Works

### Encrypted traffic (older BlueCorner / Blink stations)

Some charging stations encrypt their WebSocket frames using a repeating XOR key (20 characters). The pipeline:

1. `ws.lua` — TShark heuristic dissector that intercepts WebSocket data on port 80 and exposes `bcencrypt.hex` and `bcencrypt.command` fields
2. `getkey.pl` — Reads hex-encoded encrypted frames, identifies known OCPP message patterns (BootNotification, etc.), derives the XOR key by comparing against expected plaintext
3. `evse-ws-decrypt.sh` — Uses the key with TShark to decrypt and display all messages

### Plaintext traffic (newer eNovates stations)

Newer firmware or different network paths may carry OCPP as plain JSON over WebSocket with no encryption. `getkey.pl` detects this automatically: if the first decoded frame parses as valid JSON, it prints the messages directly without attempting XOR decryption.

## Example Outputs

### Encrypted (key extracted)

```
$ perl getkey.pl laadpaal_bluecorner_00.tcpdump 2>/dev/null
DEOGNJIZSLEFAWPOORTS
```

### Plaintext (no encryption)

```
$ perl getkey.pl blink_trace.pcap 2>/dev/null
[2,"1","BootNotification",{"chargePointVendor":"eNovates",...}]
[3,"1",{"currentTime":"2026-07-16T08:53:33Z","interval":3600,"status":"Accepted"}]
```

## License

Private / Internal use only.
