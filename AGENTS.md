# Agent Notes for EVSE OCPP Analysis Tools

## Project Context

This repo contains tools for analyzing OCPP 1.6j WebSocket traffic from EV charging stations. There are two data formats to handle:

1. **XOR-encrypted traffic** (older BlueCorner/Blink stations): WebSocket frames are XOR-encrypted with a repeating 20-char key. The `bcencrypt` custom TShark dissector (`ws.lua`) intercepts port 80 WebSocket data and outputs `bcencrypt.hex` / `bcencrypt.command` fields.
2. **Plaintext JSON traffic** (newer eNovates stations): WebSocket frames carry raw JSON — no encryption.

## Key Files

- **`getkey.pl`** — Main script. Reads tshark output of `bcencrypt.hex`, detects encrypted vs plaintext mode (validates first frame as JSON), derives XOR key for encrypted data, or prints plaintext directly.
- **`netfilter.pl`** — Reads OCPP WebSocket traffic from pcap/tcpdump files (via tshark) or trace files (L:<LEN>\n<DATA> format). Self-contained — no external Perl module dependencies.
- **`ws.lua`** — Wireshark/TShark custom dissector. Uses a portable `bxor()` arithmetic function (compatible with Lua 5.1–5.4). Registers as heuristic on `ws.port 80`.
- **`evse-ws-decrypt.sh`** — Decrypts and displays OCPP messages using a key file + `ws.lua`.
- **`evse-report.pl`** — Generates charging transaction reports from snoop log files. Uses `JSON::PP`.
- **`laadpaal_bluecorner_00.tcpdump`** — Example encrypted capture (20-char XOR key: `DEOGNJIZSLEFAWPOORTS`).
- **`blink_trace.pcap`** — Example plaintext capture from eNovates station.

## Known Details

- The XOR key is always 20 characters long, repeating cyclically.
- OCPP 1.6j messages follow JSON-RPC-like array format: `[2,"reqId","MethodName",payload]` (send) or `[3,"reqId",response]` (receive/ack).
- `getkey.pl` detects plaintext by attempting `JSON::PP::decode_json()` on the first decoded frame. If valid → plaintext mode. If not → encrypted mode.
- `JSON.pm` is not installed; use `JSON::PP` instead (core module).
- Lua 5.4 removed `bit32` module; use arithmetic `bxor()` or the `~` operator depending on Lua version.

## Common Patterns / Commands

```bash
# Extract key or view messages
perl getkey.pl <pcapfile> 2>/dev/null

# Decrypt with key file
bash evse-ws-decrypt.sh <pcapfile> <keyfile> 2>/dev/null

# Inspect raw websocket
tshark -r <pcapfile> -X lua_script:./ws.lua -T fields -e bcencrypt.hex
tshark -r <pcapfile> -Y "websocket" -T fields -e websocket.payload.text
```

## Recent Changes (as of last commit)

- `ws.lua`: replaced `~` operator with portable `bxor()` function (commit: `c8ec9e3`)
- `getkey.pl`: added plaintext detection, switched to `JSON::PP`, quieted verbose debug output
- `netfilter.pl`: inlined utils::logger and utils::cfg, removed external module deps, added pcap/tcpdump support
- `README.md`: comprehensive docs added
- `LICENSE`: UNLICENSE (public domain)
