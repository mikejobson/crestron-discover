# crestron-discover

A command-line tool that discovers Crestron AV devices on your local network using the Crestron CIP UDP broadcast protocol.

## Installation

### Homebrew (macOS — recommended)

```sh
brew install mikejobson/tap/crestron-discover
```

### go install

```sh
go install github.com/mikejobson/crestron-discover@latest
```

Requires Go 1.22 or later. The binary is placed in your `$GOPATH/bin` (or `~/go/bin` by default).

### Build from source

```sh
git clone https://github.com/mikejobson/crestron-discover.git
cd crestron-discover
go build -o crestron-discover
```

## Usage

Run the tool with no arguments:

```sh
crestron-discover
```

Example output:

```
Sending Crestron discovery packet as hostname 'my-mac'...
Waiting for replies (5s timeout)...
IP Address           Model              Serial               Version          Date         MAC
--------------------------------------------------------------------------------------------------------
192.168.1.50         CP4                FFFFFFFF             v4.0004.00114    Oct 18 2024  A1B2C3D4E5F6
192.168.1.51         DM-MD6X6           FFFFFFFF             v1.0002.00050    Jan 05 2023  0A1B2C3D4E5F
Done.
```

The tool listens for 5 seconds after sending the broadcast. All Crestron devices that respond within that window are listed.

> **Note:** The device must be on the same LAN segment — UDP broadcast packets do not cross routers or VLAN boundaries.

## How It Works

### Discovery packet

`crestron-discover` sends a single 316-byte UDP broadcast packet to `255.255.255.255` on port **41794** (the Crestron CIP discovery port). The packet contains a fixed 10-byte protocol header and the sender's hostname (truncated to 16 characters) embedded at byte offset 27. All remaining bytes are zero-padded.

The sending socket has `SO_BROADCAST` enabled, which is required on macOS for packets addressed to `255.255.255.255`.

### Device responses

Crestron devices that receive the broadcast send a UDP response back to the source port (41794). Because the tool binds to port 41794 before sending, it is already listening when replies arrive — avoiding any race condition with fast responders.

Responses from the local machine's own IP addresses are filtered out automatically.

### Response parsing

Each response is at least 272 bytes. The tool extracts:

| Field   | Location in response                                              |
|---------|-------------------------------------------------------------------|
| Model   | Bytes `0x0A`–`0x1A`, null-trimmed                                 |
| Version | Text block at `0x100`–`0x140`, format: `[v1.2.3 (Date), #Serial]` |
| Serial  | Parsed from the `#` prefix in the version text block              |
| Date    | Parsed from the `(…)` in the version text block                   |
| MAC     | Regex `@E-<12 hex digits>` searched across the full response      |

### Requirements

- macOS (released as a universal binary supporting both Intel and Apple Silicon)
- Same LAN segment as the Crestron devices being discovered
- Go 1.22+ if building from source
