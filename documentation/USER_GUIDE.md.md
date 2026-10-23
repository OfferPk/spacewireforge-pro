# User Guide: SpaceWireForge Pro (v1.0.0)

## 1\. Quick Start

### Launching the Web Studio

To run the interactive spacecraft network studio:

1. Open `index.html` in any modern web browser (Google Chrome, Apple Safari, Mozilla Firefox, Microsoft Edge).  
2. The studio is 100% self-contained and zero-infrastructure; all character encoding, CRC-8 calculations, RMAP codecs, and flow control simulators run purely client-side via JavaScript.

### Using the Python CLI

Ensure Python 3.8+ is installed:

\# Make the CLI script executable

chmod \+x spacewireforge-cli.py

\# Assemble an RMAP verified write command packet

./spacewireforge-cli.py pack-rmap \--target 0xFE \--key 0x55 \--trans-id 256 \--addr 0x40000000 \--data "STAR\_TRACKER\_CALIB"

\# Encode a SpaceWire 10-bit Data Character

./spacewireforge-cli.py pack-character \--type data \--val 0x42

\# Encode a SpaceWire 4-bit Control Character (FCT, EOP, EEP, ESC)

./spacewireforge-cli.py pack-character \--type control \--name FCT

\# Calculate standard ECSS-E-ST-50-52C CRC-8 on a hex string

./spacewireforge-cli.py calc-crc \--hex "FE017C55"

\# Run an automated space mission airworthiness and cybersecurity audit

./spacewireforge-cli.py audit-security

\# Export 50 synthetic SpaceWire/RMAP packets to a Wireshark-compatible PCAP file

./spacewireforge-cli.py export-pcap \--count 50 \--output satellite\_bus\_capture.pcap

---

## 2\. Studio Modules

### Tab 1: RMAP & Packet Studio

- **RMAP Command Builder**: Toggle between Write Command and Read Command, set Target Logical Address, 1-byte Authorization Key, 32-bit Memory Address, and Transaction Sequence ID.  
- **Packet Dissector & CRC-8 Inspector**: Color-coded breakdown of the serialized packet header, instruction field, address, header CRC-8, data payload, data CRC-8, and end-of-packet markers.  
- **CRC Error Injection**: Click "Inject CRC-8 Error" to invert header CRC bits and observe receiver abort behavior.

### Tab 2: Character & Token Dissector

- **Character Codec**: Inspect 10-bit Data Characters and 4-bit Control Characters with live odd-parity calculation.  
- **Credit-Based Flow Control (FCT) Simulator**: Click "Issue FCT (+8 Credits)" to simulate credit grants and monitor transmitter credit accounting in real time.  
- **Exchange Sequences**: Live table capturing NULL sequences, Time-Codes, and character transmissions.

### Tab 3: Spacecraft Telemetry (AOCS / OBC)

- Flight computer dashboard decoding real-time satellite telemetry:  
  - Low Earth Orbit Altitude (km)  
  - Orbital Velocity (km/s)  
  - AOCS Gyro Pitch and Roll Rates (°/s)  
  - On-Board Computer (OBC) Core Temperature (°C)  
  - Solar Array Bus Power Generation (Watts)  
  - SpaceWire Link Utilization (% of 100 Mbps)  
- Interactive buttons to inject single-event radiation upsets (EEP tokens) or reset the SpaceWire link state machine.

### Tab 4: ECSS & Mission Security Audit

- 10-point spaceflight cybersecurity verification engine evaluating RMAP key protection, AOCS routing segregation, double CRC validation, MMU write protection, and umbilical separation interlocks.

### Tab 5: EGSE Gateway Hardening

- Production-ready Linux `nftables` firewall rules protecting SpaceWire-over-IP test networks.  
- Suricata L7 intrusion detection signatures detecting RMAP authorization key tampering and spurious EEP frames.  
- Sandboxed `systemd` service unit definition with complete Linux capability drops.