# SpaceWireForge Pro (v1.0.0)

> **Spacecraft Onboard Data Network & RMAP Studio, ECSS-E-ST-50-12C Packet Dissector, ECSS-E-ST-50-52C Remote Memory Access Protocol Codec, & Space Mission Cybersecurity Hardening Platform**

[![Standard](https://img.shields.io/badge/Standard-ECSS--E--ST--50--12C-00e5ff.svg)](#) [![Protocol](https://img.shields.io/badge/Protocol-ECSS--E--ST--50--52C%20RMAP-ffd700.svg)](#) [![Security](https://img.shields.io/badge/Security-NASA%20SP--800--53%20%7C%20CCSDS-00e676.svg)](#) [![Capture](https://img.shields.io/badge/Capture-Libpcap%202.4-ffab00.svg)](#) [![Platform](https://img.shields.io/badge/Platform-Web%20Studio%20%7C%20Python%203%20CLI-blue.svg)](#)

---

## Executive Summary

**SpaceWireForge Pro** is an aerospace spacecraft network engineering software suite, packet dissector, Remote Memory Access Protocol (RMAP) codec, and spaceflight cybersecurity auditing suite designed for satellite systems engineers, payload integrators, and flight software developers (James Webb Space Telescope, Orion, BepiColombo, EarthCARE, SmallSat constellations).

The platform enables instantaneous RMAP packet assembly, double CRC-8 polynomial verification (\$x^8 \+ x^2 \+ x \+ 1\$), 10-bit Data and 4-bit Control Character encoding, credit-based flow control (FCT) tracking, live spacecraft AOCS telemetry decoding, and automated spaceflight cybersecurity auditing without requiring expensive physical interface bricks.

---

## Key Features

- **ECSS-E-ST-50-52C RMAP Packet Engine**:  
  - Full support for Verified Write Commands, Non-Verified Writes, Read Commands, and Reply packets.  
  - Automatically calculates standard 8-bit Header CRC and Data CRC (\$x^8 \+ x^2 \+ x \+ 1\$, polynomial `0x07`).  
  - Supports 1-byte Authorization Key, 32-bit Memory Address, and 2-byte Transaction Sequence IDs.  
- **SpaceWire Character Codec & FCT Flow Controller**:  
  - Live encoding of 10-bit Data Characters and 4-bit Control Characters (FCT, EOP, EEP, ESC) with odd parity calculation.  
  - Interactive credit-based flow control simulator modeling receiver buffer depth and transmitter credit authorization.  
- **Spacecraft Telemetry Dashboard (AOCS & OBC)**:  
  - Real-time instruments decoding simulated orbital telemetry: LEO Altitude (km), Orbital Velocity (km/s), Gyro Pitch/Roll rates, OBC Core Temperature, and Solar Array Bus Power.  
  - Radiation glitch simulation (Error End of Packet \- EEP injection) and link state machine recovery.  
- **Space Mission Cybersecurity Auditor**:  
  - 10-point spaceflight cybersecurity verification engine evaluating RMAP key protection, AOCS routing segregation, double CRC validation, MMU write protection, and umbilical separation interlocks.  
- **EGSE Ground Test Hardening Synthesizer**:  
  - Synthesizes Linux `nftables` packet filtering rules, Suricata L7 intrusion detection signatures for RMAP key tampering, and sandboxed Linux `systemd` service units.  
- **Wireshark Libpcap 2.4 Exporter**:  
  - Emits native binary PCAP files containing SpaceWire/RMAP frames over UDP port 50155 for deep packet inspection.  
- **Cross-Platform Python 3 CLI Utility**:  
  - `spacewireforge-cli.py` delivers command-line automation for RMAP assembly, character packing, CRC calculation, and automated HIL test bench integration.

---

## Directory Layout

.

├── README.md                           \# Master Project Overview

├── build/

│   ├── spacewireforge-cli.py           \# Standalone Python 3 CLI

│   └── spacewireforge-pro-v1.0.0.zip   \# Complete Distribution Package

├── documentation/

│   ├── ARCHITECTURE.md                 \# ECSS-E-ST-50-12C & RMAP Protocol Specification

│   ├── USER\_GUIDE.md                   \# Full Operator & CLI Manual

│   └── MONETIZATION\_AND\_MARKETING\_PLAYBOOK.md \# Commercial Strategy & Defense Packaging

├── screenshots/

│   ├── spacewire-studio-preview.svg    \# High-Res Spacecraft Studio UI Preview

│   └── spacewire-architecture-diagram.svg \# Protocol Topology & Character Layer Diagram

└── source-code/

    ├── app.js                          \# Web Application Controller

    ├── index.html                      \# Glassmorphism Studio UI

    ├── spacewire-config-synthesizer.js \# nftables & Suricata Rules Synthesizer

    ├── spacewire-forge.css             \# Dark Spacecraft Flight Stylesheet

    ├── spacewire-protocol-engine.js    \# SpaceWire Character Codec & RMAP Engine

    └── spacewire-security-auditor.js   \# Space Cybersecurity Compliance Engine

---

## Standards Compliance

- **ECSS-E-ST-50-12C**: Space Engineering \- SpaceWire \- Links, nodes, routers and networks  
- **ECSS-E-ST-50-52C**: Space Engineering \- SpaceWire \- Remote memory access protocol (RMAP)  
- **NASA SP-800-53**: Security and Privacy Controls for Federal Information Systems and Organizations  
- **CCSDS 350.0-G-3**: The Application of CCSDS Space Data Link Security Protocols