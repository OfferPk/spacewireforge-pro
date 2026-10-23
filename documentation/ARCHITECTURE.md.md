# Architecture Specification: SpaceWireForge Pro (v1.0.0)

## 1\. Executive Summary

**SpaceWireForge Pro** is an aerospace and satellite onboard data network engineering studio, packet dissector, Remote Memory Access Protocol (RMAP) codec, and spaceflight cybersecurity auditing suite designed for spacecraft systems engineers, payload integrators, and satellite software developers.

Standardized by the European Space Agency (ESA) as **ECSS-E-ST-50-12C** and adopted by NASA, JAXA, and commercial space operators (James Webb Space Telescope, BepiColombo, ExoMars, Orion, EarthCARE), **SpaceWire** is the primary high-speed (2 to 200+ Mbps) point-to-point serial data-handling network connecting:

- Spacecraft On-Board Computers (OBC)  
- Attitude & Orbit Control Systems (AOCS)  
- High-resolution scientific imaging sensors and synthetic aperture radars (SAR)  
- Mass memory solid-state recorders (SSSR)  
- Telemetry, Tracking & Command (TT\&C) transponders

---

## 2\. Physical & Character Layer Architecture

SpaceWire uses low-voltage differential signaling (LVDS) over four shielded twisted pairs (Data In/Out, Strobe In/Out). Data and Strobe encoding (\$D/S\$) ensures that a signal transition occurs on either Data or Strobe on every bit period, allowing the receiver to recover the clock directly by exclusive-ORing \$D \\oplus S\$.

### Character Encoding:

1. **Data Character (10 bits)**:  
   - Formed by 1 Parity bit, 1 Control bit (`0`), and 8 Data bits.  
   - Parity is **Odd Parity** over the 10-bit character.  
   - Bit structure: `[P][0][D7][D6][D5][D4][D3][D2][D1][D0]`  
2. **Control Character (4 bits)**:  
   - Formed by 1 Parity bit, 1 Control bit (`1`), and 2 Control code bits.  
   - Parity is **Odd Parity** over the 4-bit character.  
   - Control codes:  
     - `00b`: Flow Control Token (FCT)  
     - `01b`: End of Packet (EOP)  
     - `10b`: Error End of Packet (EEP)  
     - `11b`: Escape Character (ESC)

 DATA CHARACTER (10 Bits):

 \+---+---+---+---+---+---+---+---+---+---+

 \| P \| 0 \|D7 \|D6 \|D5 \|D4 \|D3 \|D2 \|D1 \|D0 \|

 \+---+---+---+---+---+---+---+---+---+---+

 (Odd parity over all 10 bits)

 CONTROL CHARACTER (4 Bits):

 \+---+---+---+---+

 \| P \| 1 \|C1 \|C0 \|  Codes: FCT=00, EOP=01, EEP=10, ESC=11

 \+---+---+---+---+

 (Odd parity over all 4 bits)

 CONTROL SEQUENCES:

 NULL      \= ESC \+ FCT (Transmitted when link is idle)

 Time-Code \= ESC \+ Data Character (Propagates mission elapsed time ticks)

---

## 3\. Credit-Based Flow Control (FCT)

SpaceWire prevents receiver buffer overruns through strict credit authorization:

- Transmission of an **FCT (Flow Control Token)** informs the remote transmitter that 8 additional character buffer spaces are available.  
- A transmitter may never send data characters unless it has accumulated positive transmit credits (\$\> 0\$).  
- SpaceWire transceivers support a maximum outstanding credit count of 56 characters, ensuring deterministic link flow control with zero packet dropping.

---

## 4\. ECSS-E-ST-50-52C Remote Memory Access Protocol (RMAP)

RMAP defines a standardized packet protocol enabling an initiator node to read from, write to, or perform read-modify-write operations on target memory and memory-mapped registers across SpaceWire networks:

  \+-------------------------------------------------------------------------------+

  \| TARGET LOGICAL ADDR (1B) \| PROTOCOL ID (0x01) \| INSTRUCTION (1B) \| KEY (1B)   \|

  \+-------------------------------------------------------------------------------+

  \| REPLY LOGICAL ADDR (1B)  \| PROTOCOL ID (0x00) \| TRANSACTION SEQUENCE ID (2B)  \|

  \+-------------------------------------------------------------------------------+

  \| EXTENDED ADDRESS (1B)    \| 32-BIT MEMORY ADDRESS (4B)   \| DATA LENGTH (3B)    \|

  \+-------------------------------------------------------------------------------+

  \| HEADER CRC-8 (1B) (Polynomial: x^8 \+ x^2 \+ x \+ 1, Poly 0x07)                  \|

  \+-------------------------------------------------------------------------------+

  \| OPTIONAL WRITE DATA PAYLOAD (N Bytes)                                         \|

  \+-------------------------------------------------------------------------------+

  \| OPTIONAL DATA CRC-8 (1B) \| END OF PACKET (EOP \= 0x01 / EEP \= 0x02)            \|

  \+--------------------------+----------------------------------------------------+

### Instruction Byte Bitfield:

- **Bit 7**: Reserved (`0`)  
- **Bit 6**: Packet Type (`1` \= Command, `0` \= Reply)  
- **Bit 5**: Write/Read (`1` \= Write, `0` \= Read)  
- **Bit 4**: Verify Data (`1` \= Verify before commit, `0` \= Do not verify)  
- **Bit 3**: Reply Expected (`1` \= Send reply, `0` \= No reply)  
- **Bit 2**: Increment Address (`1` \= Increment, `0` \= Non-incrementing FIFO)  
- **Bits 1–0**: Reply Address Length (`00` \= 0B, `01` \= 4B, `10` \= 8B, `11` \= 12B)

---

## 5\. Space Mission Cybersecurity & Link Defense

The auditor validates systems against 10 critical spaceflight protection directives:

1. **SEC-SPW-01**: RMAP Authorization Key Rotation & Default Key Lockout.  
2. **SEC-SPW-02**: AOCS Flight-Critical Logical Address Routing Segregation.  
3. **SEC-SPW-03**: Mandatory Double CRC-8 Validation (Header & Data) prior to memory write.  
4. **SEC-SPW-04**: Hardware Credit Limit Watchdog (Anti-FCT babbling).  
5. **SEC-SPW-05**: Hardware MMU Memory Address Range Protection.  
6. **SEC-SPW-06**: Error End of Packet (EEP) Spillover Containment & Wormhole Circuit Flush.  
7. **SEC-SPW-07**: SpaceWire State Machine Radiation Glitch Autorecovery.  
8. **SEC-SPW-08**: Monotonic SpaceWire Time-Code Step Verification.  
9. **SEC-SPW-09**: Launch Umbilical EGSE Physical Airgap Interlock.  
10. **SEC-SPW-10**: Wormhole Routing Packet Timeout & Head-of-Line Deadlock Prevention.