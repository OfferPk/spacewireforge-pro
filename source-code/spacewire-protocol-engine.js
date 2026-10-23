/**
 * SpaceWireForge Pro - Protocol Engine (v1.0.0)
 * Spacecraft Onboard Data Network & RMAP Codec
 * Standards:
 * - ECSS-E-ST-50-12C (SpaceWire - Links, nodes, routers and networks)
 * - ECSS-E-ST-50-52C (SpaceWire - Remote Memory Access Protocol / RMAP)
 * 
 * Features:
 * - Character/Token Encoding:
 *   - Data Character: Parity + Control (0) + 8-bit Data (10-bit character)
 *   - Control Character: Parity + Control (1) + 2-bit Code (4-bit character: FCT, EOP, EEP, ESC)
 *   - Control Codes: FCT (00), EOP (01), EEP (10), ESC (11)
 *   - Exchange Sequences: NULL = ESC + FCT, Time-Code = ESC + Data Character
 * - Flow Control Token (FCT): Credit-based flow control (each FCT authorizes 8 additional data characters)
 * - End of Packet (EOP = 0x01) and Error End of Packet (EEP = 0x02) markers
 * - RMAP Packet Engine (ECSS-E-ST-50-52C):
 *   - Target Logical Address, Protocol ID (0x01 = RMAP), Instruction Byte (Packet Type, Write/Read, Verify, Reply, Increment)
 *   - Key / Authorization, Sequence Number (Transaction ID), Extended Address, 32-bit Memory Address, 24-bit Data Length
 *   - Header CRC (CRC-8, polynomial x^8 + x^2 + x + 1, poly 0x07) and Data CRC calculation
 * - Libpcap 2.4 Binary Network Capture Exporter (encapsulated over UDP Port 50155 for Wireshark)
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SpaceWireEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  // Constants
  const PROTOCOL_ID_RMAP = 0x01;
  const CONTROL_FCT = 0x00; // Flow Control Token
  const CONTROL_EOP = 0x01; // End of Packet
  const CONTROL_EEP = 0x02; // Error End of Packet
  const CONTROL_ESC = 0x03; // Escape character

  /**
   * ECSS-E-ST-50-52C Standard 8-bit CRC calculation
   * Polynomial: x^8 + x^2 + x + 1 (0x07)
   */
  function calculateCrc8(bytes) {
    let crc = 0x00;
    for (let i = 0; i < bytes.length; i++) {
      crc ^= bytes[i];
      for (let j = 0; j < 8; j++) {
        if (crc & 0x80) {
          crc = ((crc << 1) ^ 0x07) & 0xFF;
        } else {
          crc = (crc << 1) & 0xFF;
        }
      }
    }
    return crc;
  }

  /**
   * SpaceWire Character Parity Calculation (Odd Parity over Character)
   */
  function calculateCharParity(isControl, bits) {
    let count = isControl ? 1 : 0;
    let v = bits;
    while (v > 0) {
      count += (v & 1);
      v >>= 1;
    }
    return (count % 2 === 0) ? 1 : 0;
  }

  /**
   * Encodes a SpaceWire Data Character (10 bits)
   * Format: Parity (1 bit) + Control Bit (0) + Data (8 bits)
   */
  function encodeDataChar(dataByte) {
    dataByte = (dataByte & 0xFF);
    const parity = calculateCharParity(false, dataByte);
    // Value = (Parity << 9) | (0 << 8) | dataByte
    const rawVal = (parity << 9) | dataByte;
    return {
      type: 'DATA',
      isControl: false,
      data: dataByte,
      parity: parity,
      rawBits: rawVal,
      bitString: parity.toString() + '0' + dataByte.toString(2).padStart(8, '0'),
      hex: '0x' + dataByte.toString(16).padStart(2, '0').toUpperCase()
    };
  }

  /**
   * Encodes a SpaceWire Control Character (4 bits)
   * Format: Parity (1 bit) + Control Bit (1) + Code (2 bits)
   */
  function encodeControlChar(ctrlType) {
    let code = 0;
    let name = 'FCT';
    if (ctrlType === 'EOP') { code = CONTROL_EOP; name = 'EOP'; }
    else if (ctrlType === 'EEP') { code = CONTROL_EEP; name = 'EEP'; }
    else if (ctrlType === 'ESC') { code = CONTROL_ESC; name = 'ESC'; }
    else { code = CONTROL_FCT; name = 'FCT'; }

    const parity = calculateCharParity(true, code);
    const rawVal = (parity << 3) | (1 << 2) | code;
    return {
      type: 'CONTROL',
      isControl: true,
      name: name,
      code: code,
      parity: parity,
      rawBits: rawVal,
      bitString: parity.toString() + '1' + code.toString(2).padStart(2, '0'),
      hex: name
    };
  }

  /**
   * Assemble a standard SpaceWire Packet with Routing and End of Packet (EOP/EEP)
   */
  function packSpaceWirePacket(options) {
    options = options || {};
    const logicalAddress = options.logicalAddress !== undefined ? (options.logicalAddress & 0xFF) : 0xFE;
    const protocolId = options.protocolId !== undefined ? (options.protocolId & 0xFF) : PROTOCOL_ID_RMAP;
    const endMarker = (options.endMarker === 'EEP') ? 'EEP' : 'EOP';
    
    let payload = options.payload || [];
    if (typeof payload === 'string') {
      const arr = [];
      for (let i = 0; i < payload.length; i++) {
        arr.push(payload.charCodeAt(i));
      }
      payload = arr;
    }

    const rawBytes = [logicalAddress, protocolId].concat(payload);
    const characters = [];

    // Header and payload as Data Characters
    rawBytes.forEach(b => characters.push(encodeDataChar(b)));
    // End of packet as Control Character
    characters.push(encodeControlChar(endMarker));

    return {
      logicalAddress: logicalAddress,
      protocolId: protocolId,
      payloadLength: payload.length,
      totalBytes: rawBytes.length,
      endMarker: endMarker,
      characters: characters,
      rawHex: rawBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    };
  }

  /**
   * Assemble an ECSS-E-ST-50-52C RMAP Write/Read Command Packet
   */
  function packRmapCommand(options) {
    options = options || {};
    const targetLogicalAddress = options.targetLogicalAddress !== undefined ? (options.targetLogicalAddress & 0xFF) : 0xFE;
    const protocolId = PROTOCOL_ID_RMAP; // 0x01
    
    // Instruction Byte:
    // Bit 7: Reserved (0)
    // Bit 6: Command / Response (1 = Command, 0 = Response)
    // Bit 5: Write / Read (1 = Write, 0 = Read)
    // Bit 4: Verify Data (1 = Verify, 0 = Do not verify)
    // Bit 3: Reply (1 = Reply expected, 0 = No reply)
    // Bit 2: Increment Address (1 = Increment, 0 = Non-increment)
    // Bits 1-0: Reply Address Length (00 = 0 bytes, 01 = 4 bytes, 10 = 8 bytes, 11 = 12 bytes)
    const isWrite = options.isWrite !== undefined ? !!options.isWrite : true;
    const verifyData = options.verifyData !== undefined ? !!options.verifyData : true;
    const replyExpected = options.replyExpected !== undefined ? !!options.replyExpected : true;
    const increment = options.increment !== undefined ? !!options.increment : true;
    const replyAddrLen = (options.replyAddrLen || 0) & 0x03;

    let instruction = (1 << 6); // Command
    if (isWrite) instruction |= (1 << 5);
    if (verifyData) instruction |= (1 << 4);
    if (replyExpected) instruction |= (1 << 3);
    if (increment) instruction |= (1 << 2);
    instruction |= replyAddrLen;

    const key = options.key !== undefined ? (options.key & 0xFF) : 0x55;
    const replyLogicalAddress = options.replyLogicalAddress !== undefined ? (options.replyLogicalAddress & 0xFF) : 0x20;
    const transactionId = options.transactionId !== undefined ? (options.transactionId & 0xFFFF) : 0x0100;
    const extendedAddress = options.extendedAddress !== undefined ? (options.extendedAddress & 0xFF) : 0x00;
    const address32 = options.address !== undefined ? (options.address >>> 0) : 0x40000000;

    let data = options.data || [];
    if (typeof data === 'string') {
      const arr = [];
      for (let i = 0; i < data.length; i++) arr.push(data.charCodeAt(i));
      data = arr;
    }
    const dataLen = isWrite ? data.length : (options.readLength || 16);

    // Build Header bytes for CRC
    const headerBytes = [
      targetLogicalAddress,
      protocolId,
      instruction,
      key
    ];

    if (replyExpected) {
      headerBytes.push(replyLogicalAddress);
      headerBytes.push(options.protocolIdReply || 0x00);
    }

    headerBytes.push((transactionId >> 8) & 0xFF);
    headerBytes.push(transactionId & 0xFF);
    headerBytes.push(extendedAddress);
    headerBytes.push((address32 >> 24) & 0xFF);
    headerBytes.push((address32 >> 16) & 0xFF);
    headerBytes.push((address32 >> 8) & 0xFF);
    headerBytes.push(address32 & 0xFF);
    headerBytes.push((dataLen >> 16) & 0xFF);
    headerBytes.push((dataLen >> 8) & 0xFF);
    headerBytes.push(dataLen & 0xFF);

    const headerCrc = calculateCrc8(headerBytes);
    headerBytes.push(headerCrc);

    let fullPacketBytes = headerBytes.slice();
    let dataCrc = null;

    if (isWrite && data.length > 0) {
      dataCrc = calculateCrc8(data);
      fullPacketBytes = fullPacketBytes.concat(data);
      fullPacketBytes.push(dataCrc);
    }

    return {
      type: isWrite ? 'RMAP_WRITE_COMMAND' : 'RMAP_READ_COMMAND',
      targetLogicalAddress: targetLogicalAddress,
      protocolId: protocolId,
      instruction: instruction,
      instructionFlags: {
        isWrite: isWrite,
        verifyData: verifyData,
        replyExpected: replyExpected,
        increment: increment,
        replyAddrLen: replyAddrLen
      },
      key: key,
      replyLogicalAddress: replyLogicalAddress,
      transactionId: transactionId,
      extendedAddress: extendedAddress,
      addressHex: '0x' + address32.toString(16).padStart(8, '0').toUpperCase(),
      dataLength: dataLen,
      headerCrc: headerCrc,
      dataCrc: dataCrc,
      payloadBytes: data,
      fullPacketBytes: fullPacketBytes,
      packetHex: fullPacketBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    };
  }

  /**
   * Assemble an RMAP Reply Packet
   */
  function packRmapReply(options) {
    options = options || {};
    const replyLogicalAddress = options.replyLogicalAddress || 0x20;
    const protocolId = PROTOCOL_ID_RMAP;
    const instruction = options.instruction || 0x20; // Response bit set
    const status = options.status !== undefined ? (options.status & 0xFF) : 0x00; // 0 = Success
    const targetLogicalAddress = options.targetLogicalAddress || 0xFE;
    const transactionId = options.transactionId || 0x0100;

    let data = options.data || [];
    if (typeof data === 'string') {
      const arr = [];
      for (let i = 0; i < data.length; i++) arr.push(data.charCodeAt(i));
      data = arr;
    }

    const headerBytes = [
      replyLogicalAddress,
      protocolId,
      instruction,
      status,
      targetLogicalAddress,
      (transactionId >> 8) & 0xFF,
      transactionId & 0xFF
    ];

    const headerCrc = calculateCrc8(headerBytes);
    headerBytes.push(headerCrc);

    let fullBytes = headerBytes.slice();
    let dataCrc = null;
    if (data.length > 0) {
      dataCrc = calculateCrc8(data);
      fullBytes = fullBytes.concat(data);
      fullBytes.push(dataCrc);
    }

    return {
      type: 'RMAP_REPLY',
      replyLogicalAddress: replyLogicalAddress,
      status: status,
      statusDesc: status === 0 ? 'SUCCESS' : `ERROR_CODE_0x${status.toString(16).toUpperCase()}`,
      transactionId: transactionId,
      headerCrc: headerCrc,
      dataCrc: dataCrc,
      fullBytes: fullBytes,
      packetHex: fullBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    };
  }

  /**
   * Credit-Based Flow Control Simulator (FCT & Receive Buffer)
   */
  function createFlowController(rxBufferSizeChars) {
    rxBufferSizeChars = rxBufferSizeChars || 64;
    let localCreditsOutstanding = 0;
    let txCreditsAvailable = 0;
    let rxBufferUsed = 0;

    function sendFct() {
      // Sending an FCT informs remote transmitter that 8 character spaces are free
      if (rxBufferUsed + localCreditsOutstanding + 8 <= rxBufferSizeChars) {
        localCreditsOutstanding += 8;
        return { success: true, token: encodeControlChar('FCT'), creditsOutstanding: localCreditsOutstanding };
      }
      return { success: false, reason: 'BUFFER_NEAR_FULL', creditsOutstanding: localCreditsOutstanding };
    }

    function receiveFct() {
      // Remote receiver sent us an FCT, grant 8 transmission credits
      txCreditsAvailable += 8;
      return { txCreditsAvailable: txCreditsAvailable };
    }

    function transmitData(charByte) {
      if (txCreditsAvailable > 0) {
        txCreditsAvailable--;
        return { success: true, character: encodeDataChar(charByte), remainingCredits: txCreditsAvailable };
      }
      return { success: false, reason: 'NO_TX_CREDITS' };
    }

    function consumeRxData() {
      if (localCreditsOutstanding > 0) {
        localCreditsOutstanding--;
      }
      return { localCreditsOutstanding: localCreditsOutstanding };
    }

    return {
      sendFct: sendFct,
      receiveFct: receiveFct,
      transmitData: transmitData,
      consumeRxData: consumeRxData,
      getStats: () => ({
        localCreditsOutstanding: localCreditsOutstanding,
        txCreditsAvailable: txCreditsAvailable,
        rxBufferSizeChars: rxBufferSizeChars
      })
    };
  }

  /**
   * Libpcap 2.4 Binary Network Capture Exporter
   * Encapsulates SpaceWire / RMAP frames in Ethernet/IPv4/UDP on Port 50155
   */
  function exportToPcap(packets) {
    const pcapHeader = new Uint8Array([
      0xd4, 0xc3, 0xb2, 0xa1, // Magic Number
      0x02, 0x00,             // Major 2
      0x04, 0x00,             // Minor 4
      0x00, 0x00, 0x00, 0x00, // TZ
      0x00, 0x00, 0x00, 0x00, // SigFigs
      0xFF, 0xFF, 0x00, 0x00, // SnapLen (65535)
      0x01, 0x00, 0x00, 0x00  // LinkType Ethernet
    ]);

    const packetBuffers = [];
    let baseTime = Math.floor(Date.now() / 1000);
    let microTime = 0;

    packets.forEach((pkt, idx) => {
      microTime += 25000; // 25ms intervals
      let curSec = baseTime + Math.floor(microTime / 1000000);
      let curUSec = microTime % 1000000;

      const rawBytes = pkt.fullPacketBytes || pkt.fullBytes || [0xFE, 0x01, 0x00];

      // Ethernet Header (14 bytes)
      // Dst: 00:50:C2:50:15:53, Src: 00:50:C2:50:15:50, EtherType: 0x0800
      const eth = [
        0x00, 0x50, 0xC2, 0x50, 0x15, 0x53,
        0x00, 0x50, 0xC2, 0x50, 0x15, 0x50,
        0x08, 0x00
      ];

      // SpaceWire encapsulation payload: 2 bytes header length + rawBytes + 1 byte EOP (0x01)
      const spwPayload = [0x53, 0x57].concat(rawBytes, [0x01]);

      const udpLen = 8 + spwPayload.length;
      const ipLen = 20 + udpLen;

      // IPv4 Header (20 bytes)
      const ip = [
        0x45, 0x00,
        (ipLen >> 8) & 0xFF, ipLen & 0xFF,
        (idx >> 8) & 0xFF, idx & 0xFF,
        0x40, 0x00,
        0x40,
        0x11, // UDP
        0x00, 0x00,
        192, 168, 50, 10,
        192, 168, 50, 20
      ];

      // UDP Header (8 bytes) Port 50155 (0xC3EB)
      const udp = [
        0xC3, 0xEB,
        0xC3, 0xEB,
        (udpLen >> 8) & 0xFF, udpLen & 0xFF,
        0x00, 0x00
      ];

      const fullPacket = [].concat(eth, ip, udp, spwPayload);
      const capLen = fullPacket.length;

      const pcapPktHeader = [
        curSec & 0xFF, (curSec >> 8) & 0xFF, (curSec >> 16) & 0xFF, (curSec >> 24) & 0xFF,
        curUSec & 0xFF, (curUSec >> 8) & 0xFF, (curUSec >> 16) & 0xFF, (curUSec >> 24) & 0xFF,
        capLen & 0xFF, (capLen >> 8) & 0xFF, (capLen >> 16) & 0xFF, (capLen >> 24) & 0xFF,
        capLen & 0xFF, (capLen >> 8) & 0xFF, (capLen >> 16) & 0xFF, (capLen >> 24) & 0xFF
      ];

      packetBuffers.push(new Uint8Array(pcapPktHeader));
      packetBuffers.push(new Uint8Array(fullPacket));
    });

    let totalSize = pcapHeader.length;
    packetBuffers.forEach(b => totalSize += b.length);
    const finalBuffer = new Uint8Array(totalSize);

    finalBuffer.set(pcapHeader, 0);
    let offset = pcapHeader.length;
    packetBuffers.forEach(b => {
      finalBuffer.set(b, offset);
      offset += b.length;
    });

    return finalBuffer;
  }

  return {
    PROTOCOL_ID_RMAP: PROTOCOL_ID_RMAP,
    CONTROL_FCT: CONTROL_FCT,
    CONTROL_EOP: CONTROL_EOP,
    CONTROL_EEP: CONTROL_EEP,
    CONTROL_ESC: CONTROL_ESC,
    calculateCrc8: calculateCrc8,
    calculateCharParity: calculateCharParity,
    encodeDataChar: encodeDataChar,
    encodeControlChar: encodeControlChar,
    packSpaceWirePacket: packSpaceWirePacket,
    packRmapCommand: packRmapCommand,
    packRmapReply: packRmapReply,
    createFlowController: createFlowController,
    exportToPcap: exportToPcap
  };
}));
