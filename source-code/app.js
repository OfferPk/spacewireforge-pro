/**
 * SpaceWireForge Pro - Application Controller (v1.0.0)
 * Orchestrates UI tabs, RMAP command synthesizer, character codec & FCT flow control simulator,
 * spacecraft telemetry display, and ECSS mission security auditing.
 */

document.addEventListener('DOMContentLoaded', function() {
  'use strict';

  // Navigation
  const tabs = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  // RMAP Elements
  const selectRmapType = document.getElementById('select-rmap-type');
  const inputTargetAddr = document.getElementById('input-target-addr');
  const inputAuthKey = document.getElementById('input-auth-key');
  const inputTransId = document.getElementById('input-trans-id');
  const inputMemAddr = document.getElementById('input-mem-addr');
  const selectEndMarker = document.getElementById('select-end-marker');
  const inputPayload = document.getElementById('input-payload');
  const btnSynthesizeRmap = document.getElementById('btn-synthesize-rmap');
  const btnCorruptCrc = document.getElementById('btn-corrupt-crc');
  const currentCmdBadge = document.getElementById('current-cmd-badge');
  const badgeCrcStatus = document.getElementById('badge-crc-status');

  // Dissector Visualizer Elements
  const visTarget = document.getElementById('vis-target');
  const visProto = document.getElementById('vis-proto');
  const visAddr = document.getElementById('vis-addr');
  const visCrc = document.getElementById('vis-crc');
  const visEop = document.getElementById('vis-eop');
  const outInstruction = document.getElementById('out-instruction');
  const outKey = document.getElementById('out-key');
  const outTransId = document.getElementById('out-trans-id');
  const outHeaderCrc = document.getElementById('out-header-crc');
  const outDataCrc = document.getElementById('out-data-crc');
  const outEndMarker = document.getElementById('out-end-marker');
  const outPacketHex = document.getElementById('out-packet-hex');

  // Token Monitor Elements
  const btnSendFct = document.getElementById('btn-send-fct');
  const btnResetCredits = document.getElementById('btn-reset-credits');
  const displayTxCredits = document.getElementById('display-tx-credits');
  const displayRxBuffer = document.getElementById('display-rx-buffer');
  const tokenTrafficTbody = document.getElementById('token-traffic-tbody');
  const btnTopExportPcap = document.getElementById('btn-top-export-pcap');

  // Spacecraft Telemetry Elements
  const gaugeSpAlt = document.getElementById('gauge-sp-alt');
  const gaugeSpVel = document.getElementById('gauge-sp-vel');
  const gaugeSpPitch = document.getElementById('gauge-sp-pitch');
  const gaugeSpRoll = document.getElementById('gauge-sp-roll');
  const gaugeSpTemp = document.getElementById('gauge-sp-temp');
  const gaugeSpPower = document.getElementById('gauge-sp-power');
  const gaugeSpUtil = document.getElementById('gauge-sp-util');
  const gaugeSpLatency = document.getElementById('gauge-sp-latency');
  const btnInjectEepGlitch = document.getElementById('btn-inject-eep-glitch');
  const btnResetLink = document.getElementById('btn-reset-link');

  // Audit Elements
  const auditScorePct = document.getElementById('audit-score-pct');
  const auditRulesContainer = document.getElementById('audit-rules-container');
  const btnRunAudit = document.getElementById('btn-run-audit');

  // Config Elements
  const codeNftables = document.getElementById('code-nftables');
  const codeSuricata = document.getElementById('code-suricata');
  const codeSystemd = document.getElementById('code-systemd');

  // State
  let forceCrcCorruption = false;
  let flowController = SpaceWireEngine.createFlowController(64);
  flowController.receiveFct(); // 8 initial credits
  flowController.receiveFct(); // 16
  flowController.receiveFct(); // 24
  flowController.receiveFct(); // 32
  flowController.receiveFct(); // 40
  flowController.receiveFct(); // 48
  flowController.receiveFct(); // 56 credits

  let packetBuffer = [];
  let simMicroTime = 100000;

  // Spacecraft state
  let orbitAlt = 542.4;
  let orbitVel = 7.61;
  let aocsPitchRate = 0.04;
  let aocsRollRate = -0.02;
  let obcTemp = 24.2;
  let solarPower = 1480;

  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const pane = document.getElementById(tab.dataset.tab);
      if (pane) pane.classList.add('active');
    });
  });

  // Synthesize RMAP Packet
  function updateRmapStudio() {
    const isWrite = (selectRmapType.value === 'WRITE');
    const targetAddr = parseInt(inputTargetAddr.value, 16) || 0xFE;
    const authKey = parseInt(inputAuthKey.value, 16) || 0x55;
    const transId = parseInt(inputTransId.value, 10) || 256;
    const memAddr = parseInt(inputMemAddr.value, 16) || 0x40000000;
    const endMarker = selectEndMarker.value;
    const payloadStr = inputPayload.value || 'DATA';

    currentCmdBadge.textContent = isWrite ? 'WRITE COMMAND' : 'READ COMMAND';
    currentCmdBadge.className = 'badge badge-rmap';

    const rmapPkt = SpaceWireEngine.packRmapCommand({
      targetLogicalAddress: targetAddr,
      isWrite: isWrite,
      verifyData: true,
      replyExpected: true,
      increment: true,
      key: authKey,
      transactionId: transId,
      address: memAddr,
      data: payloadStr
    });

    if (forceCrcCorruption) {
      rmapPkt.headerCrc = (rmapPkt.headerCrc ^ 0xFF);
      badgeCrcStatus.textContent = 'HEADER CRC ERROR DETECTED';
      badgeCrcStatus.className = 'badge badge-eep';
    } else {
      badgeCrcStatus.textContent = 'HEADER & DATA CRC VALID';
      badgeCrcStatus.className = 'badge badge-ok';
    }

    visTarget.textContent = '0x' + targetAddr.toString(16).toUpperCase().padStart(2, '0');
    visProto.textContent = '0x01 (RMAP)';
    visAddr.textContent = rmapPkt.addressHex;
    visCrc.textContent = '0x' + rmapPkt.headerCrc.toString(16).toUpperCase().padStart(2, '0');
    visEop.textContent = endMarker;

    outInstruction.textContent = `0x${rmapPkt.instruction.toString(16).toUpperCase()} (${isWrite ? 'Verified Write' : 'Read'}, Reply Expected, Incrementing)`;
    outKey.textContent = `0x${authKey.toString(16).toUpperCase()} (${authKey === 0 ? 'WARNING: Null Key' : 'Valid Authorization Key'})`;
    outTransId.textContent = `0x${transId.toString(16).toUpperCase().padStart(4, '0')} (Transaction #${transId})`;
    outHeaderCrc.textContent = `0x${rmapPkt.headerCrc.toString(16).toUpperCase().padStart(2, '0')} (Polynomial x^8 + x^2 + x + 1 ${forceCrcCorruption ? 'CORRUPT' : 'VALID'})`;
    outDataCrc.textContent = rmapPkt.dataCrc !== null ? `0x${rmapPkt.dataCrc.toString(16).toUpperCase().padStart(2, '0')} (Payload Integrity Verified)` : 'N/A (Read Command)';
    outEndMarker.textContent = `${endMarker} (${endMarker === 'EOP' ? 'Normal Packet Closure' : 'Error Abort Marker'})`;
    outPacketHex.value = rmapPkt.packetHex;

    packetBuffer.unshift(rmapPkt);
    if (packetBuffer.length > 50) packetBuffer.pop();
  }

  btnSynthesizeRmap.addEventListener('click', () => {
    forceCrcCorruption = false;
    updateRmapStudio();
  });

  btnCorruptCrc.addEventListener('click', () => {
    forceCrcCorruption = !forceCrcCorruption;
    updateRmapStudio();
  });

  [selectRmapType, inputTargetAddr, inputAuthKey, inputTransId, inputMemAddr, selectEndMarker, inputPayload].forEach(el => {
    if (el) el.addEventListener('input', () => {
      forceCrcCorruption = false;
      updateRmapStudio();
    });
  });

  // Flow Controller Simulator
  function renderFlowStats() {
    const stats = flowController.getStats();
    displayTxCredits.textContent = `TX CREDITS: ${stats.txCreditsAvailable} CHARS`;
    displayRxBuffer.textContent = `${64 - stats.localCreditsOutstanding} / 64 Chars Available`;
  }

  btnSendFct.addEventListener('click', () => {
    const res = flowController.sendFct();
    if (res.success) {
      flowController.receiveFct(); // Grant remote transmission credits
      simMicroTime += 12;
      addTokenRow(simMicroTime, 'FCT (Flow Control Token)', 'P 1 00', 'FCT (4 bits)', 'ODD OK', '+8 TX Credits', 'LINK ACTIVE');
    } else {
      alert('Local receiver buffer full. Cannot issue FCT.');
    }
    renderFlowStats();
  });

  btnResetCredits.addEventListener('click', () => {
    flowController = SpaceWireEngine.createFlowController(64);
    for (let i = 0; i < 7; i++) flowController.receiveFct();
    renderFlowStats();
    alert('Flow controller reset. 56 transmission credits restored.');
  });

  function addTokenRow(timeUs, type, bits, hex, parity, impact, state) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${timeUs}</td>
      <td><span class="badge ${type.includes('FCT') ? 'badge-fct' : (type.includes('EEP') ? 'badge-eep' : 'badge-rmap')}">${type}</span></td>
      <td style="font-family:var(--font-mono);">${bits}</td>
      <td>${hex}</td>
      <td><span class="badge badge-ok">${parity}</span></td>
      <td>${impact}</td>
      <td>${state}</td>
    `;
    if (tokenTrafficTbody.firstChild) {
      tokenTrafficTbody.insertBefore(tr, tokenTrafficTbody.firstChild);
    } else {
      tokenTrafficTbody.appendChild(tr);
    }
    if (tokenTrafficTbody.children.length > 40) {
      tokenTrafficTbody.removeChild(tokenTrafficTbody.lastChild);
    }
  }

  // Periodic Spacecraft Stream Generator
  function generateSpacecraftTelemetry() {
    simMicroTime += Math.floor(Math.random() * 40) + 120;
    
    // Slight orbital perturbations
    orbitAlt += (Math.random() - 0.505) * 0.02;
    orbitVel = Math.sqrt(398600.4418 / (6378.137 + orbitAlt));
    aocsPitchRate = (Math.random() - 0.49) * 0.08;
    aocsRollRate = (Math.random() - 0.49) * 0.05;
    solarPower = Math.round(1475 + Math.random() * 15);
    obcTemp = 24.0 + (Math.random() * 0.4);

    gaugeSpAlt.textContent = orbitAlt.toFixed(2);
    gaugeSpVel.textContent = orbitVel.toFixed(3);
    gaugeSpPitch.textContent = (aocsPitchRate >= 0 ? '+' : '') + aocsPitchRate.toFixed(2) + '°/s';
    gaugeSpRoll.textContent = (aocsRollRate >= 0 ? '+' : '') + aocsRollRate.toFixed(2) + '°/s';
    gaugeSpTemp.textContent = '+' + obcTemp.toFixed(1) + '°C';
    gaugeSpPower.textContent = solarPower.toLocaleString() + ' W';

    // Simulate character transmission
    if (Math.random() > 0.4) {
      const res = flowController.transmitData(0xFE);
      if (res.success) {
        addTokenRow(simMicroTime, 'DATA CHARACTER', res.character.bitString, res.character.hex, 'ODD OK', '-1 TX Credit', 'RUN');
      } else {
        // Send FCT
        flowController.receiveFct();
      }
    }
    renderFlowStats();
  }

  btnInjectEepGlitch.addEventListener('click', () => {
    simMicroTime += 10;
    addTokenRow(simMicroTime, 'EEP (Error End of Packet)', 'P 1 10', 'EEP (4 bits)', 'ODD OK', 'Packet Abort', 'CIRCUIT FLUSH');
    alert('Injected SpaceWire EEP (Error End of Packet) token. Target node aborted current memory transaction.');
  });

  btnResetLink.addEventListener('click', () => {
    alert('Triggered SpaceWire State Machine Reset: Transitioned ErrorReset -> ErrorWait -> Ready -> Started -> Connecting -> Run.');
  });

  // PCAP Export
  function exportPcapCapture() {
    if (packetBuffer.length === 0) {
      updateRmapStudio();
    }
    const pcapBytes = SpaceWireEngine.exportToPcap(packetBuffer);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `spacewire-flight-capture-${Date.now()}.pcap`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  btnTopExportPcap.addEventListener('click', exportPcapCapture);

  // Security Audit
  function renderAudit() {
    const config = {
      enforceDynamicRmapKeys: true,
      defaultKeyInUse: false,
      isolatedAocsRouting: true,
      verifyDataBeforeWrite: true,
      hardwareCreditGuard: true,
      rmapMemoryProtectionTable: true,
      autoEepSpilloverTermination: true,
      compliantStateMachineTimers: true,
      timeCodeMonotonicFilter: true,
      umbilicalSeparationInterlock: true,
      wormholeWatchdogTimer: true
    };

    const audit = SpaceWireSecurityAuditor.runAudit(config);
    auditScorePct.textContent = `${audit.percentage}%`;
    auditScorePct.style.color = audit.percentage >= 90 ? 'var(--accent-green)' : (audit.percentage >= 70 ? 'var(--accent-gold)' : 'var(--accent-red)');

    auditRulesContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const card = document.createElement('div');
      card.className = 'audit-rule-card ' + (f.passed ? '' : 'failed');
      card.innerHTML = `
        <div style="flex:1;">
          <div class="audit-rule-title">${f.id}: ${f.title}</div>
          <div class="audit-rule-standard">Standard: ${f.standard} | Severity: ${f.severity}</div>
          <div class="audit-rule-desc">${f.description}</div>
          <div class="audit-rule-remed"><strong>Remediation:</strong> ${f.remediation}</div>
        </div>
        <div>
          <span class="badge ${f.passed ? 'badge-ok' : 'badge-eep'}">${f.passed ? 'PASS (+10)' : 'DEFICIENCY (0)'}</span>
        </div>
      `;
      auditRulesContainer.appendChild(card);
    });
  }

  btnRunAudit.addEventListener('click', renderAudit);

  // Hardening Configurations
  function renderConfigs() {
    codeNftables.textContent = SpaceWireConfigSynthesizer.generateNftablesRules({
      bridgeInterface: 'spw-bridge0',
      egseIp: '192.168.50.10',
      udpPort: 50155
    });

    codeSuricata.textContent = SpaceWireConfigSynthesizer.generateSuricataSignatures({
      sidBase: 2850100,
      udpPort: 50155
    });

    codeSystemd.textContent = SpaceWireConfigSynthesizer.generateSystemdService({
      binaryPath: '/usr/local/bin/spacewireforge-daemon',
      user: 'spwbridge',
      udpPort: 50155
    });
  }

  // Init
  updateRmapStudio();
  renderFlowStats();
  renderAudit();
  renderConfigs();
  setInterval(generateSpacecraftTelemetry, 450);
});
