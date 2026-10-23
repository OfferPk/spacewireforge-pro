/**
 * SpaceWireForge Pro - Space Mission Cybersecurity & Link State Auditor (v1.0.0)
 * Evaluates SpaceWire & RMAP networks against:
 * - ECSS-E-ST-50-12C (SpaceWire links, state machines, and routing)
 * - ECSS-E-ST-50-52C (RMAP authorization keys and CRC verification)
 * - NASA SP-800-53 / NIST Cybersecurity Framework for Space Systems
 * - CCSDS 350.0-G-3 (Space Data Link Security Protocols)
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SpaceWireSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  const AUDIT_RULES = [
    {
      id: 'SEC-SPW-01',
      category: 'RMAP_AUTHORIZATION',
      severity: 'CRITICAL',
      title: 'RMAP Authorization Key Protection & Key Rotation',
      standard: 'ECSS-E-ST-50-52C §5.1 / NASA Space Cyber Guard',
      description: 'RMAP commands use a 1-byte Authorization Key to prevent unauthorized memory modification. Default or static keys (e.g., 0x00, 0x55) allow rogue instruments or compromised payloads to overwrite flight software.',
      check: function(config) {
        if (!config.enforceDynamicRmapKeys || config.defaultKeyInUse) {
          return {
            passed: false,
            score: 0,
            remediation: 'Implement mission-specific non-default authorization keys with cryptographic rotation across ground passes.'
          };
        }
        return { passed: true, score: 10, remediation: 'Dynamic non-default RMAP authorization keys enforced across all nodes.' };
      }
    },
    {
      id: 'SEC-SPW-02',
      category: 'PAYLOAD_ISOLATION',
      severity: 'CRITICAL',
      title: 'Flight-Critical Bus vs Scientific Payload Logical Isolation',
      standard: 'ECSS-E-ST-50-12C §10.2 / CCSDS 350.0-G-3',
      description: 'On-Board Computer (OBC), AOCS (Attitude & Orbit Control), and Telemetry & Telecommand (TT&C) nodes must be isolated via router routing tables from science instruments to prevent babbling or packet flooding.',
      check: function(config) {
        if (!config.isolatedAocsRouting) {
          return {
            passed: false,
            score: 0,
            remediation: 'Configure SpaceWire router routing table to strictly partition flight control logical addresses from instrument networks.'
          };
        }
        return { passed: true, score: 10, remediation: 'Router port partitions strictly segregate AOCS and payload telemetry.' };
      }
    },
    {
      id: 'SEC-SPW-03',
      category: 'CRC_VERIFICATION',
      severity: 'HIGH',
      title: 'Mandatory Double CRC-8 Validation (Header & Data)',
      standard: 'ECSS-E-ST-50-52C §5.4',
      description: 'Target nodes must enforce both Header CRC and Data CRC validation prior to committing memory writes. Writing memory before Data CRC verification can cause memory corruption during single-event upsets (SEU).',
      check: function(config) {
        if (!config.verifyDataBeforeWrite) {
          return {
            passed: false,
            score: 2,
            remediation: 'Buffer full incoming payload and verify Data CRC before writing into flight memory or registers.'
          };
        }
        return { passed: true, score: 10, remediation: 'Pre-write verification buffer active with CRC-8 hardware verification.' };
      }
    },
    {
      id: 'SEC-SPW-04',
      category: 'FLOW_CONTROL_CREDIT',
      severity: 'HIGH',
      title: 'FCT Credit Babbling & Transmitter Starvation Protection',
      standard: 'ECSS-E-ST-50-12C §8.3',
      description: 'Routers and nodes must monitor credit counters (max 56 character credits outstanding). Malicious or glitching nodes generating spurious FCTs can cause receiver buffer overflows.',
      check: function(config) {
        if (!config.hardwareCreditGuard) {
          return {
            passed: false,
            score: 4,
            remediation: 'Deploy credit limit watchdog halting transmission if remote terminal issues FCTs beyond configured buffer depth.'
          };
        }
        return { passed: true, score: 10, remediation: 'Hardware credit limit check active (max 56 characters).' };
      }
    },
    {
      id: 'SEC-SPW-05',
      category: 'MEMORY_BOUNDS',
      severity: 'HIGH',
      title: 'RMAP Memory Address Range Whitelisting',
      standard: 'ECSS-E-ST-50-52C §5.6 / NIST SP 800-82',
      description: 'RMAP targets must enforce strict memory access tables rejecting writes to bootloader ROM, secure cryptographic keys, or critical flight control vectors.',
      check: function(config) {
        if (!config.rmapMemoryProtectionTable) {
          return {
            passed: false,
            score: 2,
            remediation: 'Implement hardware memory management unit (MMU) write-protecting boot areas from RMAP writes.'
          };
        }
        return { passed: true, score: 10, remediation: 'Hardware-enforced MMU memory write boundaries verified.' };
      }
    },
    {
      id: 'SEC-SPW-06',
      category: 'ERROR_PROPAGATION',
      severity: 'MEDIUM',
      title: 'Error End of Packet (EEP) Spillover Containment',
      standard: 'ECSS-E-ST-50-12C §11.4',
      description: 'When an EEP (Error End of Packet) token is received on a wormhole-routed network, all intermediate switches must truncate and terminate the packet immediately to prevent link deadlocks.',
      check: function(config) {
        if (!config.autoEepSpilloverTermination) {
          return {
            passed: false,
            score: 4,
            remediation: 'Configure router ports with automatic EEP packet flush and transmission link reset.'
          };
        }
        return { passed: true, score: 10, remediation: 'Automatic EEP detection and wormhole circuit cleanup active.' };
      }
    },
    {
      id: 'SEC-SPW-07',
      category: 'LINK_AUTORESET',
      severity: 'MEDIUM',
      title: 'State Machine Disconnect / Parity Error Autorecovery',
      standard: 'ECSS-E-ST-50-12C §7.2',
      description: 'SpaceWire links must transition through ErrorReset $\\rightarrow$ ErrorWait $\\rightarrow$ Ready $\\rightarrow$ Started $\\rightarrow$ Connecting $\\rightarrow$ Run with strict 6.4us / 12.8us timers to survive radiation-induced parity glitches.',
      check: function(config) {
        if (!config.compliantStateMachineTimers) {
          return {
            passed: false,
            score: 5,
            remediation: 'Ensure state machine timeout registers adhere to standard 6.4 us and 12.8 us timer specifications.'
          };
        }
        return { passed: true, score: 10, remediation: 'Compliant link interface recovery state machine verified.' };
      }
    },
    {
      id: 'SEC-SPW-08',
      category: 'TIME_CODE_SYNC',
      severity: 'MEDIUM',
      title: 'SpaceWire Time-Code Synchronization Anti-Spoofing',
      standard: 'ECSS-E-ST-50-12C §8.8',
      description: 'Time-Codes (ESC + Data character) synchronize onboard instrument clocks. Receiving nodes must reject non-monotonic time leaps to prevent spacecraft epoch corruption.',
      check: function(config) {
        if (!config.timeCodeMonotonicFilter) {
          return {
            passed: false,
            score: 5,
            remediation: 'Implement monotonic time-code step filter rejecting delta leaps greater than 1 epoch tick.'
          };
        }
        return { passed: true, score: 10, remediation: 'Strict monotonic time-code step verification active.' };
      }
    },
    {
      id: 'SEC-SPW-09',
      category: 'GROUND_EGSE_AIRGAP',
      severity: 'HIGH',
      title: 'EGSE Ground Test Receptacle Umbilical Disconnect Interlock',
      standard: 'NASA-STD-8739.8 / ECSS-E-ST-50-12C',
      description: 'Electrical Ground Support Equipment (EGSE) test tap lines must be physically uncoupled or isolated once the spacecraft umbilical separates at launch.',
      check: function(config) {
        if (!config.umbilicalSeparationInterlock) {
          return {
            passed: false,
            score: 2,
            remediation: 'Incorporate launch umbilical physical break relays disconnecting ground SpaceWire test ports.'
          };
        }
        return { passed: true, score: 10, remediation: 'Hardware umbilical separation interlock completely isolates test taps.' };
      }
    },
    {
      id: 'SEC-SPW-10',
      category: 'WORMHOLE_DEADLOCK',
      severity: 'MEDIUM',
      title: 'Wormhole Routing Packet Timeout & Anti-Head-of-Line Blocking',
      standard: 'ECSS-E-ST-50-12C §10.3',
      description: 'SpaceWire routers use wormhole routing where the packet head advances before the tail is sent. Stalled packets can lock up router switches; watchdog timers must inject EEP to free blocked paths.',
      check: function(config) {
        if (!config.wormholeWatchdogTimer) {
          return {
            passed: false,
            score: 5,
            remediation: 'Enable router port wormhole packet timeout (default 10 ms) to terminate stalled packet transfers.'
          };
        }
        return { passed: true, score: 10, remediation: 'Wormhole packet timeout active with automated EEP injection.' };
      }
    }
  ];

  function runAudit(config) {
    config = config || {};
    let totalScore = 0;
    const maxScore = AUDIT_RULES.length * 10;
    const findings = [];

    AUDIT_RULES.forEach(rule => {
      const res = rule.check(config);
      totalScore += res.score;
      findings.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        standard: rule.standard,
        description: rule.description,
        passed: res.passed,
        score: res.score,
        remediation: res.remediation
      });
    });

    const percentage = Math.round((totalScore / maxScore) * 100);
    let airworthinessStatus = 'CERTIFIED_FLIGHT_READY';
    if (percentage < 70) {
      airworthinessStatus = 'MISSION_REJECTED';
    } else if (percentage < 90) {
      airworthinessStatus = 'CONDITIONAL_WAIVER_REQUIRED';
    }

    return {
      timestamp: new Date().toISOString(),
      score: totalScore,
      maxScore: maxScore,
      percentage: percentage,
      status: airworthinessStatus,
      totalRules: AUDIT_RULES.length,
      passedCount: findings.filter(f => f.passed).length,
      failedCount: findings.filter(f => !f.passed).length,
      findings: findings
    };
  }

  return {
    AUDIT_RULES: AUDIT_RULES,
    runAudit: runAudit
  };
}));
