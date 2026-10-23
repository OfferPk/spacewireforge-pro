/**
 * SpaceWireForge Pro - Gateway Hardening & Intrusion Detection Synthesizer (v1.0.0)
 * Generates production configurations for SpaceWire-over-IP (EGSE) bridges:
 * 1. Linux nftables packet filter rules for SpaceWire/IP UDP bridges (Port 50155)
 * 2. Suricata L7 Intrusion Detection Signatures targeting RMAP key tampering and EEP injection
 * 3. Hardened, sandboxed systemd service definition for SpaceWire bridge daemons
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SpaceWireConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  function generateNftablesRules(options) {
    options = options || {};
    const iface = options.bridgeInterface || 'spw-bridge0';
    const egseIp = options.egseIp || '192.168.50.10';
    const port = options.udpPort || 50155;

    return `#!/usr/sbin/nft -f
# SpaceWireForge Pro - SpaceWire-over-IP (EGSE) Gateway Firewall Rules
# Enforces strict L4/L7 boundaries between SpaceWire ground test networks and spacecraft simulators

flush ruleset

table inet spacewire_firewall {
    # Set of authorized EGSE ground console IPs
    set authorized_consoles {
        type ipv4_addr
        elements = { ${egseIp}, 192.168.50.11, 192.168.50.12 }
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Allow local loopback
        iif "lo" accept

        # Connection tracking
        ct state established,related accept
        ct state invalid drop

        # Block unauthorized sources attempting to access SpaceWire telemetry bridge
        iif "${iface}" udp dport ${port} ip saddr != @authorized_consoles log prefix "[SPW-UNAUTH-EGSE]: " drop

        # Strict rate limiting for SpaceWire telemetry streaming (Max 25,000 pkts/sec)
        iif "${iface}" udp dport ${port} limit rate over 25000/second burst 1500 packets log prefix "[SPW-RATE-EXCEEDED]: " drop

        # Accept authorized SpaceWire telemetry
        iif "${iface}" udp dport ${port} ip saddr @authorized_consoles accept

        # Default drop
        counter log prefix "[SPW-DEFAULT-DROP]: " drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Isolate Spacecraft Flight Segment from EGSE Payload Networks
        iif "${iface}" oif != "${iface}" ct state established,related accept
        iif "${iface}" oif != "${iface}" counter drop
    }
}
`;
  }

  function generateSuricataSignatures(options) {
    options = options || {};
    const sidBase = options.sidBase || 2850100;
    const port = options.udpPort || 50155;

    return `# ------------------------------------------------------------------------
# SpaceWireForge Pro - Suricata L7 Intrusion Detection Signatures
# Target: SpaceWire-over-UDP Encapsulation (Port ${port}) & RMAP Packets
# Standards: ECSS-E-ST-50-12C, ECSS-E-ST-50-52C, NASA SP-800-53
# ------------------------------------------------------------------------

# Rule 1: Detect SpaceWire Error End of Packet (EEP = 0x02) Marker in Telemetry Stream
alert udp any any -> any ${port} (msg:"SPW-IDS SpaceWire EEP (Error End of Packet) Marker Detected"; content:"|53 57|"; offset:0; depth:2; content:"|02|"; distance:1; sid:${sidBase+1}; rev:1; classtype:protocol-command-decode; priority:2;)

# Rule 2: Detect RMAP Non-Incrementing Memory Write to Flight Critical Register Range
alert udp any any -> any ${port} (msg:"SPW-IDS RMAP Memory Write with Non-Incrementing Address Injected"; content:"|53 57|"; offset:0; depth:2; content:"|01|"; distance:1; byte_test:1,&,0x04,5,=,0; sid:${sidBase+2}; rev:1; classtype:bad-unknown; priority:1;)

# Rule 3: Detect Default or Null RMAP Authorization Key (Key = 0x00)
alert udp any any -> any ${port} (msg:"SPW-IDS RMAP Packet with Weak / Insecure Null Authorization Key (0x00)"; content:"|53 57|"; offset:0; depth:2; content:"|01|"; distance:1; byte_test:1,=,0,7; sid:${sidBase+3}; rev:1; classtype:attempted-admin; priority:1;)

# Rule 4: Detect Time-Code Step Anomaly / Rapid Desynchronization
alert udp any any -> any ${port} (msg:"SPW-IDS SpaceWire Time-Code Anomaly / High-Frequency Sync Broadcast"; content:"|53 57|"; offset:0; depth:2; threshold:type both, track by_src, count 200, seconds 1; sid:${sidBase+4}; rev:1; classtype:denial-of-service; priority:2;)

# Rule 5: Detect RMAP Header CRC Failure / Single-Event Upset (SEU) Telemetry Corrupt
alert udp any ${port} -> any any (msg:"SPW-IDS RMAP Target Reported Header or Data CRC Failure"; content:"|53 57|"; offset:0; depth:2; byte_test:1,=,0x02,7; sid:${sidBase+5}; rev:1; classtype:system-call-detect; priority:3;)
`;
  }

  function generateSystemdService(options) {
    options = options || {};
    const binPath = options.binaryPath || '/usr/local/bin/spacewireforge-daemon';
    const user = options.user || 'spwbridge';
    const port = options.udpPort || 50155;

    return `[Unit]
Description=SpaceWireForge Pro - ECSS-E-ST-50-12C Spacecraft Bus Gateway Daemon
Documentation=man:spacewireforge(8) https://github.com/spacecraft/spacewireforge
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${user}
Group=${user}
ExecStart=${binPath} --listen-port ${port} --routing-table /etc/spacewire/routing.conf --verify-crc
Restart=always
RestartSec=2s

# Strict Linux OS Security Sandboxing Directives (Mission Critical Flight Readiness)
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_NETLINK
RestrictRealtime=false
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
MemoryDenyWriteExecute=true
LockPersonality=true
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM

# Resource limits
LimitNOFILE=65535
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
`;
  }

  return {
    generateNftablesRules: generateNftablesRules,
    generateSuricataSignatures: generateSuricataSignatures,
    generateSystemdService: generateSystemdService
  };
}));
