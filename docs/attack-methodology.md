# Attack Methodology

This document describes each attack phase from the attacker's perspective, maps them to real-world ICS incidents, and explains why each technique is effective against industrial control systems. Understanding the attacker's mindset is essential for building effective detections.

## ICS Cyber Kill Chain

The attack simulation follows the ICS Cyber Kill Chain (based on the SANS ICS Kill Chain model), adapted for Modbus/TCP environments:

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│    Phase 1   │   │    Phase 2   │   │    Phase 3   │
│    Recon     │──►│ Initial      │──►│    Web       │
│              │   │ Access       │   │ Exploitation │
└──────────────┘   └──────────────┘   └──────────────┘
                                            │
┌──────────────┐   ┌──────────────┐   ┌─────▼────────┐
│    Phase 6   │   │    Phase 5   │   │    Phase 4   │
│   Impact     │◄──│ Persistence  │◄──│     OT       │
│ (Deny/Destr) │   │              │   │ Manipulation │
└──────────────┘   └──────────────┘   └──────────────┘
```

## Phase 1: Reconnaissance

### Attacker Goal
Map the OT network — identify which PLCs exist, what function codes they accept, and what registers/coils are configured.

### Techniques Used

**Port Scanning (T0802)**
```
5 rapid TCP connections to modbus-sim:5020
```
The attacker probes for Modbus/TCP services (port 502/5020). Unlike IT port scans, OT port scans are extremely targeted — attackers already know the protocol and just need to find live hosts.

**Register Enumeration (T0802)**
```
FC 0x01: Read Coils (addr 0-15)     — discover digital outputs
FC 0x04: Read Input Registers (0-9) — discover analog inputs
```
Reading registers reveals the PLC's I/O configuration. An attacker can determine what physical processes the PLC controls (valves, motors, sensors) by mapping which addresses return valid data.

**Device Fingerprinting (T0846)**
```
FC 0x08: Diagnostics        — query device health counters
FC 0x2B: Read Device ID     — extract vendor, model, firmware version
```
FC 0x2B (MEI - Modbus Encapsulated Interface) returns vendor name, product code, and firmware version. This information enables targeted exploits against known vulnerabilities in specific PLC firmware versions.

### Real-World Parallel
**Industroyer/CrashOverride (2016)** — The attackers spent months mapping Ukraine's power grid, identifying specific IEC 104 and IEC 61850 endpoints before launching their attack. The reconnaissance phase was the longest and most critical.

### Why Modbus Is Vulnerable
Modbus has **no authentication**. Any device on the network can read any register from any PLC. There is no concept of sessions, tokens, or access control — the protocol was designed in 1979 for trusted serial networks.

---

## Phase 2: Initial Access via SSH Brute Force

### Attacker Goal
Gain shell access to OT infrastructure (SCADA servers, engineering workstations, historians) to pivot deeper into the control network.

### Techniques Used

**Credential Stuffing (T0886)**
```
10 SSH login attempts with ICS-specific usernames:
root, admin, operator, plc-admin, scada, engineer,
hmi-user, ot-admin, maintenance, field-tech
```

The username list targets default and common OT credentials. Many ICS environments use shared accounts (`operator`, `engineer`) because individual authentication was never part of the original system design.

### Real-World Parallel
**Triton/TRISIS (2017)** — Attackers gained initial access to the safety instrumented system (SIS) network through compromised IT credentials, then moved laterally to reach the Triconex safety controllers.

### Detection Logic
Wazuh's built-in rule 5712 detects SSH brute force after 8 failed attempts in 120 seconds. Our custom rule 100110 escalates this to level 12 because SSH access to OT systems is a critical initial access vector that demands immediate investigation.

---

## Phase 3: Web Application Exploitation

### Attacker Goal
Compromise the HMI (Human-Machine Interface) web application to gain control over the PLC programming interface.

### Techniques Used

**SQL Injection (T0866)**
```
/login?username=admin%027+OR+1=1--&password=x
/hardware?id=1+union+select+*+from+users--
```

OpenPLC's web interface allows PLC programming, hardware configuration, and runtime control. SQL injection against the login page could bypass authentication, while injection against hardware endpoints could extract the full user database.

**Cross-Site Scripting (T0866)**
```
/dashboard?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E
/programs?q=SRC=javascript:alert(1)
```

XSS against the HMI dashboard could steal session cookies from operators, hijack their authenticated sessions, or inject false process data into the HMI display — causing operators to take incorrect manual actions.

### Real-World Parallel
**Oldsmar Water Treatment (2021)** — An attacker accessed the water treatment plant's HMI (TeamViewer) and changed the sodium hydroxide levels to dangerous concentrations. Web-based HMIs are increasingly common attack surfaces in OT environments.

### Why HMI Attacks Matter
In traditional IT security, XSS steals cookies. In OT environments, a compromised HMI can:
- Display false readings to operators (hiding an attack in progress)
- Send unauthorized commands to PLCs
- Disable safety alarms
- Modify PLC programs (the most dangerous outcome)

---

## Phase 4: OT Process Manipulation

### Attacker Goal
Directly modify PLC memory to change physical process behavior — the primary objective of an ICS attack.

### Techniques Used

**Unauthorized Modbus Writes (T0883)**
```
FC 0x05: Write Single Coil    — toggle emergency stop bypass
FC 0x06: Write Single Register — override process setpoint
FC 0x0F: Write Multiple Coils  — disable all safety interlocks
FC 0x10: Write Multiple Regs   — set pressure to dangerous level
```

Each write function code targets a different aspect of the physical process:
- **Coils** control digital outputs (relays, switches, valves)
- **Registers** hold analog values (setpoints, thresholds, PID parameters)
- **Multiple writes** allow batch modification of entire control logic sections

### Real-World Parallel
**Stuxnet (2010)** — Modified centrifuge speed setpoints via unauthorized writes to Siemens S7-315/417 PLCs, causing physical destruction while reporting normal values to operators.

### Why This Is the Most Dangerous Phase
Unlike IT attacks where data is the target, OT attacks target **physical processes**. A single unauthorized Modbus write can:
- Open a valve that should be closed (flooding, chemical release)
- Disable a safety interlock (removing the last line of defense)
- Change a setpoint beyond safe operating limits (overpressure, overtemperature)
- Override manual controls (operators lose ability to intervene)

### Detection Response
Rule 100101 triggers the automated `firewall-drop` active response, blocking the source IP within seconds. This is the only phase where automated containment is enabled — because the risk of allowing continued unauthorized writes outweighs the risk of a false positive block.

---

## Phase 5: Persistence

### Attacker Goal
Maintain access to compromised systems and survive reboots or security sweeps.

### Techniques Used

**Configuration Tampering (T0831)**
```
echo 'nameserver 10.0.100.50' >> /etc/resolv.conf   — DNS hijacking
echo '10.0.100.50 scada-update-server' >> /etc/hosts — fake update server
```

By modifying DNS resolution, the attacker can:
- Redirect firmware update checks to a malicious server
- Intercept and modify communications between OT components
- Maintain C2 (command and control) access through DNS tunneling

### Real-World Parallel
**BlackEnergy (2015)** — Attackers maintained persistence in Ukraine's power grid for 6+ months using modified system configurations and scheduled tasks before executing the attack on December 23, 2015.

### Detection Logic
Wazuh's File Integrity Monitoring (FIM) detects changes to monitored system files (`/etc/resolv.conf`, `/etc/hosts`). Rules 550/554 fire when file checksums change, alerting SOC analysts to unauthorized modifications.

---

## Phase 6: Impact — Denial of Control

### Attacker Goal
Prevent operators from controlling the physical process — the ultimate impact in an ICS attack.

### Techniques Used

**Modbus Write Flooding (T0813)**
```
10 rapid FC 0x06 writes in <2 seconds
Register 1 = 0xFFFF (maximum value) on every write
```

By flooding the PLC with rapid write commands, the attacker:
1. Continuously overrides any operator corrections
2. Saturates the Modbus communication channel
3. Potentially crashes the PLC firmware (some PLCs can't handle rapid writes)
4. Denies control — operators can write values, but the attacker immediately overwrites them

### Real-World Parallel
**Industroyer (2016)** — Sent rapid IEC 104 commands to circuit breakers, opening them faster than operators could reclose them. The attack was designed to deny control, not just cause a one-time outage.

### Detection Logic
Rule 100103 uses frequency-based correlation: when 6+ Modbus write events (rule 100101) occur within 30 seconds, it escalates to level 12. This distinguishes between a single unauthorized write (concerning but manageable) and a flooding attack (critical — the attacker is actively denying control).

---

## Attack Surface Summary

| Attack Surface | Protocol | Authentication | Encryption | Risk |
|---------------|----------|---------------|------------|------|
| Modbus/TCP | TCP/502 | None | None | Critical |
| OpenPLC HMI | HTTP/8080 | Basic (web form) | None | High |
| SSH | TCP/22 | Password | Yes (transport) | Medium |
| System configs | Local filesystem | OS permissions | N/A | Medium |

## What This Lab Doesn't Simulate

For completeness, here are attack vectors that exist in real OT environments but are outside this lab's scope:

- **Supply chain attacks** (compromised PLC firmware updates)
- **Physical access attacks** (serial console, USB, removable media)
- **Wireless attacks** (rogue access points on OT networks)
- **Safety system attacks** (SIS manipulation like Triton)
- **Man-in-the-middle** (ARP spoofing on the OT network to modify Modbus in transit)
- **Protocol-specific DoS** (malformed Modbus packets that crash PLC firmware)
