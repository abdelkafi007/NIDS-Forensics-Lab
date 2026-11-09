# Production Network Intrusion Detection (NIDS) & Network Forensics Lab

[![Suricata](https://img.shields.io/badge/Suricata-8.0.8%20(AF--PACKET)-red.svg)](https://suricata.io/)
[![Zeek](https://img.shields.io/badge/Zeek-9.0.1%20(NSM)-blue.svg)](https://zeek.org/)
[![Hypervisor](https://img.shields.io/badge/QEMU%2FKVM-libvirt-orange.svg)](https://www.linux-kvm.org/)
[![Host](https://img.shields.io/badge/Host-Fedora%20Workstation%2044-navy.svg)](https://fedoraproject.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1046%20%7C%20T1071%20%7C%20T1572%20%7C%20T1587%20%7C%20T1048-purple.svg)](https://attack.mitre.org/)

A production-grade Blue Team network security monitoring environment built to intercept, detect, and forensically analyze advanced cyber attack vectors in real time. Deployed across a dual-homed virtualization architecture using hardware-tuned Linux virtual switching, zero-copy packet rings, custom Suricata signatures, and deep protocol-aware Zeek telemetry.

---

## 📑 Core Documentation & Reference Guides

- 📘 **[Project 2: Complete Attack Vectors & OWASP/MITRE Reference Guide](Project2NIDSAttacksandOWASPGuide%20(1).pdf)** ([docs copy](docs/Project2_NIDS_Attacks_and_OWASP_Guide.pdf)): Comprehensive breakdown of the 6 attack vectors, MITRE ATT&CK vs. OWASP Top 10 mappings, Suricata signature mechanics, Zeek telemetry fields, and Wireshark forensic filters.
- 📓 **[Lab Implementation Workbook](docs/LAB_WORKBOOK.md)**: Chronological step-by-step engineering journal detailing hypervisor plumbing, dual-NIC setup, sensor hardening, rule authoring, and upcoming traffic replay phases.
- 🔍 **[Technical Case Study: Docker vs. Libvirt Firewall Collision](docs/DOCKER_FIREWALL_CASE_STUDY.md)**: Deep dive into diagnosing and resolving the host nftables `FORWARD drop` collision caused by Docker Engine on Fedora Workstation.

---

## 🏗️ Architecture & Network Topology

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        FEDORA WORKSTATION 44 (HOST)                    │
│   Hardware: AMD Ryzen 7 | 32 GB RAM | NVIDIA RTX 5060                  │
│   Hypervisor: QEMU/KVM managed via libvirt / virt-manager             │
│   Injection Engine: tcpreplay, wireshark, tshark, nftables             │
│                                                                        │
│   ┌───────────────────────────┐     ┌──────────────────────────────┐   │
│   │   virbr0 (NAT / default)  │     │   virbr1 (soc-bridge / TAP)  │   │
│   │   Subnet: 192.168.122.0/24│     │   Subnet: 192.168.100.0/24   │   │
│   │   [Management & Egress]   │     │   [Sterile Sniffing Wire]    │   │
│   └─────────────┬─────────────┘     └──────────────┬───────────────┘   │
└─────────────────┼──────────────────────────────────┼───────────────────┘
                  │                                  │
                  │ vnet0 (DHCP)                     │ vnet1 (No IP / Promisc)
                  ▼                                  ▼
┌─────────────────┴──────────────────────────────────┴───────────────────┐
│                    UBUNTU SERVER 26.04 SENSOR VM                       │
│                         Hostname: leviathan@levi                       │
│                                                                        │
│   enp1s0: 192.168.122.130 (SSH management, package repository updates) │
│   enp7s0: Passive Tap (Promiscuous mode, Hardware Offloads OFF)         │
│                                                                        │
│   ┌───────────────────────────┐     ┌──────────────────────────────┐   │
│   │   Suricata NIDS 8.0.8     │     │   Zeek NSM 9.0.1             │   │
│   │   - AF-PACKET ring buffer │     │   - Protocol state engine    │   │
│   │   - 6 Custom Threat Rules │     │   - conn, http, dns, ssl logs│   │
│   │   - fast.log / eve.json   │     │   - zeek-cut / jq analytics  │   │
│   └───────────────────────────┘     └──────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Threat Detection Coverage Matrix

| # | Attack Vector | MITRE ATT&CK | OWASP 2025 | Suricata Signature Mechanics | Zeek Forensic Artifact |
|---|---|---|---|---|---|
| **1** | **Half-Open TCP SYN Scan** | `T1046` | A02 | `flags:S,12; flow:stateless; detection_filter:track by_src, count 20, seconds 5` | `conn.log` (State: `S0`, `REJ`, high `id.orig_h` rate) |
| **2** | **Obfuscated Base64 User-Agent** | `T1071.001` | A05, A09 | `http.user_agent; pcre:"/^[A-Za-z0-9+/]{30,}={0,2}$/"` | `http.log` (`user_agent` field extraction) |
| **3** | **Unauthorized SSH Egress Tunnel** | `T1572`, `T1021.004` | A01 | `![22]; flow:established,to_server; content:"SSH-2.0-"; depth:8` | `conn.log` + `ssh.log` (Non-standard port analysis) |
| **4** | **Cobalt Strike / Sliver C2 Beacon** | `T1071.001`, `T1041` | A08 | `http.method:GET; http.uri; pcre:"/^\/(submit\.php\?id=\|activity\|[a-zA-Z0-9]{4})$/"` | `conn.log` (Jitter/interval analysis) + `http.log` |
| **5** | **Rogue / Self-Signed TLS Cert** | `T1587.003` | A04 | `tls.cert_serial; content:"08:bb:00:ee"` | `ssl.log` (`server_name`, `ja3`) + `x509.log` (`certificate.serial`) |
| **6** | **DNS Data Exfiltration Tunnel** | `T1048.003` | A02 | `dns.query; pcre:"/^[a-zA-Z0-9_-]{35,}\./"` | `dns.log` (High query entropy, query length >35) |

---

## ⚙️ Sensor Engineering & Performance Tuning

### 1. Hardware Offloading Elimination
Modern NICs use Generic Receive Offload (GRO) and Large Receive Offload (LRO) to merge packets into 64KB synthetic frames. This breaks packet-level signature inspection (TCP flags, packet sizes, fragment inspection).
```bash
sudo ethtool -K enp7s0 gro off lro off tso off gso off rx off tx off
```
Persisted at boot via systemd unit: [`scripts/nids-nic-tune.service`](scripts/nids-nic-tune.service).

### 2. Stealth Passive Sniffing Port
The sniffing interface (`enp7s0`) has **no IP address assigned** (`dhcp4: false`, `dhcp6: false`) and runs in **Promiscuous Mode** (`ip link set dev enp7s0 up promisc on`). It cannot be targeted, scanned, or pinged by an adversary on the wire.

### 3. AF-PACKET Zero-Copy Ring Buffers
Suricata is configured with Linux `af-packet` in `suricata.yaml` to read packets directly from the kernel memory ring buffer without user-space memory duplication, ensuring zero packet loss during high-throughput injection.

---

## 📁 Repository Structure

```text
Project-2-NIDS-Forensics-Lab/
├── README.md                                  # Master documentation & technical overview
├── Project2NIDSAttacksandOWASPGuide (1).pdf   # Complete Attack Vectors & OWASP/MITRE Reference Guide
├── docs/
│   ├── LAB_WORKBOOK.md                        # Full chronological step-by-step implementation journal
│   ├── DOCKER_FIREWALL_CASE_STUDY.md          # Deep dive into Docker/nftables forwarding conflict & resolution
│   ├── Project2_NIDS_Attacks_and_OWASP_Guide.pdf # Attack & OWASP Reference Guide (docs copy)
│   └── projects_roadmap.pdf                   # Master engineering roadmap (CI1 -> M2 Alternance)
├── rules/
│   └── local.rules                    # Custom Suricata detection rules with MITRE/OWASP mappings
├── scripts/
│   ├── nids-nic-tune.service          # Promiscuous mode & offload disablement service
│   └── docker-libvirt-fix.service     # Host-level Docker nftables exception service
├── screenshots/                       # 24 chronological, high-resolution evidence screenshots
│   ├── 01_soc_bridge_isolated_network.png
│   ├── 06_dual_nics_detected_ip_link.png
│   ├── 08_ssh_connected_promisc_mode_up.png
│   ├── 19_suricata_test_1_rule_success.png
│   ├── 21_zeek_9_installed_configured_enp7s0.png
│   └── 22_suricata_test_2_rules_success.png
├── pcaps/                             # Replay PCAP samples for Phase 4
└── zeek-logs/                         # Extracted Zeek forensic logs
```

---

## 💼 CV Highlights (Portfolio Packaging)

### Version Française (CV Ingénieur / Alternance SOC)
> - **Déploiement et réglage fin d’une sonde NIDS Suricata & Zeek (Ubuntu Server 26.04 sur KVM)** : configuration en mode passif/promiscuous sur pont virtuel isolé (`af-packet`), désactivation du hardware offloading (`gro`/`lro`/`tso`).
> - **Ingénierie de détection (Suricata)** : conception et validation de 6 signatures personnalisées (`local.rules`) pour contrer les scans furtifs Nmap SYN (filtrage par seuil), tunnels SSH non autorisés, C2 Cobalt Strike/Sliver, certificats TLS illégitimes et exfiltration DNS (regex PCRE).
> - **Analyse médico-légale et investigation de trafic (PCAP)** : rejeu de flux malveillants via `tcpreplay`, extraction et corrélation de métadonnées de sessions sous Zeek (`conn.log`, `dns.log`, `ssl.log`, `http.log`) et extraction de charges utiles sous Wireshark/tshark.

### English Version (SOC Analyst / Detection Engineer)
> - **Engineered an Enterprise NIDS & NSM Sensor (Suricata 8 + Zeek 9 on KVM)**: Deployed dual-homed virtual architecture with passive promiscuous sniffing on an isolated mirror bridge, hardened with zero NIC offloading and AF-PACKET ring buffers.
> - **Detection Engineering & Rule Authoring**: Crafted and tuned 6 custom Suricata signatures targeting Nmap stealth SYN scans (rate-filtered), obfuscated Base64 C2 headers, rogue SSH egress tunnels, Cobalt Strike/Sliver malleable profiles, default C2 TLS serials, and high-entropy DNS tunneling.
> - **Network Forensics & Telemetry Correlation**: Ingested and replayed attack PCAPs via `tcpreplay`; extracted artifacts and reconstructed encrypted/plaintext sessions using Zeek telemetry and Wireshark payload carving.
