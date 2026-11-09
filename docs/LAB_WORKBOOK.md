# Project 2 Lab Workbook: Network Traffic & Intrusion Detection (NIDS)

**Author:** leviathan  
**Environment:** Fedora Workstation 44 (Host) | Ubuntu Server 26.04 (Sensor) | QEMU/KVM  
**Last Updated:** November 2026  

---

## 1. Lab Architecture & Topology

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        FEDORA WORKSTATION 44 (HOST)                    │
│   Hypervisor: QEMU/KVM managed via libvirt / virt-manager              │
│   Traffic Engine: tcpreplay, wireshark, tshark, nftables               │
│                                                                        │
│   ┌───────────────────────────┐     ┌──────────────────────────────┐   │
│   │   virbr0 (NAT / default)  │     │   virbr1 (soc-bridge / TAP)  │   │
│   │   Subnet: 192.168.122.0/24│     │   Subnet: 192.168.100.0/24   │   │
│   │   [Management & Internet] │     │   [Sterile Sniffing Wire]    │   │
│   └─────────────┬─────────────┘     └──────────────┬───────────────┘   │
└─────────────────┼──────────────────────────────────┼───────────────────┘
                  │                                  │
                  │ vnet0 (DHCP)                     │ vnet1 (No IP / Promisc)
                  ▼                                  ▼
┌─────────────────┴──────────────────────────────────┴───────────────────┐
│                    UBUNTU SERVER 26.04 SENSOR VM                       │
│                         Hostname: leviathan@levi                       │
│                                                                        │
│   enp1s0: 192.168.122.130 (SSH & Updates)                              │
│   enp7s0: Passive Tap (Promiscuous, GRO/LRO/TSO Off, AF-PACKET)        │
│                                                                        │
│   ┌───────────────────────────┐     ┌──────────────────────────────┐   │
│   │  Suricata NIDS 8.0.8      │     │  Zeek NSM 9.0.1              │   │
│   │  - AF-PACKET zero-copy    │     │  - Protocol Parsing Engine   │   │
│   │  - local.rules (6 vectors)│     │  - conn/http/dns/ssl logs    │   │
│   │  - fast.log / eve.json    │     │  - zeek-cut / jq analytics   │   │
│   └───────────────────────────┘     └──────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Chronological Implementation Log

### Phase 1: Virtual Bridge & VM Plumbing
1. **Isolated Bridge Creation:**
   - Created `soc-bridge` (`virbr1`) inside Virt-Manager with isolated forwarding (no outbound NAT), subnet `192.168.100.0/24`.
   - *Evidence:* `screenshots/01_soc_bridge_isolated_network.png`
2. **Sensor VM Provisioning:**
   - Deployed Ubuntu Server 26.04 live server image inside QEMU/KVM.
   - Handled `osinfo-db` ISO detection mismatch by manually setting profile to Ubuntu LTS.
   - *Evidence:* `screenshots/02_virt_manager_os_select.png`, `screenshots/03_virt_manager_os_detect_error.png`, `screenshots/04_ubuntu_server_initial_login.png`
3. **Dual-NIC Configuration:**
   - Added second virtual network adapter bound to `soc-bridge` with VirtIO model.
   - Interfaces identified: `enp1s0` (NAT) and `enp7s0` (Isolated Tap).
   - *Evidence:* `screenshots/05_virt_manager_vm_list.png`, `screenshots/06_dual_nics_detected_ip_link.png`
4. **Stealth Sniffing Interface Setup (`enp7s0`):**
   - Configured `/etc/netplan/00-installer-config.yaml` to ensure `enp7s0` has `dhcp4: false`, `dhcp6: false`, and flushed any stray DHCP leases to make the sensor invisible on the wire.
   - Enabled promiscuous mode: `sudo ip link set dev enp7s0 up promisc on`.
   - *Evidence:* `screenshots/07_netplan_initial_installer_config.png`, `screenshots/08_ssh_connected_promisc_mode_up.png`

---

### Incident Diagnosis: Docker & Nftables Forwarding Collision
- **Symptom:** The VM suffered 100% packet loss (`ping 8.8.8.8` timed out), preventing package installation.
- **Root Cause:** Docker's daemon injected an nftables `policy drop` on the host's `FORWARD` filter hook. Packets exiting `virbr0` were dropped before reaching the NAT postrouting chain.
- **Resolution:**
  ```bash
  sudo nft insert rule ip filter DOCKER-USER iifname "virbr0" accept
  sudo nft insert rule ip filter DOCKER-USER oifname "virbr0" accept
  ```
  Persisted via systemd service `docker-libvirt-fix.service`.
- *Evidence:* `screenshots/09_vm_ping_100_percent_loss.png` through `screenshots/14_vm_cold_boot_enp1s0_ip_restored.png`. Full case study documented in `docs/DOCKER_FIREWALL_CASE_STUDY.md`.

---

### Phase 2: Sensor Hardening & Engine Deployment
1. **Disabling NIC Offloading:**
   - Disabled Generic Receive Offload (GRO), Large Receive Offload (LRO), TCP Segmentation Offload (TSO) on `enp7s0` to preserve packet header fidelity for signature inspection.
   - Deployed persistent systemd unit `nids-nic-tune.service`.
2. **Suricata 8.0.8 Deployment:**
   - Installed via official OISF stable PPA.
   - Configured `HOME_NET: "[192.168.100.0/24]"` and `af-packet` listener on `enp7s0`.
   - Debugged `/etc/suricata/suricata.yaml` rule file paths and YAML indentation.
   - Verified configuration syntax: `sudo suricata -T -c /etc/suricata/suricata.yaml -v`.
   - *Evidence:* `screenshots/15_suricata_syntax_rule_file_warning.png` through `screenshots/19_suricata_test_1_rule_success.png`.
3. **Zeek 9.0.1 Deployment:**
   - Integrated OpenSUSE Build Service (`security:zeek`) repository for Ubuntu 24.04/26.04.
   - Bound Zeek listening interface to `enp7s0` in `/opt/zeek/etc/node.cfg` and declared local network in `networks.cfg`.
   - Added `/opt/zeek/bin` to global environment `$PATH`.
   - *Evidence:* `screenshots/20_zeek_apt_package_not_found.png`, `screenshots/21_zeek_9_installed_configured_enp7s0.png`.

---

### Phase 3: Custom Signature Engineering (In Progress)
Rules authored inside `/etc/suricata/rules/local.rules`:

| SID | Attack Vector | MITRE ATT&CK | Key Keywords Used | Status |
|---|---|---|---|---|
| **1000001** | Nmap SYN Stealth Port Scan | T1046 | `flags:S,12`, `flow:stateless`, `detection_filter` | Verified |
| **1000002** | Obfuscated Base64 User-Agent C2 | T1071.001 | `http.user_agent`, `pcre:"/^[A-Za-z0-9+/]{30,}={0,2}$/"` | Verified |
| **1000003** | Unauthorized SSH Tunnel | T1572 | `![22]`, `content:"SSH-2.0-"`, `depth:8`, `flow:to_server` | Drafted |
| **1000004** | Cobalt Strike/Sliver HTTP Beacon | T1071.001 | `http.method:GET`, `http.uri`, PCRE stager regex | Drafted |
| **1000005** | Cobalt Strike Default Rogue TLS Cert | T1587.003 | `tls.cert_serial:"08:bb:00:ee"` | Drafted |
| **1000006** | High-Entropy DNS Tunneling / Exfil | T1048.003 | `dns.query`, PCRE subdomain length >35 chars | Drafted |

---

## 3. What Needs to be Done (Upcoming Phases)

### Phase 3 Completion:
- [ ] Append Rules 3, 4, 5, 6 to `/etc/suricata/rules/local.rules` in VM.
- [ ] Run syntax test (`suricata -T`) to verify all 6 rules load with 0 failures.

### Phase 4: Live Traffic Replay & Forensics:
- [ ] Start Suricata live daemon on `enp7s0` (`sudo suricata -c /etc/suricata/suricata.yaml --af-packet=enp7s0 -D`).
- [ ] Start Zeek live capture on `enp7s0` (`sudo zeek -i enp7s0 local`).
- [ ] Replay malicious PCAPs from Fedora host across `soc-bridge` (`virbr1`) using `sudo tcpreplay -i virbr1 <sample.pcap>`.
- [ ] Observe and correlate alerts in `/var/log/suricata/fast.log` and `eve.json`.
- [ ] Investigate session metadata in Zeek (`conn.log`, `dns.log`, `http.log`, `ssl.log`) using `zeek-cut` and `jq`.
- [ ] Wireshark / tshark deep packet inspection: payload carving and certificate extraction.

### Phase 5: Verification & Telemetry Packaging:
- [ ] Finalize telemetry extraction across all attack vectors.
- [ ] Export structured alert metrics and Zeek session graphs.
