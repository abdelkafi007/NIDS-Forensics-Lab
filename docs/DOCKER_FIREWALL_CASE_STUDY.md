# Technical Case Study: Resolving the Docker vs. Libvirt Host Routing Collision

**Author:** leviathan  
**Environment:** Fedora Workstation 44 (Host) | QEMU/KVM (`libvirt`) | Docker Engine | Ubuntu Server 26.04 VM  
**Topic:** Linux Kernel Forwarding, Nftables Hook Architecture, Inter-Zone Masquerading  

---

## 1. Executive Summary
During the deployment of an Ubuntu Server NIDS sensor inside QEMU/KVM, the sensor VM experienced total internet egress failure (100% packet loss to `8.8.8.8` and timeouts to `archive.ubuntu.com`), despite the virtual bridge (`virbr0`) assigning valid DHCP leases and local ICMP communication between host and guest functioning normally.

Forensic network diagnosis revealed a multi-layered firewall collision between **Fedora's firewalld 2.x nftables architecture** and **Docker Engine's automated iptables/nftables chains**.

---

## 2. Root Cause Analysis

### Layer 1: Firewalld Inter-Zone Forwarding Default Drop
- In Fedora 40+, `firewalld` separates physical interfaces (`eno1`, `wlo1` in `FedoraWorkstation` zone) from virtual bridges (`virbr0`, `virbr1` in `libvirt` zone).
- Even when `net.ipv4.ip_forward = 1` is enabled at the kernel level, firewalld drops traffic crossing between zones unless an explicit forwarding policy connects the ingress zone to the egress zone.
- Furthermore, outbound NAT (`masquerade`) was disabled on the host egress interface.

### Layer 2: Docker FORWARD Chain `policy drop` (The Decisive Bottleneck)
When Docker starts, it modifies the Linux kernel `filter` table:
```text
table ip filter {
    chain FORWARD {
        type filter hook forward priority filter; policy drop;
        jump DOCKER-USER
        jump DOCKER-FORWARD
    }
}
```
- The base `FORWARD` chain has a default policy of **`drop`**.
- Packets leaving `virbr0` (192.168.122.130) destined for WAN (`8.8.8.8`) traversed the forward hook.
- Because these packets did not originate from a Docker container, they fell through `DOCKER-FORWARD` and were dropped silently by the default `drop` verdict **before ever reaching the postrouting NAT hook**.

---

## 3. Remediation & Hardening

### Step 1: Firewalld Inter-Zone Forwarding & Masquerade Policy
```bash
sudo firewall-cmd --permanent --new-policy libvirt-to-wan
sudo firewall-cmd --permanent --policy libvirt-to-wan --add-ingress-zone libvirt
sudo firewall-cmd --permanent --policy libvirt-to-wan --add-egress-zone ANY
sudo firewall-cmd --permanent --policy libvirt-to-wan --add-masquerade
sudo firewall-cmd --permanent --policy libvirt-to-wan --set-target ACCEPT
sudo firewall-cmd --reload
```

### Step 2: Bypassing Docker's Drop Filter via `DOCKER-USER`
Docker provides the `DOCKER-USER` chain specifically to allow administrators to insert pre-routing filtering rules that take precedence before Docker's internal container rules:
```bash
sudo nft insert rule ip filter DOCKER-USER iifname "virbr0" accept
sudo nft insert rule ip filter DOCKER-USER oifname "virbr0" accept
```

### Step 3: Production Persistence Unit
To guarantee this exception survives host reboots and Docker restarts, a systemd unit was deployed:
`/etc/systemd/system/docker-libvirt-fix.service`:
```ini
[Unit]
Description=Allow libvirt VM traffic through Docker FORWARD chain
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft insert rule ip filter DOCKER-USER iifname "virbr0" accept
ExecStart=/usr/sbin/nft insert rule ip filter DOCKER-USER oifname "virbr0" accept
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

---

## 4. Key Engineering Takeaways
- Docker and Libvirt/KVM running on the same Linux host frequently fight over `iptables`/`nftables` rulesets.
- When troubleshooting VM connectivity, always check:
  1. Layer 2 bridge membership (`bridge link show`)
  2. Layer 3 routing (`ip route`)
  3. Kernel forwarding (`sysctl net.ipv4.ip_forward`)
  4. Firewall filter hooks (`nft list ruleset | grep FORWARD`)
  5. NAT translation (`nft list table ip nat`)
