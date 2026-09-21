# Netwatch

Telegram bot that watches your home network and alerts you when a new device appears.
It scans the local subnet with `arp-scan`, keeps a small JSON database of known
devices, and can fingerprint a device (OS guess, open ports, service versions) with `nmap`.

## Features

- New-device alerts (IP, MAC, vendor, private/random MAC flag)
- Device list with online/offline state and custom names
- On-demand fingerprinting: OS guess, open ports, service versions, risky-port hints
- Quick port scan
- Only answers to the owner's Telegram chat; only scans private IP ranges

## Requirements

- Linux on the same L2 network as the devices (a VM must use bridged networking)
- `arp-scan`, `nmap`, Python 3.10+
- A Telegram bot token (from @BotFather) and your chat ID

## Setup

    sudo apt install -y arp-scan nmap python3-venv
    python3 -m venv venv
    venv/bin/pip install -r requirements.txt
    cp env.example env        # then edit it
    set -a; . ./env; set +a
    sudo -E venv/bin/python bot.py

Find your interface name with `ip -br a`. To run it as a service, adapt
`netwatch.service` (paths, `/etc/netwatch.env`) and use `systemctl enable --now netwatch`.

## Commands

    /scan                  scan now
    /list                  all devices, online/offline
    /info <ip|mac>         OS, open ports, versions
    /portscan <ip>         quick port scan
    /trust <mac> <name>    name a device
    /untrust <mac>         forget a device
    /help

## Notes and limitations

- The first scan stores every device found as the baseline (no alerts).
- Detection is MAC-based: a spoofed MAC of a known device will not be flagged.
- Phones with random MACs may show up as new devices per network.
- Sleeping phones can miss ARP probes, so scans use a slow packet interval (`-i 30`);
  one scan takes roughly 25-30 seconds.
- OS detection (`nmap -O`) needs root and often fails on phones (no open ports).

## Disclaimer

Use only on networks you own or are authorized to test.
