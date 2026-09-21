#!/usr/bin/env python3
import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from asyncio.subprocess import PIPE
from pathlib import Path

from telegram import BotCommand, Update
from telegram.ext import Application, CommandHandler, ContextTypes, filters

TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
IFACE = os.environ.get("IFACE", "eth0")
INTERVAL = int(os.environ.get("SCAN_INTERVAL", "60"))
OUI_FILE = os.environ.get("OUI_FILE", "/usr/share/arp-scan/ieee-oui.txt")
DB_PATH = Path(os.environ.get("DB_PATH", "/var/lib/netwatch/known_devices.json"))

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1900: "UPnP", 3389: "RDP", 5900: "VNC"}

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO
)
log = logging.getLogger("netwatch")

db_lock = asyncio.Lock()
ONLINE: dict[str, str] = {} 


async def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=PIPE, stderr=PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def is_random_mac(mac: str) -> bool:
    """Locally administered bit set = private/random MAC (typical for phones)."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def short_vendor(mac: str, vendor: str) -> str:
    if is_random_mac(mac):
        return "Private MAC"
    v = re.sub(
        r"[, ]+(?:Corporation|Corporate|Limited|Ltd|Co|Inc)\b.*$",
        "", vendor, flags=re.I,
    )
    return (v or "Unknown")[:30]


def load_db() -> dict:
    try:
        return json.loads(DB_PATH.read_text())
    except FileNotFoundError:
        return {}


def save_db(db: dict) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = DB_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2, ensure_ascii=False))
    tmp.replace(DB_PATH)


def norm_mac(s: str) -> str | None:
    s = s.lower().replace("-", ":")
    return s if MAC_RE.match(s) else None


async def arp_scan() -> dict[str, tuple[str, str]]:
    rc, out, err = await run(
        [
            "arp-scan", "--localnet", "--interface", IFACE,
            f"--ouifile={OUI_FILE}", "--plain", "-i", "30",
            "--retry=3", "--timeout=800",
        ],
        90,
    )
    if rc != 0:
        raise RuntimeError(err.strip() or f"arp-scan error (code {rc})")
    found: dict[str, tuple[str, str]] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            mac = parts[1].strip().lower()
            if MAC_RE.match(mac):
                vendor = parts[2].strip() if len(parts) > 2 else ""
                found[mac] = (parts[0].strip(), vendor)
    return found


async def scan_and_notify(bot) -> dict[str, tuple[str, str]]:
    found = await arp_scan()
    now = int(time.time())
    new: list[str] = []
    async with db_lock:
        db = load_db()
        baseline = not db
        for mac, (ip, vendor) in found.items():
            if mac not in db:
                db[mac] = {"name": None, "first_seen": now}
                if not baseline:
                    new.append(mac)
            db[mac].update(ip=ip, vendor=vendor, last_seen=now)
        save_db(db)
    ONLINE.clear()
    ONLINE.update({m: v[0] for m, v in found.items()})

    if baseline and found:
        await bot.send_message(
            CHAT_ID,
            f"First scan: {len(found)} devices added to the baseline (no alerts).\n"
            "Use /list to see them and /trust <mac> <name> to label them.",
        )
    for mac in new:
        ip, vendor = found[mac]
        lines = [
            "New device detected",
            f"IP: {ip}",
            f"MAC: {mac}",
            f"Vendor: {short_vendor(mac, vendor)}",
        ]
        if is_random_mac(mac):
            lines.append("Note: private/random MAC (likely a phone)")
        lines += ["", f"Name it: /trust {mac} <name>"]
        await bot.send_message(CHAT_ID, "\n".join(lines))
    return found


async def scan_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        await scan_and_notify(context.bot)
    except Exception as e:
        log.error("Scan error: %s", e)


def build_info(ip: str, mac: str | None, d: dict | None, xml_text: str) -> str:
    d = d or {}
    host = ET.fromstring(xml_text).find("host")
    name = d.get("name") or "unnamed"
    lines = [f"Device: {ip} ({name})"]

    if mac:
        lines.append(f"MAC: {mac}")
        if is_random_mac(mac):
            lines.append("Vendor: Private MAC (likely phone/tablet)")
        else:
            lines.append(f"Vendor: {short_vendor(mac, d.get('vendor', ''))}")

    ports: list[str] = []
    flagged: list[str] = []
    if host is not None:
        hn = host.find("hostnames/hostname")
        if hn is not None and hn.get("name"):
            lines.append(f"Hostname: {hn.get('name')}")
        times = host.find("times")
        if times is not None and times.get("srtt"):
            lines.append(f"Latency: {int(times.get('srtt')) / 1000:.1f} ms")

        matches = host.findall("os/osmatch")
        if matches and int(matches[0].get("accuracy", "0")) >= 95:
            lines.append(f"OS: {matches[0].get('name')} ({matches[0].get('accuracy')}%)")
        else:
            lines.append("OS: unknown (no reliable match)")
        banner_os = sorted(
            {x.get("ostype") for x in host.findall("ports/port/service") if x.get("ostype")}
        )
        if banner_os:
            lines.append(f"OS hint: {', '.join(banner_os)} (from service banners)")

        for prt in host.findall("ports/port"):
            st = prt.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = prt.find("service")
            svc = sv.get("name", "?") if sv is not None else "?"
            ver = ""
            if sv is not None:
                ver = " ".join(x for x in (sv.get("product"), sv.get("version")) if x)
                if not ver:
                    ver = sv.get("extrainfo", "")
            num = int(prt.get("portid"))
            entry = f"{num}/{prt.get('protocol')} - {svc}"
            if ver:
                entry += f" - {ver[:40]}"
            ports.append(entry)
            if prt.get("protocol") == "tcp" and num in RISKY_PORTS:
                flagged.append(f"{RISKY_PORTS[num]} ({num})")

    lines.append("")
    if ports:
        lines.append(f"Open ports ({len(ports)}):")
        lines += ports
        if flagged:
            lines += ["", "Worth checking: " + ", ".join(flagged)]
    else:
        lines.append("No open TCP ports found (top 200).")
        lines.append("This is normal for phones and firewalled PCs.")
        lines.append("OS detection needs at least one open port.")
    return "\n".join(lines)


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Scanning...")
    try:
        found = await scan_and_notify(context.bot)
    except Exception as e:  # noqa: BLE001
        await update.message.reply_text(f"Error: {e}")
        return
    await update.message.reply_text(f"Done: {len(found)} devices online.")


async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with db_lock:
        db = load_db()
    if not db:
        await update.message.reply_text("Database is empty. Run /scan.")
        return

    def key(item):
        try:
            return int(ipaddress.ip_address(item[1].get("ip", "0.0.0.0")))
        except ValueError:
            return 0

    def fmt(mac: str, d: dict) -> str:
        return (
            f"{d.get('ip', '-')} - {d.get('name') or 'unnamed'}\n"
            f"MAC: {mac}\n"
            f"Vendor: {short_vendor(mac, d.get('vendor', ''))}"
        )

    on, off = [], []
    for mac, d in sorted(db.items(), key=key):
        (on if mac in ONLINE else off).append(fmt(mac, d))

    parts = [f"Online ({len(on)})"] + on
    if off:
        parts += [f"Offline ({len(off)})"] + off
    await update.message.reply_text("\n\n".join(parts)[:4000])


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /info <ip|mac>")
        return
    target = context.args[0]
    mac = norm_mac(target)
    d = None
    async with db_lock:
        db = load_db()
    if mac:
        d = db.get(mac)
        if not d or not d.get("ip"):
            await update.message.reply_text("Unknown MAC.")
            return
        target = d["ip"]
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        await update.message.reply_text("Invalid IP or MAC.")
        return
    if not ip.is_private:
        await update.message.reply_text("Only local (private) IPs can be scanned.")
        return
    if not mac:
        for m, dd in db.items():
            if dd.get("ip") == str(ip):
                mac, d = m, dd
                break
    await update.message.reply_text(f"Fingerprinting {ip} (1-3 min)...")
    try:
        rc, out, err = await run(
            ["nmap", "-Pn", "-O", "-sV", "--version-light", "--osscan-guess",
             "--top-ports", "200", "--open", "-T4", "-oX", "-", str(ip)],
            300,
        )
    except asyncio.TimeoutError:
        await update.message.reply_text("Timed out.")
        return
    try:
        text = build_info(str(ip), mac, d, out)
    except ET.ParseError:
        await update.message.reply_text(f"nmap error: {(err or out)[:500]}")
        return
    await update.message.reply_text(text)


async def cmd_portscan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /portscan <ip>")
        return
    try:
        ip = ipaddress.ip_address(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid IP.")
        return
    if not ip.is_private:
        await update.message.reply_text("Only local (private) IPs can be scanned.")
        return
    await update.message.reply_text(f"Scanning ports on {ip}...")
    try:
        rc, out, err = await run(["nmap", "-F", "-T4", "--open", str(ip)], 180)
    except asyncio.TimeoutError:
        await update.message.reply_text("Timed out.")
        return
    await update.message.reply_text((out or err)[:3800])


async def cmd_trust(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2 or not (mac := norm_mac(context.args[0])):
        await update.message.reply_text("Usage: /trust <mac> <name>")
        return
    name = " ".join(context.args[1:])[:40]
    async with db_lock:
        db = load_db()
        if mac not in db:
            await update.message.reply_text("This MAC is not in the database.")
            return
        db[mac]["name"] = name
        save_db(db)
    await update.message.reply_text(f"Saved: {mac} is now '{name}'.")


async def cmd_untrust(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not (mac := norm_mac(context.args[0])):
        await update.message.reply_text("Usage: /untrust <mac>")
        return
    async with db_lock:
        db = load_db()
        if db.pop(mac, None) is None:
            await update.message.reply_text("This MAC is not in the database.")
            return
        save_db(db)
    await update.message.reply_text(
        f"Removed {mac}. If it is still on the network, "
        "you will get a new-device alert on the next scan."
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Netwatch - home network monitor\n"
        f"Scans the network every {INTERVAL} seconds and alerts you about new devices.\n"
        "\n"
        "Commands:\n"
        "/scan - scan the network now\n"
        "/list - show all devices\n"
        "/info <ip|mac> - OS, open ports and versions\n"
        "/portscan <ip> - quick port scan\n"
        "/trust <mac> <name> - name a device\n"
        "/untrust <mac> - forget a device\n"
        "/help - show this message"
    )


async def set_commands(app: Application) -> None:
    await app.bot.set_my_commands([
        BotCommand("scan", "Scan the network now"),
        BotCommand("list", "Show all devices"),
        BotCommand("info", "OS and open ports of a device"),
        BotCommand("portscan", "Quick port scan"),
        BotCommand("trust", "Name a device"),
        BotCommand("untrust", "Forget a device"),
        BotCommand("help", "Show help"),
    ])


def main() -> None:
    app = Application.builder().token(TOKEN).post_init(set_commands).build()
    only_me = filters.Chat(chat_id=CHAT_ID)
    for name, fn in [
        ("start", cmd_help),
        ("help", cmd_help),
        ("scan", cmd_scan),
        ("list", cmd_list),
        ("info", cmd_info),
        ("portscan", cmd_portscan),
        ("trust", cmd_trust),
        ("untrust", cmd_untrust),
    ]:
        app.add_handler(CommandHandler(name, fn, filters=only_me))
    app.job_queue.run_repeating(scan_job, interval=INTERVAL, first=5)
    app.run_polling()


if __name__ == "__main__":
    main()
