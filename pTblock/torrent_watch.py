#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import requests
from dotenv import load_dotenv

LOG = logging.getLogger("torrent_watch")

BLOCK_MARKERS = ("blocked", ">> block", "[block")
DEFAULT_OUTPUT = "data/torrent-offenders.txt"
DEFAULT_LOG_DB = "data/ban_log.json"


@dataclass
class Settings:
    log_path: Path
    output_file: Path
    panel_scheme: str
    panel_host: str
    panel_port: int
    panel_base_path: str
    username: str
    password: str
    two_factor: Optional[str]
    webhook_url: Optional[str]
    webhook_token: Optional[str]
    ban_hours: int
    poll_interval: float
    log_file: Path
    wa_enabled: bool
    wa_api_key: Optional[str]
    wa_channel: Optional[str]
    validator_url: str
    tblock_token: Optional[str]
    vps_ip: Optional[str]

    @property
    def base_url(self) -> str:
        base = self.panel_base_path.rstrip("/")
        if not base.startswith("/"):
            base = f"/{base}"
        return f"{self.panel_scheme}://{self.panel_host}:{self.panel_port}{base}"

    @property
    def api_base(self) -> str:
        return f"{self.base_url}/panel/api"


def load_settings(env_path: Optional[Path] = None) -> Settings:
    if env_path:
        load_dotenv(env_path)
    else:
        load_dotenv()

    def must_get(key: str) -> str:
        val = os.getenv(key)
        if not val:
            raise RuntimeError(f"Missing required environment variable {key}")
        return val

    log_path = Path(os.getenv("XRAY_LOG_PATH", "/usr/local/x-ui/access.log"))
    output_file = Path(os.getenv("XRAY_OFFENDER_FILE", DEFAULT_OUTPUT))
    panel_scheme = os.getenv("XRAY_PANEL_SCHEME", "http")
    panel_host = must_get("XRAY_PANEL_HOST")
    panel_port = int(os.getenv("XRAY_PANEL_PORT", "2053"))
    panel_base = os.getenv("XRAY_PANEL_BASE", "/")
    username = must_get("XRAY_PANEL_USER")
    password = must_get("XRAY_PANEL_PASS")
    two_factor = os.getenv("XRAY_PANEL_2FA") or None
    webhook_url = os.getenv("TORRENT_WEBHOOK_URL") or None
    webhook_token = os.getenv("TORRENT_WEBHOOK_TOKEN") or None
    if not webhook_url:
        webhook_token = None
    ban_hours = int(os.getenv("TORRENT_BAN_HOURS", "5"))
    poll_interval = float(os.getenv("TORRENT_POLL_INTERVAL", "1.0"))
    log_file = Path(os.getenv("TORRENT_LOG_FILE", DEFAULT_LOG_DB))
    wa_enabled = os.getenv("WASENDER_ENABLED", "0") == "1" or os.getenv("WHATSAPP_INTEGRATION", "False").lower() == "true"
    wa_api_key = os.getenv("WASENDER_API_KEY") or None
    wa_channel = os.getenv("WASENDER_CHANNEL") or None
    validator_url = os.getenv("VALIDATOR_URL", "https://whale-app-sdmtd.ondigitalocean.app").rstrip("/")
    tblock_token = os.getenv("TBLOCK_TOKEN") or None
    vps_ip = os.getenv("VPS_IP") or None

    return Settings(
        log_path=log_path,
        output_file=output_file,
        panel_scheme=panel_scheme,
        panel_host=panel_host,
        panel_port=panel_port,
        panel_base_path=panel_base,
        username=username,
        password=password,
        two_factor=two_factor,
        webhook_url=webhook_url,
        webhook_token=webhook_token,
        ban_hours=ban_hours,
        poll_interval=poll_interval,
        log_file=log_file,
        wa_enabled=wa_enabled,
        wa_api_key=wa_api_key,
        wa_channel=wa_channel,
        validator_url=validator_url,
        tblock_token=tblock_token,
        vps_ip=vps_ip,
    )


class XuiClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = requests.Session()
        self.login()

    def login(self) -> None:
        payload: Dict[str, Any] = {
            "username": self.settings.username,
            "password": self.settings.password,
        }
        if self.settings.two_factor:
            payload["twoFactorCode"] = self.settings.two_factor
        url = f"{self.settings.base_url}/login/"
        LOG.info("Authenticating to 3x-ui panel at %s", url)
        resp = self.session.post(url, json=payload, timeout=15)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Failed to login to 3x-ui: {resp.status_code} {resp.text}"
            )

    def _request(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        url = f"{self.settings.api_base}{path}"
        resp = self.session.request(method, url, timeout=20, **kwargs)
        if resp.status_code == 401:
            LOG.warning("Session expired, re-authenticating")
            self.login()
            resp = self.session.request(method, url, timeout=20, **kwargs)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success", True):
            raise RuntimeError(data.get("msg", "Unknown 3x-ui API failure"))
        return data

    def get_client(self, email: str) -> Optional[Dict[str, Any]]:
        path = f"/inbounds/getClientTraffics/{requests.utils.quote(email)}"
        data = self._request("GET", path)
        obj = data.get("obj")
        if isinstance(obj, list):
            return obj[0] if obj else None
        return obj

    def get_inbound(self, inbound_id: int) -> Dict[str, Any]:
        path = f"/inbounds/get/{inbound_id}"
        data = self._request("GET", path)
        return data["obj"]

    def set_client_enabled(
        self,
        inbound_id: int,
        client_uuid: str,
        enable: bool,
    ) -> bool:
        inbound = self.get_inbound(inbound_id)
        settings_raw = inbound.get("settings")
        clients_blob = json.loads(settings_raw)
        clients = clients_blob.get("clients", [])
        updated = False
        payload_client: Optional[Dict[str, Any]] = None
        for client in clients:
            if client.get("id") == client_uuid:
                if client.get("enable", True) == enable:
                    return False
                client["enable"] = enable
                client["updated_at"] = int(time.time() * 1000)
                updated = True
                payload_client = client
                break
        if not updated:
            raise RuntimeError(f"Client {client_uuid} not found in inbound {inbound_id}")
        if payload_client is None:
            raise RuntimeError("Client payload missing after update")
        payload = {
            "id": inbound_id,
            "settings": json.dumps({"clients": [payload_client]}),
        }
        path = f"/inbounds/updateClient/{client_uuid}"
        self._request("POST", path, json=payload)
        return True


class BanLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries = self._load()

    def _load(self) -> list[Dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            content = json.loads(self.path.read_text())
            return content.get("bans", [])
        except Exception:
            LOG.exception("Failed to parse %s, starting fresh", self.path)
            return []

    def _persist(self) -> None:
        self.path.write_text(json.dumps({"bans": self.entries}, indent=2))

    def add(self, entry: Dict[str, Any]) -> None:
        self.entries.append(entry)
        self._persist()



class WebhookNotifier:
    def __init__(self, url: Optional[str], token: Optional[str]):
        self.url = url
        self.token = token

    def notify(self, payload: Dict[str, Any]) -> None:
        if not self.url:
            return
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Webhook-Token"] = self.token
        try:
            resp = requests.post(self.url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            LOG.info("Webhook notified for %s", payload.get("email"))
        except Exception as exc:
            LOG.error("Failed to notify webhook: %s", exc)


class WhatsAppNotifier:
    def __init__(self, enabled: bool, api_key: Optional[str], channel: Optional[str]):
        self.enabled = enabled and bool(api_key) and bool(channel)
        self.api_key = api_key
        self.channel = channel

    def send_ban(self, email: str, domain: str, hours: int) -> None:
        if not self.enabled:
            return
        payload = {
            "to": self.channel,
            "text": (
                f"🚫 *TBlock Alert*\n"
                f"• User: `{email}`\n"
                f"• Reason: torrenting\n"
                f"• Source: `{domain}`\n"
                f"• Action: banned for {hours} hours\n"
                f"• Service: dragonforce"
            )
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(
                "https://www.wasenderapi.com/api/send-message",
                headers=headers,
                json=payload,
                timeout=12,
            )
            data = resp.json()
            if resp.status_code == 200 and data.get("success"):
                LOG.info("WhatsApp notification sent for %s", email)
            else:
                LOG.warning("WhatsApp send failed: %s", data)
        except Exception as exc:
            LOG.error("Failed to send WhatsApp notification: %s", exc)


def follow_file(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                yield ""
            else:
                yield line


def parse_line(line: str) -> Tuple[Optional[str], Optional[str], str, Optional[str], bool]:
    parts = line.strip().split()
    if len(parts) < 6:
        return None, None, "", None, False
    timestamp = " ".join(parts[:2])
    ip_section = next((p for p in parts if p.startswith("from")), None)
    email_idx = next((i for i, p in enumerate(parts) if p == "email:"), None)
    ip = None
    if ip_section:
        idx = parts.index(ip_section)
        if idx + 1 < len(parts):
            ip = parts[idx + 1].split(":")[0]
    email = "UNKNOWN"
    if email_idx is not None and email_idx + 1 < len(parts):
        email = parts[email_idx + 1]
    blocked = "blocked" in line.lower()
    domain = None
    try:
        if "accepted" in parts:
            acc_idx = parts.index("accepted")
            if acc_idx + 1 < len(parts):
                target = parts[acc_idx + 1]
                if ":" in target:
                    proto, rest = target.split(":", 1)
                    domain = rest.split(":")[0]
    except Exception:
        domain = None
    return ip, timestamp, email, domain, blocked


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)


class TorrentWatcher:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.xui = XuiClient(settings)
        self.log = BanLog(settings.log_file)
        self.notifier = WebhookNotifier(settings.webhook_url, settings.webhook_token)
        self.wa = WhatsAppNotifier(settings.wa_enabled, settings.wa_api_key, settings.wa_channel)
        self.output_file = settings.output_file
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.stop_requested = False
        self.processed_emails: set[str] = set()
        self.notified_emails: set[str] = set()
        self.revalidate_thread = threading.Thread(target=self._revalidate_loop, daemon=True)
        self.base_dir = Path(__file__).resolve().parent.parent

    def stop(self, *_: Any) -> None:
        self.stop_requested = True
        self._self_destruct()

    def write_offender(self, timestamp: str, ip: str, email: str, raw: str) -> None:
        detect_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
        with self.output_file.open("a", encoding="utf-8") as fh:
            fh.write(
                f"{detect_time}\t{timestamp}\t{ip}\t{email}\t{raw.rstrip()}\n"
            )
        LOG.info("Logged offender %s to %s", email, self.output_file)

    def disable_client(self, email: str, ip: str) -> bool:
        client = self.xui.get_client(email)
        if not client:
            LOG.warning("No client found for email %s", email)
            return False
        inbound_id = client.get("inboundId") or client.get("inbound_id")
        client_uuid = client.get("uuid") or client.get("id")
        if inbound_id is None or client_uuid is None:
            LOG.warning("Client data missing inboundId/uuid for %s", email)
            return False
        disabled = self.xui.set_client_enabled(inbound_id, client_uuid, enable=False)
        entry = {
            "email": email,
            "ip": ip,
            "inbound_id": inbound_id,
            "client_uuid": client_uuid,
            "disabled_at": datetime.now(timezone.utc).isoformat(),
            "recommended_review_hours": self.settings.ban_hours,
        }
        if disabled:
            LOG.info("Disabled client %s; waiting for manual review", email)
        else:
            LOG.info("Client %s already in desired state", email)
        self.log.add(entry)
        if self.notifier.url and email not in self.notified_emails:
            self.notifier.notify(
                {
                    "event": "torrent_blocked",
                    "email": email,
                    "ip": ip,
                    "recommended_review_hours": self.settings.ban_hours,
                }
            )
            self.notified_emails.add(email)
        return True

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        LOG.info("Watching %s", self.settings.log_path)
        LOG.info("Writing offenders to %s", self.output_file)
        self.revalidate_thread.start()
        for line in follow_file(self.settings.log_path):
            if self.stop_requested:
                break
            if not line:
                time.sleep(self.settings.poll_interval)
                continue
            low = line.lower()
            if not any(marker in low for marker in BLOCK_MARKERS):
                continue
            ip, timestamp, email, domain, blocked = parse_line(line)
            if not blocked:
                continue
            if not ip or not email or email == "UNKNOWN":
                continue
            if email in self.processed_emails:
                continue
            LOG.info("Detected bittorrent usage from %s (%s) via %s", email, ip, domain or "unknown")
            self.write_offender(timestamp or "", ip, email, line)
            try:
                if self.disable_client(email, ip):
                    self.processed_emails.add(email)
                    if domain:
                        self.wa.send_ban(email, domain, self.settings.ban_hours)
            except Exception as exc:
                LOG.error("Failed to disable %s: %s", email, exc)

    def _revalidate_loop(self) -> None:
        if not self.settings.tblock_token:
            LOG.error("No TBLOCK_TOKEN set; stopping service for safety.")
            self._self_destruct()
            return
        while not self.stop_requested:
            try:
                self._check_status()
            except Exception as exc:
                LOG.error("Revalidation failed: %s", exc)
                self._self_destruct()
                return
            for _ in range(60 * 60 * 5):  # 5 hours
                if self.stop_requested:
                    return
                time.sleep(1)

    def _check_status(self) -> None:
        url = f"{self.settings.validator_url}/status"
        payload = {
            "token": self.settings.tblock_token,
            "vps_ip": self.settings.vps_ip or "",
        }
        resp = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=12,
        )
        if resp.status_code >= 400:
            detail = resp.text
            try:
                data = resp.json()
                if isinstance(data, dict):
                    detail = data.get("detail") or data.get("message") or detail
            except Exception:
                pass
            raise RuntimeError(f"Validator rejected token: {detail}")
        data = resp.json()
        if not data.get("ok"):
            raise RuntimeError("Validator response not OK")

    def _self_destruct(self) -> None:
        try:
            subprocess.run(["systemctl", "stop", "tblock-watcher.service"], check=False)
            subprocess.run(["systemctl", "disable", "tblock-watcher.service"], check=False)
            subprocess.run(["rm", "-f", "/etc/systemd/system/tblock-watcher.service"], check=False)
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            if self.base_dir.exists():
                subprocess.run(["rm", "-rf", str(self.base_dir)], check=False)
        except Exception as exc:
            LOG.error("Self-destruct encountered an error: %s", exc)
        os._exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Torrent watcher daemon")
    parser.add_argument(
        "--env-file",
        help="Path to .env file (defaults to .env in repo root)",
    )
    parser.add_argument("--debug", action="store_true", help="Verbose logging")
    return parser.parse_args()


def main() -> int:
    setup_logging()
    args = parse_args()
    env_path = Path(args.env_file) if args.env_file else None
    settings = load_settings(env_path)
    if args.debug:
        LOG.setLevel(logging.DEBUG)
    watcher = TorrentWatcher(settings)
    LOG.info("Service configured. Offender file: %s | Ban log: %s", settings.output_file, settings.log_file)
    watcher.run()
    LOG.info("Watcher stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
