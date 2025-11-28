import getpass
import json
import os
import platform
import sqlite3
import subprocess
import sys
import textwrap
from importlib import import_module
from pathlib import Path
from typing import Optional, Tuple

REQUESTS = None
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

XUI_DB_PATH = Path("/etc/x-ui/x-ui.db")
TARGET_DIR = Path("/etc/tblock")
VALIDATOR_URL = "https://whale-app-sdmtd.ondigitalocean.app"


def fail(msg: str):
    print(f"{RED}[!] {msg}{RESET}")
    sys.exit(1)


def banner():
    art = r"""
 _   _     _            _       __ _      _           _        _ _           
| | | |   | |          | |     / _| |    (_)         | |      | | |          
| |_| |__ | | ___   ___| | __ | |_| | __  _ _ __  ___| |_ __ _| | | ___ _ __ 
| __| '_ \| |/ _ \ / __| |/ / |  _| |/ / | | '_ \/ __| __/ _` | | |/ _ \ '__|
| |_| |_) | | (_) | (__|   < _| | |   <  | | | | \__ \ || (_| | | |  __/ |   
 \__|_.__/|_|\___/ \___|_|\_(_)_| |_|\_\ |_|_| |_|___/\__\__,_|_|_|\___|_|   
    """
    print(f"{CYAN}{art}{RESET}")
    print(f"{BOLD}{GREEN}tblock.fk installer{RESET}  {YELLOW}@dragonforce{RESET}\n")


def get_server_ip() -> str:
    try:
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            check=True,
            capture_output=True,
            text=True,
        )
        parts = result.stdout.split()
        for idx, token in enumerate(parts):
            if token == "src" and idx + 1 < len(parts):
                return parts[idx + 1]
    except Exception:
        pass
    fallback = subprocess.getoutput("hostname -I").split()
    return fallback[0] if fallback else "127.0.0.1"


def check_ubuntu():
    if platform.system().lower() != "linux":
        fail("Only Linux is supported")
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            data = f.read().lower()
        if "ubuntu" not in data:
            fail("Only Ubuntu is supported")
    except FileNotFoundError:
        fail("Cannot detect OS; /etc/os-release missing")


def check_xui_installed():
    if not XUI_DB_PATH.exists():
        fail("3x-ui not detected. Install 3x-ui first.")


def check_cert_present():
    try:
        conn = sqlite3.connect(XUI_DB_PATH)
        cur = conn.cursor()
        cur.execute("select key, value from settings where key in ('webCertFile','webKeyFile')")
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        fail(f"Failed to read x-ui settings: {e}")
    settings = {k: v for k, v in rows}
    cert = settings.get("webCertFile")
    key = settings.get("webKeyFile")
    if not cert or not key:
        fail("SSL cert/key not configured. Run 3x-ui option 19 to install cert.")
    if not Path(cert).exists() or not Path(key).exists():
        fail("Configured SSL cert/key files not found on disk.")


def ensure_venv(base: Path) -> Path:
    venv_path = base / "venv"
    if not venv_path.exists():
        try:
            subprocess.check_call([sys.executable, "-m", "venv", str(venv_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            print("[!] Creating virtualenv failed. Attempting to install python3-venv ...")
            installer = ["apt-get", "install", "-y", "python3-venv"]
            if os.geteuid() != 0:
                installer.insert(0, "sudo")
            try:
                subprocess.check_call(installer, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.check_call([sys.executable, "-m", "venv", str(venv_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                fail("Creating virtualenv failed. Install python3-venv (e.g., sudo apt-get install -y python3-venv) and rerun.")
    return venv_path


def run_pip(venv: Path, packages):
    pip = venv / "bin" / "pip"
    if not pip.exists():
        py = venv / "bin" / "python"
        try:
            subprocess.check_call([str(py), "-m", "ensurepip", "--upgrade"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            fail("pip is missing in the virtualenv. Install python3-venv and python3-pip, then rerun.")
    if not pip.exists():
        fail("pip is missing in the virtualenv. Install python3-venv and python3-pip, then rerun.")
    subprocess.check_call([str(pip), "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.check_call([str(pip), "install"] + packages, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def load_requests(venv: Path):
    major, minor = sys.version_info[:2]
    site_packages = venv / "lib" / f"python{major}.{minor}" / "site-packages"
    if site_packages.exists() and str(site_packages) not in sys.path:
        sys.path.insert(0, str(site_packages))
    try:
        return import_module("requests")
    except ImportError as e:
        fail(f"requests not available even after install: {e}")


def get_public_ip() -> str:
    try:
        resp = REQUESTS.get("https://api.ipify.org?format=json", timeout=8)
        resp.raise_for_status()
        return resp.json().get("ip")
    except Exception as e:
        fail(f"Could not determine public IP: {e}")


def validate_with_backend(token: str, vps_ip: str, hostname: str | None = None):
    if not VALIDATOR_URL:
        fail("VALIDATOR_URL not set")
    payload = {"token": token, "vps_ip": vps_ip, "hostname": hostname or ""}
    try:
        resp = REQUESTS.post(VALIDATOR_URL.rstrip("/") + "/validate", data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=10)
        if resp.status_code >= 400:
            msg = ""
            if resp.headers.get("content-type", "").startswith("application/json"):
                data = resp.json()
                if isinstance(data, dict):
                    if "detail" in data:
                        msg = data["detail"]
                    elif "message" in data:
                        msg = data["message"]
                elif isinstance(data, list):
                    msg = "; ".join([item.get("msg", str(item)) for item in data if isinstance(item, dict)]) or str(data)
            else:
                msg = resp.text
            if "uniq_token_ip_active" in msg or "duplicate key" in msg:
                msg = "TBlock is already installed on this VPS for this token. Please contact the admin to reset your slot."
            fail(f"Token check failed: {msg or 'unknown error'}")
        return resp.json()
    except Exception as e:
        fail(f"Token check failed: {e}")


def load_xui_config():
    try:
        conn = sqlite3.connect(XUI_DB_PATH)
        cur = conn.cursor()
        cur.execute("select key, value from settings where key in ('webPort','webBasePath','webCertFile','webKeyFile','twoFactorToken')")
        settings_rows = cur.fetchall()
        cur.execute("select username from users limit 1")
        user_row = cur.fetchone()
        conn.close()
    except Exception as e:
        fail(f"Failed to read x-ui settings: {e}")
    settings = {k: v for k, v in settings_rows}
    port = settings.get("webPort")
    raw_base = settings.get("webBasePath")
    cert = settings.get("webCertFile")
    twofa = settings.get("twoFactorToken") or ""
    if not port or raw_base is None or not cert:
        fail("Missing port/base/cert settings in x-ui database.")
    base_path = "/" + str(raw_base).strip("/")
    try:
        domain = Path(cert).parent.name
    except Exception:
        domain = ""
    if not domain:
        fail("Could not determine domain from cert path.")
    username = user_row[0] if user_row else ""
    if not username:
        fail("Could not find a panel username in users table.")
    return {
        "port": str(port),
        "base": base_path,
        "cert": cert,
        "domain": domain,
        "username": username,
        "twofa": twofa,
    }


def verify_wasender(api_key: str) -> bool:
    try:
        resp = REQUESTS.get(
            "https://www.wasenderapi.com/api/whatsapp-sessions",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        data = resp.json()
        if resp.status_code == 200 and isinstance(data, dict) and data.get("success") and data.get("data"):
            return True
        return False
    except Exception:
        return False


def test_wasender_message(api_key: str, channel_id: str) -> Tuple[bool, str]:
    try:
        payload = {"to": channel_id, "text": "tblock.fk test message"}
        resp = REQUESTS.post(
            "https://www.wasenderapi.com/api/send-message",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            data=json.dumps(payload),
            timeout=12,
        )
        data = resp.json()
        if resp.status_code == 200 and isinstance(data, dict) and data.get("success"):
            return True, ""
        return False, str(data)
    except Exception as e:
        return False, str(e)


def ensure_access_log(log_path: Path):
    while True:
        if log_path.exists():
            print(f"{GREEN}✓ Access log detected{RESET}")
            return
        print(f"{YELLOW}Access log not found at {log_path}{RESET}")
        print("Enable logging in 3x-ui (Panel -> Settings -> Logs) and ensure access log is on.")
        ans = input(f"{CYAN}Have you enabled the log? (y/n): {RESET}").strip().lower()
        if ans == "y":
            continue
        else:
            print(f"{YELLOW}Waiting for log to be enabled...{RESET}")


def install_requirements(venv: Path, base: Path):
    req = base / "requirements.txt"
    if not req.exists():
        req.write_text("requests\npython-dotenv\n", encoding="utf-8")
    pip = venv / "bin" / "pip"
    subprocess.check_call([str(pip), "install", "-r", str(req)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_service(base: Path, venv: Path, env_path: Path):
    service = textwrap.dedent(
        f"""
        [Unit]
        Description=tblock.fk watcher
        After=network.target

        [Service]
        Type=simple
        WorkingDirectory={base}
        EnvironmentFile={env_path}
        ExecStart={venv}/bin/python pTblock/torrent_watch.py
        Restart=on-failure
        TimeoutStopSec=5
        KillMode=process

        [Install]
        WantedBy=multi-user.target
        """
    ).strip() + "\n"
    service_path = base / "tblock-watcher.service"
    service_path.write_text(service, encoding="utf-8")
    return service_path


def write_panel_service(base: Path, venv: Path, env_path: Path, port: str):
    service = textwrap.dedent(
        f"""
        [Unit]
        Description=tblock.fk panel
        After=network.target

        [Service]
        Type=simple
        WorkingDirectory={base}
        EnvironmentFile={env_path}
        ExecStart={venv}/bin/uvicorn pTblock.panel_app:app --host 0.0.0.0 --port {port}
        Restart=on-failure
        TimeoutStopSec=5
        KillMode=process

        [Install]
        WantedBy=multi-user.target
        """
    ).strip() + "\n"
    service_path = base / "tblock-panel.service"
    service_path.write_text(service, encoding="utf-8")
    return service_path


def install_service_unit(service_path: Path):
    target = Path("/etc/systemd/system") / service_path.name
    service_name = service_path.name
    cmds = [
        (["cp", str(service_path), str(target)], "copy service"),
        (["systemctl", "daemon-reload"], "daemon-reload"),
        (["systemctl", "enable", "--now", service_name], "enable/start service"),
    ]
    for cmd, desc in cmds:
        final = cmd if os.geteuid() == 0 else ["sudo"] + cmd
        try:
            subprocess.check_call(final, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{GREEN}✓ {desc}{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{YELLOW}! Failed to {desc}: {e}{RESET}")
            return False
    return True


def create_cli_menu():
    script = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        svc="tblock-watcher.service"
        svc_panel="tblock-panel.service"
        RED="\\033[91m"; GREEN="\\033[92m"; YELLOW="\\033[93m"; CYAN="\\033[96m"; RESET="\\033[0m"; BOLD="\\033[1m"

        banner() {
          cat <<'EOF'
         _   _     _            _       __ _      _           _        _ _           
        | | | |   | |          | |     / _| |    (_)         | |      | | |          
        | |_| |__ | | ___   ___| | __ | |_| | __  _ _ __  ___| |_ __ _| | | ___ _ __ 
        | __| '_ \\| |/ _ \\ / __| |/ / |  _| |/ / | | '_ \\/ __| __/ _` | | |/ _ \\ '__|
        | |_| |_) | | (_) | (__|   < _| | |   <  | | | | \\__ \\ || (_| | | |  __/ |   
         \\__|_.__/|_|\\___/ \\___|_|\\_(_)_| |_|\\_\\ |_|_| |_|___/\\__\\__,_|_|_|\\___|_|   
        EOF
          echo -e "${BOLD}${CYAN}tblock.fk control${RESET}"
        }

        workdir="/etc/tblock"

        status_msg() {
          echo -e "${BOLD}Watcher:${RESET} $(systemctl is-active --quiet "$svc" && echo -e "${GREEN}running${RESET}" || echo -e "${YELLOW}stopped${RESET}")"
          echo -e "${BOLD}Panel:${RESET} $(systemctl is-active --quiet "$svc_panel" && echo -e "${GREEN}running${RESET}" || echo -e "${YELLOW}stopped${RESET}")"
        }

        show_logs() {
          echo -e "${CYAN}Recent logs:${RESET}"
          journalctl -u "$svc" -n 50 --no-pager --output=cat || echo "No logs available."
        }

        start_svc() {
          systemctl start "$svc" "$svc_panel" && echo -e "${GREEN}tblock started.${RESET}"
        }

        stop_svc() {
          systemctl stop "$svc" "$svc_panel" && echo -e "${GREEN}tblock stopped.${RESET}"
        }

        remove_all() {
          echo -e "${YELLOW}This will remove tblock service and files in ${workdir}.${RESET}"
          read -rp "Proceed? (y/n): " ans
          if [[ "$ans" != "y" ]]; then
            echo "Cancelled."
            return
          fi
          systemctl disable --now "$svc_panel" "$svc" 2>/dev/null || true
          rm -f /etc/systemd/system/"$svc" /etc/systemd/system/"$svc_panel"
          systemctl daemon-reload
          rm -f /usr/local/bin/tblock
          if [[ -d "$workdir" ]]; then
            rm -rf "$workdir"
          fi
          echo -e "${GREEN}tblock removed.${RESET}"
        }

        while true; do
          clear
          banner
          echo -e "${BOLD}1) Status${RESET}"
          echo -e "${BOLD}2) Logs${RESET}"
          echo -e "${BOLD}3) Start${RESET}"
          echo -e "${BOLD}4) Stop${RESET}"
          echo -e "${BOLD}5) Remove tblock${RESET}"
          echo -e "${BOLD}6) Exit${RESET}"
          read -rp "Select an option: " opt
          case "$opt" in
            1) status_msg; read -rp \"Press Enter to return...\" _ ;;
            2) show_logs; read -rp \"Press Enter to return...\" _ ;;
            3) start_svc; read -rp \"Press Enter to return...\" _ ;;
            4) stop_svc; read -rp \"Press Enter to return...\" _ ;;
            5) remove_all; read -rp \"Press Enter to return...\" _ ;;
            6) exit 0 ;;
            *) echo \"Invalid option\"; sleep 1 ;;
          esac
        done
        """
    )
    path = Path("/usr/local/bin/tblock")
    try:
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
        print(f"{GREEN}✓ Installed CLI helper 'tblock'{RESET}")
    except Exception as e:
        print(f"{YELLOW}! Could not install CLI helper: {e}{RESET}")


def main():
    base = TARGET_DIR
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    src_root = Path(__file__).resolve().parent
    import shutil
    for name in ["installer.py", "requirements.txt", "env.template"]:
        src = src_root / name
        if src.exists():
            shutil.copy2(src, TARGET_DIR / name)
    dst_dir = TARGET_DIR / "pTblock"
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    shutil.copytree(src_root / "pTblock", dst_dir)
    banner()
    check_ubuntu()
    print(f"{GREEN}✓ Ubuntu detected{RESET}")
    check_xui_installed()
    print(f"{GREEN}✓ 3x-ui detected{RESET}")
    check_cert_present()
    print(f"{GREEN}✓ SSL certificate found{RESET}")
    xui = load_xui_config()

    venv = ensure_venv(base)
    run_pip(venv, ["requests", "python-dotenv", "fastapi", "uvicorn", "python-multipart"])
    global REQUESTS
    REQUESTS = load_requests(venv)

    token = getpass.getpass("Enter your TBlock token: ").strip()
    if not token:
        fail("Token is required")
    if len(token) < 4:
        fail("Token must be at least 4 characters")

    vps_ip = get_public_ip()
    hostname = subprocess.getoutput("hostname") or None
    print(f"{CYAN}Validating token for IP {vps_ip}...{RESET}")
    result = validate_with_backend(token, vps_ip, hostname)
    print(f"{GREEN}✓ Token validated{RESET} (remaining slots: {result.get('remaining_slots')})")
    print(f"{YELLOW}Gathering panel details...{RESET}")

    panel_pass = ""
    while True:
        panel_pass = getpass.getpass(f"Enter password for panel user '{xui['username']}': ").strip()
        if not panel_pass:
            print(f"{YELLOW}Password required.{RESET}")
            continue
        try:
            sess = REQUESTS.Session()
            payload = {"username": xui["username"], "password": panel_pass}
            if xui.get("twofa"):
                payload["twoFactorCode"] = xui["twofa"]
            base_path = xui["base"].rstrip("/")
            url_https = f"https://{xui['domain']}:{xui['port']}{base_path}/login/"
            print(f"{CYAN}Trying panel login at {url_https} with user {xui['username']}...{RESET}")
            ok = False
            try:
                resp = sess.post(url_https, data=payload, timeout=12, verify=False, allow_redirects=False)
                if resp.status_code in (200, 302):
                    ok = True
            except Exception as e:
                print(f"{YELLOW}Login attempt to {url_https} failed: {e}{RESET}")
            if not ok:
                print(f"{RED}Password rejected by panel. Try again.{RESET}")
                continue
        except Exception as e:
            print(f"{RED}Password rejected by panel ({e}). Try again.{RESET}")
            continue
        break
    twofa = xui.get("twofa", "")

    wa_enabled = False
    wa_pat = ""
    wa_api = ""
    wa_channel = ""
    ans = input(f"{CYAN}Send suspension notices to WhatsApp channel? (y/n): {RESET}").strip().lower()
    if ans == "y":
        print(f"{YELLOW}Provide your Wasender personal access token (https://wasenderapi.com/settings/tokens).{RESET}")
        for attempt in range(3):
            wa_pat_try = getpass.getpass("Wasender personal access token: ").strip()
            if not wa_pat_try:
                print(f"{YELLOW}Token required.{RESET}")
                continue
            print(f"{CYAN}Validating personal access token...{RESET}")
            if verify_wasender(wa_pat_try):
                wa_pat = wa_pat_try
                break
            else:
                print(f"{RED}Validation failed. Ensure at least one WhatsApp session is connected.{RESET}")
        if wa_pat:
            print(f"{YELLOW}Now provide your Wasender API key for sending messages (https://wasenderapi.com/whatsapp/manage/).{RESET}")
            for attempt in range(3):
                wa_api_try = getpass.getpass("Wasender API key: ").strip()
                if not wa_api_try:
                    print(f"{YELLOW}API key required.{RESET}")
                    continue
                wa_channel_try = input(f"{CYAN}WhatsApp channel id (e.g., 123456789@newsletter): {RESET}").strip()
                if not wa_channel_try:
                    print(f"{YELLOW}Channel id required.{RESET}")
                    continue
                ok, err = test_wasender_message(wa_api_try, wa_channel_try)
                if ok:
                    wa_api = wa_api_try
                    wa_channel = wa_channel_try
                    wa_enabled = True
                    break
                else:
                    print(f"{RED}Send test failed: {err}{RESET}")
            if not wa_enabled:
                print(f"{YELLOW}Skipping WhatsApp automation. Contact 075 126 7252 for help.{RESET}")

    log_path = Path("/usr/local/x-ui/access.log")
    ensure_access_log(log_path)

    env_path = base / ".env"
    server_ip = get_server_ip()
    env_values = {
        "XRAY_LOG_PATH": str(log_path),
        "XRAY_OFFENDER_FILE": "data/torrent-offenders.txt",
        "XRAY_PANEL_SCHEME": "https",
        "XRAY_PANEL_HOST": xui["domain"],
        "XRAY_PANEL_PORT": xui["port"],
        "XRAY_PANEL_BASE": xui["base"],
        "XRAY_PANEL_USER": xui["username"],
        "XRAY_PANEL_PASS": panel_pass,
        "XRAY_PANEL_2FA": twofa,
        "TORRENT_LOG_FILE": "data/ban_log.json",
        "TORRENT_BAN_HOURS": "5",
        "TORRENT_POLL_INTERVAL": "1.0",
        "WEBHOOK_ALLOWED_ORIGINS": xui["domain"],
        "WEBHOOK_ALLOWED_IPS": server_ip,
        "WASENDER_ENABLED": "1" if wa_enabled else "0",
        "WASENDER_PERSONAL_TOKEN": wa_pat,
        "WASENDER_API_KEY": wa_api,
        "WASENDER_CHANNEL": wa_channel,
        "WHATSAPP_INTEGRATION": "True" if wa_enabled else "False",
        "TBLOCK_TOKEN": token,
        "VALIDATOR_URL": VALIDATOR_URL,
        "VPS_IP": vps_ip,
        "BAN_DB": str((base / "data" / "bans.db").resolve()),
        "PANEL_PORT": "2374",
    }
    env_path.write_text("\n".join(f"{k}={v}" for k, v in env_values.items()) + "\n", encoding="utf-8")
    print(f"{YELLOW}Proceeding with tblock core install...{RESET}")
    data_dir = base / "data"
    data_dir.mkdir(exist_ok=True)
    install_requirements(venv, base)
    service_path = write_service(base, venv, env_path)
    panel_service = write_panel_service(base, venv, env_path, env_values["PANEL_PORT"])
    if install_service_unit(service_path):
        print(f"{GREEN}tblock watcher installed and running.{RESET}")
    else:
        print(f"{YELLOW}Service not fully installed. Manual steps may be required.{RESET}")
    if install_service_unit(panel_service):
        print(f"{GREEN}tblock panel installed and running on port {env_values['PANEL_PORT']}.{RESET}")
    else:
        print(f"{YELLOW}Panel service not fully installed. Manual steps may be required.{RESET}")
    subprocess.run(["systemctl", "restart", "tblock-watcher.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "restart", "tblock-panel.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    create_cli_menu()
    watcher_active = subprocess.call(["systemctl", "is-active", "--quiet", "tblock-watcher.service"]) == 0
    panel_active = subprocess.call(["systemctl", "is-active", "--quiet", "tblock-panel.service"]) == 0
    icon_ok = f"{GREEN}✓{RESET}"
    icon_err = f"{RED}!{RESET}"
    print(f"{icon_ok if watcher_active else icon_err} tblock watcher service {'running' if watcher_active else 'not running'}")
    print(f"{icon_ok if panel_active else icon_err} tblock panel service {'running' if panel_active else 'not running'}")
    print(f"{GREEN}Panel URL: http://{server_ip}:{env_values['PANEL_PORT']}/login{RESET}")
    print(f"{GREEN}Login with panel username: {xui['username']} and your provided password.{RESET}")


if __name__ == "__main__":
    main()
