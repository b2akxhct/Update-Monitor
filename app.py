#!/usr/bin/env python3
"""
Update Monitor — surveille et met à jour un parc de machines Linux
(Debian/Ubuntu) via SSH. Tout est géré depuis l'interface web :
hosts, planning des vérifications automatiques, webhook Discord,
et déclenchement manuel de vérifications ou de mises à jour réelles.
"""

import ipaddress
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone

import paramiko
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

DB_PATH = os.environ.get("DB_PATH", "/app/data/monitor.db")
DISCORD_MAX_LEN = 1900  # marge de sécurité sous la limite Discord de 2000

app = Flask(__name__)
db_lock = threading.Lock()
scheduler = BackgroundScheduler()


# ---------------------------------------------------------------------------
# Gestionnaires de paquets supportés
# ---------------------------------------------------------------------------
# Chaque entrée fournit : label affiché, commande de vérification (sans
# modifier le système), commande de mise à jour réelle, les codes de sortie
# à considérer comme "pas une erreur", et une fonction qui extrait la liste
# des paquets upgradables depuis la sortie brute.
#
# NB : le filtre "sécurité uniquement" (security_only) ne fonctionne
# correctement que pour apt (basé sur le nom du dépôt "-security"). Pour
# les autres gestionnaires il n'a pour l'instant aucun effet.

def _parse_lines_nonempty(out):
    return [l for l in out.splitlines() if l.strip()]


def _parse_dnf_yum(out):
    lines = []
    for l in out.splitlines():
        parts = l.split()
        if len(parts) == 3 and "." in parts[0] and not l.startswith("Last metadata"):
            lines.append(l)
    return lines


def _parse_pacman(out):
    return [l for l in out.splitlines() if "->" in l]


def _parse_zypper(out):
    return [l for l in out.splitlines() if re.match(r"^v\s*\|", l.strip(), re.IGNORECASE)]


def _sudo(is_root):
    return "" if is_root else "sudo -n "


PACKAGE_MANAGERS = {
    "apt": {
        "label": "APT (Debian / Ubuntu)",
        "check_cmd": lambda root: (
            f"{_sudo(root)}apt-get update -qq && "
            "apt list --upgradable 2>/dev/null | grep -v '^Listing' || true"
        ),
        "upgrade_cmd": lambda root: (
            f"{_sudo(root)}apt-get update -qq && "
            f"{_sudo(root)}DEBIAN_FRONTEND=noninteractive apt-get "
            '-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" '
            "-y full-upgrade"
        ),
        "autoremove_cmd": lambda root: (
            f"{_sudo(root)}DEBIAN_FRONTEND=noninteractive apt-get -y autoremove"
        ),
        "success_exit_codes": {0},
        "parse": _parse_lines_nonempty,
    },
    "apk": {
        "label": "APK (Alpine Linux)",
        "check_cmd": lambda root: (
            f"{_sudo(root)}apk update -q && apk list -u 2>/dev/null"
        ),
        "upgrade_cmd": lambda root: (
            f"{_sudo(root)}apk update -q && {_sudo(root)}apk upgrade --no-cache"
        ),
        # apk n'a pas d'équivalent fiable à "autoremove" pour l'instant
        "autoremove_cmd": None,
        "success_exit_codes": {0},
        "parse": _parse_lines_nonempty,
    },
    "dnf": {
        "label": "DNF (Fedora / RHEL 8+ / CentOS Stream)",
        "check_cmd": lambda root: f"{_sudo(root)}dnf check-update -q",
        "upgrade_cmd": lambda root: f"{_sudo(root)}dnf -y upgrade",
        "autoremove_cmd": lambda root: f"{_sudo(root)}dnf -y autoremove",
        # dnf check-update renvoie 100 (pas 0) quand des mises à jour existent
        "success_exit_codes": {0, 100},
        "parse": _parse_dnf_yum,
    },
    "yum": {
        "label": "YUM (RHEL / CentOS 7)",
        "check_cmd": lambda root: f"{_sudo(root)}yum check-update -q",
        "upgrade_cmd": lambda root: f"{_sudo(root)}yum -y update",
        "autoremove_cmd": lambda root: f"{_sudo(root)}yum -y autoremove",
        "success_exit_codes": {0, 100},
        "parse": _parse_dnf_yum,
    },
    "pacman": {
        "label": "Pacman (Arch Linux)",
        "check_cmd": lambda root: (
            f"{_sudo(root)}pacman -Sy --noconfirm >/dev/null 2>&1; pacman -Qu 2>/dev/null"
        ),
        "upgrade_cmd": lambda root: f"{_sudo(root)}pacman -Syu --noconfirm",
        "autoremove_cmd": lambda root: (
            f"{_sudo(root)}bash -c "
            "'pkgs=$(pacman -Qtdq 2>/dev/null); "
            'if [ -n "$pkgs" ]; then pacman -Rns --noconfirm $pkgs; '
            "else echo \"Aucun paquet orphelin à supprimer\"; fi'"
        ),
        # pacman -Qu renvoie 1 quand il n'y a rien à mettre à jour (pas une erreur)
        "success_exit_codes": {0, 1},
        "parse": _parse_pacman,
    },
    "zypper": {
        "label": "Zypper (openSUSE)",
        "check_cmd": lambda root: (
            f"{_sudo(root)}zypper --non-interactive refresh -q; "
            "zypper --non-interactive list-updates"
        ),
        "upgrade_cmd": lambda root: f"{_sudo(root)}zypper --non-interactive update",
        # Pas d'équivalent autoremove fiable implémenté pour zypper pour l'instant
        "autoremove_cmd": None,
        "success_exit_codes": {0, 100, 101, 102, 103},
        "parse": _parse_zypper,
    },
}

DEFAULT_PACKAGE_MANAGER = "apt"


DEFAULT_SETTINGS = {
    "discord_webhook_url": "",
    "notify_only_if_updates": 1,
    "schedule_cron": "0 8 * * *",
    "ssh_timeout": 15,
    "auto_upgrade": 0,
    "auto_autoremove": 0,
}


# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock, get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                user TEXT NOT NULL,
                auth_method TEXT NOT NULL DEFAULT 'key',  -- 'key' | 'password'
                ssh_key_path TEXT,
                ssh_password TEXT,
                security_only INTEGER NOT NULL DEFAULT 0,
                package_manager TEXT NOT NULL DEFAULT 'apt'
            )
        """)
        # Migration pour les bases créées avant l'ajout de package_manager
        try:
            conn.execute("ALTER TABLE hosts ADD COLUMN package_manager TEXT NOT NULL DEFAULT 'apt'")
        except sqlite3.OperationalError:
            pass  # colonne déjà présente
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL,
                update_count INTEGER,
                packages TEXT,
                error_message TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS upgrade_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                output TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                discord_webhook_url TEXT,
                notify_only_if_updates INTEGER NOT NULL DEFAULT 1,
                schedule_cron TEXT NOT NULL DEFAULT '0 8 * * *',
                ssh_timeout INTEGER NOT NULL DEFAULT 15,
                auto_upgrade INTEGER NOT NULL DEFAULT 0,
                auto_autoremove INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Migration pour les bases créées avant l'ajout de ces réglages
        for col_def in ("auto_upgrade INTEGER NOT NULL DEFAULT 0", "auto_autoremove INTEGER NOT NULL DEFAULT 0"):
            try:
                conn.execute(f"ALTER TABLE settings ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass  # colonne déjà présente
        existing = conn.execute("SELECT id FROM settings WHERE id = 1").fetchone()
        if not existing:
            conn.execute("""
                INSERT INTO settings (id, discord_webhook_url, notify_only_if_updates, schedule_cron, ssh_timeout, auto_upgrade, auto_autoremove)
                VALUES (1, :discord_webhook_url, :notify_only_if_updates, :schedule_cron, :ssh_timeout, :auto_upgrade, :auto_autoremove)
            """, DEFAULT_SETTINGS)
        conn.commit()


def get_settings():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        return dict(row)


def update_settings(data):
    with db_lock, get_db() as conn:
        conn.execute("""
            UPDATE settings SET
                discord_webhook_url = ?,
                notify_only_if_updates = ?,
                schedule_cron = ?,
                ssh_timeout = ?,
                auto_upgrade = ?,
                auto_autoremove = ?
            WHERE id = 1
        """, (
            data["discord_webhook_url"],
            1 if data.get("notify_only_if_updates") else 0,
            data["schedule_cron"],
            int(data["ssh_timeout"]),
            1 if data.get("auto_upgrade") else 0,
            1 if data.get("auto_autoremove") else 0,
        ))
        conn.commit()


# ---------------------------------------------------------------------------
# SSH — vérification et mise à jour
# ---------------------------------------------------------------------------

def _ssh_connect(host_row, ssh_timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host_row["address"],
        "port": host_row["port"],
        "username": host_row["user"],
        "timeout": ssh_timeout,
    }
    if host_row["auth_method"] == "key" and host_row["ssh_key_path"]:
        connect_kwargs["key_filename"] = host_row["ssh_key_path"]
    elif host_row["ssh_password"]:
        connect_kwargs["password"] = host_row["ssh_password"]
    client.connect(**connect_kwargs)
    return client


def check_host(host_row, ssh_timeout):
    """Liste les paquets upgradables sur le host (ne modifie rien)."""
    pm = PACKAGE_MANAGERS.get(host_row["package_manager"] or DEFAULT_PACKAGE_MANAGER, PACKAGE_MANAGERS[DEFAULT_PACKAGE_MANAGER])
    is_root = host_row["user"] == "root"

    try:
        client = _ssh_connect(host_row, ssh_timeout)
    except Exception as e:
        return {"status": "error", "error_message": str(e)}

    try:
        cmd = pm["check_cmd"](is_root)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=ssh_timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()

        if exit_code not in pm["success_exit_codes"] and not out:
            return {"status": "error", "error_message": err or f"exit code {exit_code}"}

        lines = pm["parse"](out)
        if host_row["security_only"]:
            lines = [l for l in lines if "-security" in l.lower()]

        return {"status": "ok", "update_count": len(lines), "packages": "\n".join(lines)}
    except Exception as e:
        return {"status": "error", "error_message": str(e)}
    finally:
        client.close()


def upgrade_host(host_row, ssh_timeout):
    """Lance réellement la mise à jour sur le host. Peut prendre du temps."""
    pm = PACKAGE_MANAGERS.get(host_row["package_manager"] or DEFAULT_PACKAGE_MANAGER, PACKAGE_MANAGERS[DEFAULT_PACKAGE_MANAGER])
    is_root = host_row["user"] == "root"

    try:
        client = _ssh_connect(host_row, ssh_timeout)
    except Exception as e:
        return {"status": "error", "output": str(e)}

    try:
        # Timeout plus large pour l'upgrade (téléchargement + install)
        upgrade_timeout = max(ssh_timeout * 20, 300)
        cmd = pm["upgrade_cmd"](is_root)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=upgrade_timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        combined = out + ("\n--- stderr ---\n" + err if err.strip() else "")
        status = "ok" if exit_code in pm["success_exit_codes"] or exit_code == 0 else "error"
        return {"status": status, "output": combined.strip()}
    except Exception as e:
        return {"status": "error", "output": str(e)}
    finally:
        client.close()


def run_autoremove(host_row, ssh_timeout):
    """Supprime les paquets qui ne sont plus nécessaires (orphelins/dépendances
    inutiles). Retourne un statut 'ok' avec un message explicite si le
    gestionnaire de paquets du host n'a pas d'équivalent supporté."""
    pm = PACKAGE_MANAGERS.get(host_row["package_manager"] or DEFAULT_PACKAGE_MANAGER, PACKAGE_MANAGERS[DEFAULT_PACKAGE_MANAGER])
    cmd_builder = pm.get("autoremove_cmd")
    if not cmd_builder:
        return {"status": "ok", "output": f"(pas de nettoyage automatique supporté pour {pm['label']})"}

    is_root = host_row["user"] == "root"
    try:
        client = _ssh_connect(host_row, ssh_timeout)
    except Exception as e:
        return {"status": "error", "output": str(e)}

    try:
        timeout = max(ssh_timeout * 10, 180)
        cmd = cmd_builder(is_root)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        combined = out + ("\n--- stderr ---\n" + err if err.strip() else "")
        status = "ok" if exit_code == 0 else "error"
        return {"status": status, "output": combined.strip()}
    except Exception as e:
        return {"status": "error", "output": str(e)}
    finally:
        client.close()


def _maybe_autoremove(host_row, ssh_timeout, upgrade_result, auto_autoremove_enabled):
    """Si activé, lance le nettoyage après une mise à jour réussie et
    fusionne le résultat dans upgrade_result. Ne modifie rien si la
    mise à jour elle-même a échoué."""
    if not auto_autoremove_enabled or upgrade_result["status"] != "ok":
        return upgrade_result

    ar = run_autoremove(host_row, ssh_timeout)
    header = "\n\n--- Suppression des paquets inutiles ---\n"
    upgrade_result["output"] = (upgrade_result.get("output") or "") + header + ar["output"]
    if ar["status"] == "error":
        upgrade_result["output"] += "\n[Le nettoyage a échoué, la mise à jour elle-même a réussi]"
    return upgrade_result


def record_check(host_id, result):
    with db_lock, get_db() as conn:
        conn.execute("""
            INSERT INTO checks (host_id, checked_at, status, update_count, packages, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            host_id, datetime.now(timezone.utc).isoformat(), result["status"],
            result.get("update_count"), result.get("packages"), result.get("error_message"),
        ))
        conn.commit()


def record_upgrade(host_id, started_at, result):
    with db_lock, get_db() as conn:
        conn.execute("""
            INSERT INTO upgrade_logs (host_id, started_at, finished_at, status, output)
            VALUES (?, ?, ?, ?, ?)
        """, (
            host_id, started_at, datetime.now(timezone.utc).isoformat(),
            result["status"], result.get("output"),
        ))
        conn.commit()


# ---------------------------------------------------------------------------
# Notification Discord
# ---------------------------------------------------------------------------

def send_discord_notification(webhook_url, summary_lines):
    if not webhook_url or not summary_lines:
        return
    message = "\n".join(summary_lines)
    chunks = []
    while message:
        if len(message) <= DISCORD_MAX_LEN:
            chunks.append(message)
            break
        cut = message.rfind("\n", 0, DISCORD_MAX_LEN)
        if cut == -1:
            cut = DISCORD_MAX_LEN
        chunks.append(message[:cut])
        message = message[cut:].lstrip("\n")

    for chunk in chunks:
        try:
            resp = requests.post(webhook_url, json={"content": chunk}, timeout=10)
            if resp.status_code not in (200, 204):
                app.logger.error("Discord webhook a répondu %s : %s", resp.status_code, resp.text)
        except requests.RequestException as e:
            app.logger.error("Échec d'envoi Discord : %s", e)


# ---------------------------------------------------------------------------
# Cycle de vérification complet (utilisé par le scheduler et "Vérifier tout")
# ---------------------------------------------------------------------------

def _process_host_for_scheduled_check(host, settings):
    """Vérifie un host et, si l'auto-upgrade est activée et des mises à
    jour sont trouvées, les installe (+ nettoyage si activé). Met à jour
    l'historique en base et retourne une ligne de résumé pour Discord."""
    ssh_timeout = settings["ssh_timeout"]
    auto_upgrade = bool(settings.get("auto_upgrade"))
    auto_autoremove = bool(settings.get("auto_autoremove"))

    result = check_host(host, ssh_timeout)
    record_check(host["id"], result)

    if result["status"] == "error":
        return f"⚠️ **{host['name']}** : erreur ({result['error_message']})"

    if result["update_count"] == 0:
        return f"✅ **{host['name']}** : à jour"

    if not auto_upgrade:
        return f"🔶 **{host['name']}** : {result['update_count']} mise(s) à jour"

    # Auto-upgrade activée et des mises à jour sont disponibles
    started_at = datetime.now(timezone.utc).isoformat()
    up_result = upgrade_host(host, ssh_timeout)
    up_result = _maybe_autoremove(host, ssh_timeout, up_result, auto_autoremove)
    record_upgrade(host["id"], started_at, up_result)

    # Re-vérifie après coup pour le compteur final envoyé sur Discord
    final = check_host(host, ssh_timeout)
    record_check(host["id"], final)

    if up_result["status"] == "error":
        return f"⚠️ **{host['name']}** : échec de la mise à jour automatique"
    if final["status"] == "ok" and final["update_count"] == 0:
        return f"✅ **{host['name']}** : mis à jour automatiquement ({result['update_count']} paquet(s))"
    if final["status"] == "ok":
        return f"🔶 **{host['name']}** : mise à jour partielle, {final['update_count']} restante(s)"
    return f"⚠️ **{host['name']}** : mise à jour effectuée mais vérification finale en erreur"


def run_full_check(notify=True):
    settings = get_settings()

    with get_db() as conn:
        hosts = conn.execute("SELECT * FROM hosts").fetchall()

    summary_lines = [f"**Rapport de mises à jour — {datetime.now().strftime('%d/%m/%Y %H:%M')}**"]
    any_flagged = False  # updates trouvées, installées, ou erreur

    for host in hosts:
        line = _process_host_for_scheduled_check(host, settings)
        summary_lines.append(line)
        if not line.startswith("✅"):
            any_flagged = True

    if notify:
        webhook_url = settings["discord_webhook_url"]
        if webhook_url and (any_flagged or not settings["notify_only_if_updates"]):
            send_discord_notification(webhook_url, summary_lines)

    return summary_lines


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def start_scheduler():
    settings = get_settings()
    cron_expr = settings["schedule_cron"]
    parts = cron_expr.split()
    if len(parts) != 5:
        parts = ["0", "8", "*", "*", "*"]
    trigger = CronTrigger(minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4])
    scheduler.remove_all_jobs()
    scheduler.add_job(run_full_check, trigger=trigger, id="full_check")
    if not scheduler.running:
        scheduler.start()


# ---------------------------------------------------------------------------
# Tri par adresse IP
# ---------------------------------------------------------------------------

def _ip_sort_key(address):
    """Clé de tri numérique : 10.0.0.9 < 10.0.0.10. Les hostnames (non-IP)
    passent après les IP, triés alphabétiquement."""
    try:
        ip = ipaddress.ip_address((address or "").strip())
        return (0, ip.version, int(ip), "")
    except ValueError:
        return (1, 0, 0, (address or "").lower())


def _sort_params():
    """Lit ?sort=ip&order=asc|desc. Retourne (sort, order) ; sort vaut
    None si aucun tri par IP n'est demandé (tri par nom par défaut)."""
    sort = "ip" if request.args.get("sort") == "ip" else None
    order = "desc" if request.args.get("order") == "desc" else "asc"
    return sort, order


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    with get_db() as conn:
        hosts = conn.execute("SELECT * FROM hosts ORDER BY name").fetchall()
        data = []
        for h in hosts:
            last = conn.execute(
                "SELECT * FROM checks WHERE host_id = ? ORDER BY checked_at DESC LIMIT 1", (h["id"],)
            ).fetchone()
            last_upgrade = conn.execute(
                "SELECT * FROM upgrade_logs WHERE host_id = ? ORDER BY started_at DESC LIMIT 1", (h["id"],)
            ).fetchone()
            data.append({
                "host": dict(h),
                "last_check": dict(last) if last else None,
                "last_upgrade": dict(last_upgrade) if last_upgrade else None,
            })
    sort, order = _sort_params()
    if sort == "ip":
        data.sort(key=lambda r: _ip_sort_key(r["host"]["address"]), reverse=(order == "desc"))
    return render_template("dashboard.html", data=data, active="dashboard", sort=sort, order=order)


@app.route("/api/check/<int:host_id>", methods=["POST"])
def api_check_one(host_id):
    settings = get_settings()
    with get_db() as conn:
        host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not host:
        return jsonify({"error": "host introuvable"}), 404
    result = check_host(host, settings["ssh_timeout"])
    record_check(host_id, result)
    return jsonify(result)


@app.route("/api/check-all", methods=["POST"])
def api_check_all():
    notify = request.args.get("notify", "true").lower() == "true"
    summary = run_full_check(notify=notify)
    return jsonify({"summary": summary})


@app.route("/api/upgrade/<int:host_id>", methods=["POST"])
def api_upgrade_one(host_id):
    settings = get_settings()
    with get_db() as conn:
        host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not host:
        return jsonify({"error": "host introuvable"}), 404

    started_at = datetime.now(timezone.utc).isoformat()
    result = upgrade_host(host, settings["ssh_timeout"])
    result = _maybe_autoremove(host, settings["ssh_timeout"], result, bool(settings.get("auto_autoremove")))
    record_upgrade(host_id, started_at, result)

    # Re-vérifie immédiatement après l'upgrade pour rafraîchir le compteur
    check_result = check_host(host, settings["ssh_timeout"])
    record_check(host_id, check_result)

    return jsonify({"upgrade": result, "check_after": check_result})


@app.route("/api/upgrade-stream/<int:host_id>", methods=["POST"])
def api_upgrade_stream(host_id):
    """Lance la mise à jour (+ nettoyage si activé) et streame la sortie SSH en direct."""
    settings = get_settings()
    with get_db() as conn:
        host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not host:
        return Response("[ERREUR] host introuvable\n[DONE] status=error\n", mimetype="text/plain"), 404

    ssh_timeout = settings["ssh_timeout"]
    auto_autoremove = bool(settings.get("auto_autoremove"))
    pm = PACKAGE_MANAGERS.get(host["package_manager"] or DEFAULT_PACKAGE_MANAGER, PACKAGE_MANAGERS[DEFAULT_PACKAGE_MANAGER])
    is_root = host["user"] == "root"
    max_duration = max(ssh_timeout * 40, 1800)  # garde-fou : 30 min par défaut

    def stream_command(client, cmd, result_holder):
        """Exécute cmd sur une session SSH dédiée, streame la sortie en
        direct, et remplit result_holder avec exit_code/output à la fin."""
        output_chunks = []
        transport = client.get_transport()
        channel = transport.open_session()
        channel.set_combine_stderr(True)
        channel.exec_command(cmd)
        channel.settimeout(1.0)

        start_time = time.monotonic()
        while True:
            if channel.recv_ready():
                data = channel.recv(4096)
                if data:
                    text = data.decode("utf-8", errors="replace")
                    output_chunks.append(text)
                    yield text
                continue
            if channel.exit_status_ready():
                break
            if time.monotonic() - start_time > max_duration:
                yield "\n[ERREUR] Délai maximum dépassé, arrêt du suivi (la commande continue peut-être côté serveur)\n"
                break
            time.sleep(0.2)

        while channel.recv_ready():
            data = channel.recv(4096)
            text = data.decode("utf-8", errors="replace")
            output_chunks.append(text)
            yield text

        result_holder["exit_code"] = channel.recv_exit_status() if channel.exit_status_ready() else -1
        result_holder["output"] = "".join(output_chunks)

    def generate():
        started_at = datetime.now(timezone.utc).isoformat()
        status = "error"
        full_output = ""

        yield f"$ Connexion SSH à {host['address']}:{host['port']}...\n"
        try:
            client = _ssh_connect(host, ssh_timeout)
        except Exception as e:
            msg = f"[ERREUR] Connexion SSH échouée : {e}\n"
            yield msg
            record_upgrade(host_id, started_at, {"status": "error", "output": msg})
            yield "[DONE] status=error\n"
            return

        try:
            cmd = pm["upgrade_cmd"](is_root)
            yield f"$ {cmd}\n\n"
            holder = {}
            yield from stream_command(client, cmd, holder)
            exit_code = holder.get("exit_code", -1)
            full_output = holder.get("output", "")
            status = "ok" if (exit_code in pm["success_exit_codes"] or exit_code == 0) else "error"
            yield f"\n$ Terminé (code {exit_code})\n"

            if status == "ok" and auto_autoremove:
                if pm.get("autoremove_cmd"):
                    ar_cmd = pm["autoremove_cmd"](is_root)
                    yield f"\n$ {ar_cmd}\n\n"
                    ar_holder = {}
                    yield from stream_command(client, ar_cmd, ar_holder)
                    ar_exit = ar_holder.get("exit_code", -1)
                    full_output += "\n\n--- Suppression des paquets inutiles ---\n" + ar_holder.get("output", "")
                    yield f"\n$ Nettoyage terminé (code {ar_exit})\n"
                    if ar_exit != 0:
                        full_output += "\n[Le nettoyage a échoué, la mise à jour elle-même a réussi]"
                else:
                    note = f"(pas de nettoyage automatique supporté pour {pm['label']})"
                    yield f"\n$ {note}\n"
                    full_output += "\n\n" + note

            record_upgrade(host_id, started_at, {"status": status, "output": full_output})
        except Exception as e:
            err_msg = f"\n[ERREUR] {e}\n"
            yield err_msg
            record_upgrade(host_id, started_at, {"status": "error", "output": full_output + err_msg})
            status = "error"
        finally:
            client.close()

        yield "$ Nouvelle vérification...\n"
        check_result = check_host(host, ssh_timeout)
        record_check(host_id, check_result)
        if check_result["status"] == "ok":
            yield f"$ {check_result['update_count']} mise(s) à jour restante(s)\n"
        else:
            yield f"$ Erreur de vérification : {check_result.get('error_message')}\n"

        yield f"[DONE] status={status}\n"

    return Response(
        generate(),
        mimetype="text/plain",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


# ---------------------------------------------------------------------------
# Routes — Gestion des hosts
# ---------------------------------------------------------------------------

@app.route("/hosts")
def hosts_page():
    with get_db() as conn:
        hosts = conn.execute("SELECT * FROM hosts ORDER BY name").fetchall()
    sort, order = _sort_params()
    if sort == "ip":
        hosts = sorted(hosts, key=lambda h: _ip_sort_key(h["address"]), reverse=(order == "desc"))
    return render_template(
        "hosts.html", hosts=hosts, edit_host=None, active="hosts",
        package_managers=PACKAGE_MANAGERS, default_pm=DEFAULT_PACKAGE_MANAGER,
        sort=sort, order=order,
    )


@app.route("/hosts/add", methods=["POST"])
def hosts_add():
    _save_host(request.form, host_id=None)
    return redirect(url_for("hosts_page"))


@app.route("/hosts/<int:host_id>/edit", methods=["GET"])
def hosts_edit_form(host_id):
    with get_db() as conn:
        hosts = conn.execute("SELECT * FROM hosts ORDER BY name").fetchall()
        edit_host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    sort, order = _sort_params()
    if sort == "ip":
        hosts = sorted(hosts, key=lambda h: _ip_sort_key(h["address"]), reverse=(order == "desc"))
    return render_template(
        "hosts.html", hosts=hosts, edit_host=edit_host, active="hosts",
        package_managers=PACKAGE_MANAGERS, default_pm=DEFAULT_PACKAGE_MANAGER,
        sort=sort, order=order,
    )


@app.route("/hosts/<int:host_id>/update", methods=["POST"])
def hosts_update(host_id):
    _save_host(request.form, host_id=host_id)
    return redirect(url_for("hosts_page"))


@app.route("/hosts/<int:host_id>/delete", methods=["POST"])
def hosts_delete(host_id):
    with db_lock, get_db() as conn:
        conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        conn.commit()
    return redirect(url_for("hosts_page"))


def _save_host(form, host_id):
    name = form["name"].strip()
    address = form["address"].strip()
    port = int(form.get("port") or 22)
    user = form["user"].strip()
    auth_method = form.get("auth_method", "key")
    ssh_key_path = form.get("ssh_key_path", "").strip() or None
    ssh_password = form.get("ssh_password", "").strip() or None
    security_only = 1 if form.get("security_only") == "on" else 0
    package_manager = form.get("package_manager", DEFAULT_PACKAGE_MANAGER)
    if package_manager not in PACKAGE_MANAGERS:
        package_manager = DEFAULT_PACKAGE_MANAGER

    with db_lock, get_db() as conn:
        if host_id is None:
            conn.execute("""
                INSERT INTO hosts (name, address, port, user, auth_method, ssh_key_path, ssh_password, security_only, package_manager)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, address, port, user, auth_method, ssh_key_path, ssh_password, security_only, package_manager))
        else:
            # Ne réécrit le mot de passe que si un nouveau a été saisi
            if ssh_password:
                conn.execute("""
                    UPDATE hosts SET name=?, address=?, port=?, user=?, auth_method=?,
                        ssh_key_path=?, ssh_password=?, security_only=?, package_manager=? WHERE id=?
                """, (name, address, port, user, auth_method, ssh_key_path, ssh_password, security_only, package_manager, host_id))
            else:
                conn.execute("""
                    UPDATE hosts SET name=?, address=?, port=?, user=?, auth_method=?,
                        ssh_key_path=?, security_only=?, package_manager=? WHERE id=?
                """, (name, address, port, user, auth_method, ssh_key_path, security_only, package_manager, host_id))
        conn.commit()


# ---------------------------------------------------------------------------
# Routes — Réglages
# ---------------------------------------------------------------------------

@app.route("/settings", methods=["GET"])
def settings_page():
    return render_template("settings.html", settings=get_settings(), active="settings")


@app.route("/settings", methods=["POST"])
def settings_save():
    update_settings({
        "discord_webhook_url": request.form.get("discord_webhook_url", "").strip(),
        "notify_only_if_updates": request.form.get("notify_only_if_updates") == "on",
        "schedule_cron": request.form.get("schedule_cron", "0 8 * * *").strip(),
        "ssh_timeout": request.form.get("ssh_timeout", 15),
        "auto_upgrade": request.form.get("auto_upgrade") == "on",
        "auto_autoremove": request.form.get("auto_autoremove") == "on",
    })
    start_scheduler()  # reprogramme immédiatement avec le nouveau planning
    return redirect(url_for("settings_page"))


# ---------------------------------------------------------------------------
# Démarrage
# ---------------------------------------------------------------------------

def bootstrap():
    init_db()
    start_scheduler()


bootstrap()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
