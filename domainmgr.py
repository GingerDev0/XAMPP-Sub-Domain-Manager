#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from urllib import request, parse, error
import secrets
import string

LAMPP = "/opt/lampp/lampp"
HTTPD_CONF = "/opt/lampp/etc/httpd.conf"
VHOSTS_CONF = "/opt/lampp/etc/extra/httpd-vhosts.conf"
VHOSTS_ROOT = "/opt/lampp/vhosts"
SSL_LINK_BASE = "/opt/lampp/ssl/live"
DATA_DIR = "/opt/lampp/domainmgr"
CONFIG_JSON = os.path.join(DATA_DIR, "config.json")
SUBS_JSON = os.path.join(DATA_DIR, "subdomains.json")
LOG_DIR = "/opt/lampp/logs"
PREP_MARK = os.path.join(DATA_DIR, ".prep_done")

ENV_PATH = Path(__file__).resolve().with_suffix(".env")
CF_API = "https://api.cloudflare.com/client/v4"
PROFTPD_CONF = "/opt/lampp/etc/proftpd.conf"

RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"; OK = "\033[92m"; WARN = "\033[93m"; ERR = "\033[91m"; CYAN = "\033[96m"

def hr(): print(DIM + "─" * 60 + RESET)
def box_title(title: str):
    print(CYAN + "┌" + "─" * 58 + "┐" + RESET)
    print(CYAN + "│ " + RESET + BOLD + f"{title:<56}" + RESET + CYAN + "│" + RESET)
    print(CYAN + "├" + "─" * 58 + "┤" + RESET)
def box_end(): print(CYAN + "└" + "─" * 58 + "┘" + RESET)

def require_root():
    if os.geteuid() != 0:
        print("This script must be run with sudo/root.", file=sys.stderr); sys.exit(1)

def run(cmd: str, check=True, capture=False, env=None, shell=False) -> subprocess.CompletedProcess:
    if shell: return subprocess.run(cmd, check=check, capture_output=capture, text=True, env=env, shell=True)
    return subprocess.run(shlex.split(cmd), check=check, capture_output=capture, text=True, env=env)

def run_with_countdown(cmd_list, seconds: int, label: str):
    print(f"\n{DIM}Waiting up to {seconds}s for {label} ...{RESET}")
    stop_flag = {"stop": False}
    def countdown():
        for r in range(seconds, 0, -1):
            if stop_flag["stop"]: break
            print(f"\r{BOLD}{r:>3}s{RESET} ", end="", flush=True); time.sleep(1)
        print("\r" + " " * 8 + "\r", end="", flush=True)
    t = threading.Thread(target=countdown, daemon=True); t.start()
    rc = subprocess.Popen(cmd_list).wait(); stop_flag["stop"] = True; t.join(timeout=0.1)
    if rc != 0: raise subprocess.CalledProcessError(rc, cmd_list)

def ensure_dirs():
    for d in [DATA_DIR, VHOSTS_ROOT, LOG_DIR, os.path.dirname(VHOSTS_CONF), os.path.dirname(SSL_LINK_BASE)]:
        os.makedirs(d, exist_ok=True)

def load_env() -> Dict[str, str]:
    env = {}
    if ENV_PATH.exists():
        with open(ENV_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line: continue
                k, v = line.split("=", 1); env[k.strip()] = v.strip()
    return env

def save_env(env: Dict[str, str]):
    lines = [f"{k}={env[k]}" for k in ["CF_API_TOKEN", "CF_PROXIED", "PUBLIC_IP"] if k in env and env[k] != ""]
    ENV_PATH.write_text("\n".join(lines) + "\n"); os.chmod(ENV_PATH, 0o600)

def get_public_ip(prefer: Optional[str]) -> str:
    if prefer: return prefer.strip()
    try:
        with request.urlopen("https://ipv4.icanhazip.com", timeout=10) as resp:
            ip = resp.read().decode().strip(); socket.inet_aton(ip); return ip
    except Exception:
        print("Could not auto-detect public IP. Set PUBLIC_IP in .env.", file=sys.stderr); sys.exit(1)

def get_public_ip_soft(prefer: Optional[str]) -> Optional[str]:
    if prefer: return prefer.strip()
    try:
        with request.urlopen("https://ipv4.icanhazip.com", timeout=10) as resp:
            ip = resp.read().decode().strip(); socket.inet_aton(ip); return ip
    except Exception: return None

def read_json(path: str, default):
    try: 
        with open(path, "r") as f: return json.load(f)
    except FileNotFoundError: return default

def write_json(path: str, data): 
    with open(path, "w") as f: json.dump(data, f, indent=2)

def ensure_vhosts_include_enabled():
    with open(HTTPD_CONF, "r") as f: content = f.read()
    new = re.sub(r'^\s*#\s*Include\s+etc/extra/httpd-vhosts\.conf','Include etc/extra/httpd-vhosts.conf', content, flags=re.MULTILINE)
    if new != content: 
        with open(HTTPD_CONF, "w") as f: f.write(new)

def lampp_reload():
    try: run(f"{LAMPP} reload")
    except subprocess.CalledProcessError: run(f"{LAMPP} restart")

def ensure_docroot(domain: str) -> str:
    docroot = os.path.join(VHOSTS_ROOT, domain, "public")
    os.makedirs(docroot, exist_ok=True)

    index_php = os.path.join(docroot, "index.php")
    created = False
    if not os.path.exists(index_php):
        src_txt = Path(__file__).resolve().with_name("index.txt")
        content = src_txt.read_text(encoding="utf-8") if src_txt.exists() else "<?php echo 'OK: ' . htmlspecialchars($_SERVER['HTTP_HOST']); ?>"
        Path(index_php).write_text(content, encoding="utf-8")
        created = True

    # If we just created index.php, try to chown it to the subdomain's user and daemon group
    if created:
        try:
            sub_prefix = domain.split(".", 1)[0]
            # Safe UNIX username check
            if re.fullmatch(r"[a-z_][a-z0-9_-]*", sub_prefix or ""):
                rc = subprocess.run(["id", "-u", sub_prefix], check=False)
                if rc.returncode == 0:
                    shutil.chown(index_php, user=sub_prefix, group="daemon")
        except Exception:
            pass

    return docroot

def vhost_block_http(domain: str, docroot: str) -> str:
    return f"""
# --- BEGIN {domain} ---
<VirtualHost *:80>
    ServerName {domain}
    DocumentRoot "{docroot}"
    ErrorLog "{LOG_DIR}/{domain}-error.log"
    CustomLog "{LOG_DIR}/{domain}-access.log" combined
    <Directory "{docroot}">
        AllowOverride All
        Require all granted
    </Directory>
    #RewriteEngine On
    #RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [L,R=301]
</VirtualHost>
# --- END {domain} ---
""".strip() + "\n"

def vhost_block_ssl(domain: str, docroot: str) -> str:
    cert_dir = os.path.join(SSL_LINK_BASE, domain)
    fullchain = os.path.join(cert_dir, "fullchain.pem"); privkey = os.path.join(cert_dir, "privkey.pem")
    return f"""
# --- BEGIN SSL {domain} ---
<VirtualHost *:443>
    ServerName {domain}
    DocumentRoot "{docroot}"
    ErrorLog "{LOG_DIR}/{domain}-ssl-error.log"
    CustomLog "{LOG_DIR}/{domain}-ssl-access.log" combined
    SSLEngine on
    SSLCertificateFile "{fullchain}"
    SSLCertificateKeyFile "{privkey}"
    <Directory "{docroot}">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
# --- END SSL {domain} ---
""".strip() + "\n"

def upsert_vhost(domain: str, docroot: str, with_ssl: bool):
    if not os.path.exists(VHOSTS_CONF): Path(VHOSTS_CONF).touch()
    with open(VHOSTS_CONF, "r") as f: text = f.read()
    text = re.sub(rf"# --- BEGIN {re.escape(domain)} ---.*?# --- END {re.escape(domain)} ---\n?","", text, flags=re.DOTALL)
    text = re.sub(rf"# --- BEGIN SSL {re.escape(domain)} ---.*?# --- END SSL {re.escape(domain)} ---\n?","", text, flags=re.DOTALL)
    text = text.rstrip() + "\n\n" + vhost_block_http(domain, docroot)
    if with_ssl: text = text.rstrip() + "\n\n" + vhost_block_ssl(domain, docroot)
    with open(VHOSTS_CONF, "w") as f: f.write(text)

def enable_http_to_https_redirect(domain: str):
    with open(VHOSTS_CONF, "r") as f: text = f.read()
    new_text = re.sub(rf"(<VirtualHost \*:80>\s*?\n\s*ServerName {re.escape(domain)}.*?)(#RewriteEngine On\n\s*#RewriteRule \^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} \[L,R=301\])",
                      lambda m: m.group(1) + "RewriteEngine On\n    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]", text, flags=re.DOTALL)
    if new_text != text:
        with open(VHOSTS_CONF, "w") as f: f.write(new_text)

def symlink_le_certs(domain: str):
    os.makedirs(os.path.join(SSL_LINK_BASE, domain), exist_ok=True)
    for src, name in [(f"/etc/letsencrypt/live/{domain}/fullchain.pem", "fullchain.pem"),
                      (f"/etc/letsencrypt/live/{domain}/privkey.pem", "privkey.pem")]:
        dst = os.path.join(SSL_LINK_BASE, domain, name)
        if os.path.islink(dst) or os.path.exists(dst): os.remove(dst)
        os.symlink(src, dst)

def remove_ssl_symlinks(domain: str):
    d = os.path.join(SSL_LINK_BASE, domain)
    if os.path.isdir(d): shutil.rmtree(d, ignore_errors=True)

def cert_expires_on(domain: str) -> Optional[str]:
    cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
    if not os.path.exists(cert_path): return None
    try:
        out = subprocess.check_output(["openssl","x509","-in",cert_path,"-noout","-enddate"], text=True)
        return out.strip().split("=",1)[1]
    except Exception: return None

def http_json(method: str, url: str, headers: Dict[str, str], payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode(); headers = dict(headers); headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode(); return json.loads(body) if body else {}
    except error.HTTPError as e:
        msg = e.read().decode(); raise RuntimeError(f"HTTP {e.code} on {url}: {msg}") from None

def cf_headers(token: str) -> Dict[str, str]: return {"Authorization": f"Bearer {token}"}

def cf_get_zone_id(token: str, apex_domain: str) -> str:
    url = f"{CF_API}/zones?name={parse.quote(apex_domain)}&status=active"
    r = http_json("GET", url, cf_headers(token)); result = r.get("result", [])
    if not result: raise RuntimeError(f"Zone {apex_domain} not found in Cloudflare")
    return result[0]["id"]

def cf_find_record(token: str, zone_id: str, name: str, rtype="A") -> Optional[Dict[str, Any]]:
    url = f"{CF_API}/zones/{zone_id}/dns_records?type={rtype}&name={parse.quote(name)}"
    r = http_json("GET", url, cf_headers(token)); items = r.get("result", [])
    return items[0] if items else None

def cf_upsert_a_record(token: str, zone_id: str, name: str, ip: str, proxied: bool) -> Dict[str, Any]:
    existing = cf_find_record(token, zone_id, name, "A")
    payload = {"type":"A","name":name,"content":ip,"ttl":1,"proxied":proxied}
    if existing:
        url = f"{CF_API}/zones/{zone_id}/dns_records/{existing['id']}"
        r = http_json("PUT", url, cf_headers(token), payload)
    else:
        url = f"{CF_API}/zones/{zone_id}/dns_records"
        r = http_json("POST", url, cf_headers(token), payload)
    return r

def cf_delete_record(token: str, zone_id: str, rec_id: str):
    url = f"{CF_API}/zones/{zone_id}/dns_records/{rec_id}"; http_json("DELETE", url, cf_headers(token))

def derive_apex(domain: str) -> str:
    parts = domain.strip(".").split("."); 
    if len(parts) < 2: raise ValueError("Invalid domain")
    return ".".join(parts[-2:])

def certbot_issue_cloudflare(domain: str, cf_token: str, email: str, countdown_seconds: int = 60):
    with tempfile.NamedTemporaryFile(prefix="cloudflare_", suffix=".ini", delete=False) as tf:
        cred_path = tf.name; tf.write(f"dns_cloudflare_api_token = {cf_token}\n".encode("utf-8"))
    os.chmod(cred_path, 0o600)
    try:
        cmd_list = ["certbot","certonly","--dns-cloudflare","--dns-cloudflare-credentials",cred_path,
                    "--dns-cloudflare-propagation-seconds",str(countdown_seconds),"-d",domain,
                    "--non-interactive","--agree-tos","-m",email]
        run_with_countdown(cmd_list, countdown_seconds, "cert DNS propagation (Let’s Encrypt)")
    finally:
        try: os.remove(cred_path)
        except FileNotFoundError: pass

def gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def user_exists(name: str) -> bool:
    cp = run(f"id -u {shlex.quote(name)}", check=False); return cp.returncode == 0

def create_system_user(username: str, home: str):
    if user_exists(username): return
    run(f"useradd -r -M -d {shlex.quote(home)} -s /usr/sbin/nologin {shlex.quote(username)}")

def set_user_password(username: str, plaintext: str):
    proc = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, text=True)
    proc.communicate(f"{username}:{plaintext}")
    if proc.returncode != 0: raise RuntimeError("Failed to set password with chpasswd")

def add_user_to_group(username: str, group: str):
    run(f"usermod -aG {shlex.quote(group)} {shlex.quote(username)}", check=False)

def ensure_dir_writeable_by_group(path: str, group: str):
    run(f"chgrp -R {shlex.quote(group)} {shlex.quote(path)}", check=False)
    run(f"chmod -R g+rwX {shlex.quote(path)}", check=False)
    run(f"find {shlex.quote(path)} -type d -exec chmod g+s {{}} +", check=False)

def ensure_traversable_parents(fqdn: str):
    base = os.path.join(VHOSTS_ROOT, fqdn)
    run(f"chmod g+rx {shlex.quote(VHOSTS_ROOT)}", check=False)
    run(f"chmod g+rx {shlex.quote(base)}", check=False)

def grant_daemon_and_user(docroot: str, username: str, fqdn: Optional[str]=None):
    add_user_to_group(username, "daemon")
    ensure_dir_writeable_by_group(docroot, "daemon")
    if fqdn: ensure_traversable_parents(fqdn)

def render_proftpd_conf(public_ip: Optional[str], main_domain: Optional[str], tls_enabled: bool) -> str:
    masc = f"MasqueradeAddress               {public_ip}\n" if public_ip else ""
    tls = ""
    if tls_enabled and main_domain:
        tls = f"""
<IfModule mod_tls.c>
  TLSEngine                     on
  TLSLog                        /opt/lampp/logs/proftpd-tls.log
  TLSProtocol                   TLSv1.2
  TLSRSACertificateFile         /opt/lampp/ssl/live/{main_domain}/fullchain.pem
  TLSRSACertificateKeyFile      /opt/lampp/ssl/live/{main_domain}/privkey.pem
  TLSCipherSuite                HIGH
  TLSOptions                    NoSessionReuseRequired
  TLSRequired                   on
  TLSRenegotiate                none
</IfModule>
""".rstrip()
    return f"""ServerName                      "{(main_domain or 'XAMPP').split(':')[0]} FTP Server"
ServerType                      standalone
DefaultServer                   on

Port                            21
Umask                           002

User                            daemon
Group                           daemon

DefaultRoot                     ~

AuthOrder                       mod_auth_unix.c
RequireValidShell               off
UseFtpUsers                     off

PassivePorts                    40000 40100
{masc}AllowOverwrite                  on

<Directory ~>
  AllowOverwrite                on
  <Limit MKD STOR STOU APPE RNFR RNTO DELE RMD>
    AllowAll
  </Limit>
</Directory>

<Directory /opt/lampp/htdocs/*>
  AllowOverwrite                on
</Directory>

<Directory /opt/lampp/vhosts/*/public>
  AllowOverwrite                on
  <Limit MKD STOR STOU APPE RNFR RNTO DELE RMD>
    AllowAll
  </Limit>
</Directory>

{tls}
<Limit SITE_CHMOD>
  DenyAll
</Limit>
""".replace("\n\n\n", "\n\n").strip() + "\n"

def write_proftpd_conf(public_ip: Optional[str], main_domain: Optional[str], tls_enabled: bool):
    text = render_proftpd_conf(public_ip, main_domain, tls_enabled)
    Path(PROFTPD_CONF).write_text(text)
    run(f"{LAMPP} restartftp", check=False)

def one_time_prep():
    if os.path.exists(PREP_MARK): return
    box_title("One-time system prep")
    run("systemctl stop apache2", check=False)
    run("systemctl disable apache2", check=False)
    try:
        status = run("ufw status", check=False, capture=True)
        if "Status: active" in (status.stdout or ""):
            run("ufw allow 80/tcp", check=False)
            run("ufw allow 443/tcp", check=False)
            run("ufw allow 21/tcp", check=False)
            run("ufw allow 40000:40100/tcp", check=False)
    except Exception: pass
    run("snap install core", check=False)
    run("snap refresh core", check=False)
    run("snap install --classic certbot", check=False)
    run("ln -sf /snap/bin/certbot /usr/bin/certbot", check=False)
    run("snap set certbot trust-plugin-with-root=ok", check=False)
    run("snap install certbot-dns-cloudflare", check=False)
    run("systemctl stop vsftpd", check=False)
    run("systemctl disable vsftpd", check=False)
    ensure_dirs()
    if os.path.exists(HTTPD_CONF): ensure_vhosts_include_enabled()
    pub_ip_soft = get_public_ip_soft(None)
    write_proftpd_conf(public_ip=pub_ip_soft, main_domain=None, tls_enabled=False)
    Path(PREP_MARK).write_text(datetime.utcnow().isoformat() + "Z")
    print(OK + "System prep complete." + RESET); box_end()

def prompt_env_and_save(existing: Dict[str, str]) -> Dict[str, str]:
    box_title("Cloudflare + network settings")
    token = input("Cloudflare API Token (Zone:Read + DNS:Edit): ").strip() or existing.get("CF_API_TOKEN", "")
    while not token:
        print(ERR + "Token is required." + RESET); token = input("Cloudflare API Token: ").strip()
    public_ip = input("Public IP (Enter to auto-detect): ").strip()
    proxied_in = (input("Proxy via Cloudflare? [Y/n]: ").strip().lower() or "y")
    proxied = "true" if proxied_in in ("y","yes") else "false"
    env = {"CF_API_TOKEN": token, "CF_PROXIED": proxied}
    if public_ip: env["PUBLIC_IP"] = public_ip
    save_env(env); box_end(); return env

def print_domain_details(fqdn: str, docroot: str):
    cert_exp = cert_expires_on(fqdn) or "no cert"
    print(); hr(); print(BOLD + "Configuration summary" + RESET)
    print(f"  Host:      {fqdn}")
    print(f"  URL:       https://{fqdn}/")
    print(f"  Docroot:   {docroot}")
    print(f"  Logs:      {LOG_DIR}/{fqdn}-access.log")
    print(f"             {LOG_DIR}/{fqdn}-error.log")
    print(f"             {LOG_DIR}/{fqdn}-ssl-access.log")
    print(f"             {LOG_DIR}/{fqdn}-ssl-error.log")
    print(f"  Vhosts:    {VHOSTS_CONF}")
    print(f"  SSL link:  {os.path.join(SSL_LINK_BASE, fqdn)}")
    print(f"  Cert exp:  {cert_exp}"); hr()

def first_time_setup(cfg: Dict[str, Any], subs: Dict[str, Any], env: Dict[str, str]):
    box_title("First-time domain setup")
    domain = input("Main domain (e.g., example.com): ").strip().lower()
    while not domain: domain = input("Main domain: ").strip().lower()
    admin_email = input("Admin email for Let's Encrypt (e.g., you@example.com): ").strip()
    while not admin_email: admin_email = input("Admin email: ").strip()
    public_ip = get_public_ip(env.get("PUBLIC_IP"))
    apex = derive_apex(domain); zone_id = cf_get_zone_id(env["CF_API_TOKEN"], apex)
    ensure_dirs(); docroot = ensure_docroot(domain); upsert_vhost(domain, docroot, with_ssl=False)
    proxied_bool = env.get("CF_PROXIED","true").lower() == "true"
    cf_upsert_a_record(env["CF_API_TOKEN"], zone_id, domain, public_ip, proxied_bool)
    print("\nIssuing Let's Encrypt certificate via DNS-01 (Cloudflare)...")
    certbot_issue_cloudflare(domain, env["CF_API_TOKEN"], admin_email, countdown_seconds=60)
    symlink_le_certs(domain); upsert_vhost(domain, docroot, with_ssl=True)
    enable_http_to_https_redirect(domain); lampp_reload()
    write_proftpd_conf(public_ip=public_ip, main_domain=domain, tls_enabled=True)
    cfg.update({"main_domain": domain, "zone_id": zone_id, "apex": apex, "created_at": datetime.utcnow().isoformat()+"Z"})
    write_json(CONFIG_JSON, cfg); write_json(SUBS_JSON, subs)
    print(OK + f"\nMain domain {domain} configured with SSL + FTPS (ProFTPD)." + RESET); print_domain_details(domain, docroot); box_end()

def add_subdomain(cfg: Dict[str, Any], subs: Dict[str, Any], env: Dict[str, str]):
    if not cfg.get("main_domain"): print("Run first-time setup first."); return
    box_title("Add sub-domain")
    sub = input("Subdomain prefix (e.g., test for test.example.com): ").strip().lower()
    if not sub: print(ERR + "Subdomain required." + RESET); box_end(); return
    fqdn = f"{sub}.{cfg['main_domain']}"; public_ip = get_public_ip(env.get("PUBLIC_IP"))
    ensure_dirs(); docroot = ensure_docroot(fqdn); upsert_vhost(fqdn, docroot, with_ssl=False)
    ftp_user = sub
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", ftp_user):
        print(WARN + f"Subdomain prefix '{sub}' is not a safe UNIX username; normalizing." + RESET)
        ftp_user = re.sub(r"[^a-z0-9_-]","", sub.lower()); 
        if not ftp_user or not re.match(r"[a-z_]", ftp_user[0]): ftp_user = f"u_{ftp_user or 'user'}"
    create_system_user(ftp_user, docroot)
    ftp_pass = gen_password(); set_user_password(ftp_user, ftp_pass)
    grant_daemon_and_user(docroot, ftp_user, fqdn=fqdn)
    print(OK + f"FTP user created for {fqdn}" + RESET)
    print(WARN + "Password is shown once — store it securely." + RESET)
    print(f"  Host:   {cfg['main_domain']}  (or server IP)")
    print(f"  User:   {ftp_user}")
    print(f"  Pass:   {ftp_pass}")
    print(f"  Root:   {docroot}")
    print(f"  Mode:   FTPS (explicit TLS)")
    proxied_bool = env.get("CF_PROXIED","true").lower() == "true"
    cf_upsert_a_record(env["CF_API_TOKEN"], cfg["zone_id"], fqdn, public_ip, proxied_bool)
    print("\nIssuing Let's Encrypt certificate via DNS-01 (Cloudflare)...")
    admin_email = input("Admin email for Let's Encrypt (leave blank to use admin@main): ").strip() or ("admin@" + cfg["main_domain"])
    certbot_issue_cloudflare(fqdn, env["CF_API_TOKEN"], admin_email, countdown_seconds=60)
    symlink_le_certs(fqdn); upsert_vhost(fqdn, docroot, with_ssl=True); enable_http_to_https_redirect(fqdn); lampp_reload()
    subs[fqdn] = {"fqdn": fqdn, "docroot": docroot, "ftp_user": ftp_user, "created_at": datetime.utcnow().isoformat() + "Z"}
    write_json(SUBS_JSON, subs)
    print(OK + f"Sub-domain {fqdn} added and secured." + RESET); print_domain_details(fqdn, docroot); box_end()

def list_subdomains(subs: Dict[str, Any]):
    box_title("Sub-domains")
    if not subs: print("(none yet)"); box_end(); return
    for i, name in enumerate(sorted(subs.keys()), 1):
        meta = subs[name]; extra = f", ftp_user: {meta.get('ftp_user')}" if meta.get("ftp_user") else ""
        print(f"{i:>2}. {BOLD}{name}{RESET}  {DIM}(docroot: {meta.get('docroot')}{extra}){RESET}")
    box_end()

def manage_subdomains(cfg: Dict[str, Any], subs: Dict[str, Any], env: Dict[str, str]):
    if not subs: print("No sub-domains to manage."); return
    box_title("Manage sub-domains")
    names = sorted(subs.keys()); 
    for i, name in enumerate(names, 1): print(f"{i}) {name}")
    choice = input("\nSelect a sub-domain number to manage (or Enter to cancel): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(names)): print("Cancelled."); box_end(); return
    fqdn = names[int(choice)-1]
    print(f"\nManaging {BOLD}{fqdn}{RESET}")
    print("  a) Re-issue certificate")
    print("  b) Re-point DNS A record to current server IP")
    print("  c) Remove sub-domain (vhost + DNS)  [ask about files + delete FTP user]")
    print("  d) Reset FTP password for this sub-domain")
    print("  Enter to cancel")
    opt = input("Choice: ").strip().lower()
    if opt == "a":
        email = input("Admin email for Let's Encrypt (blank = admin@main): ").strip() or ("admin@" + cfg["main_domain"])
        certbot_issue_cloudflare(fqdn, env["CF_API_TOKEN"], email, countdown_seconds=60)
        symlink_le_certs(fqdn); upsert_vhost(fqdn, subs[fqdn]["docroot"], with_ssl=True)
        enable_http_to_https_redirect(fqdn); lampp_reload(); print(OK + "Certificate re-issued and vhost updated." + RESET)
    elif opt == "b":
        public_ip = get_public_ip(env.get("PUBLIC_IP")); proxied_bool = env.get("CF_PROXIED","true").lower() == "true"
        cf_upsert_a_record(env["CF_API_TOKEN"], cfg["zone_id"], fqdn, public_ip, proxied_bool); print(OK + "DNS A record updated." + RESET)
    elif opt == "c":
        sure = input(f"Remove {fqdn} DNS A record and vhost? [y/N]: ").strip().lower()
        if sure not in ("y","yes"): print("Cancelled."); box_end(); return
        rec = cf_find_record(env["CF_API_TOKEN"], cfg["zone_id"], fqdn, "A")
        if rec: cf_delete_record(env["CF_API_TOKEN"], cfg["zone_id"], rec["id"])
        with open(VHOSTS_CONF, "r") as f: text = f.read()
        text = re.sub(rf"# --- BEGIN {re.escape(fqdn)} ---.*?# --- END {re.escape(fqdn)} ---\n?","", text, flags=re.DOTALL)
        text = re.sub(rf"# --- BEGIN SSL {re.escape(fqdn)} ---.*?# --- END SSL {re.escape(fqdn)} ---\n?","", text, flags=re.DOTALL)
        with open(VHOSTS_CONF, "w") as f: f.write(text)
        lampp_reload()
        ftp_user = subs.get(fqdn, {}).get("ftp_user")
        if ftp_user:
            try: run(f"userdel {shlex.quote(ftp_user)}", check=False); print(OK + f"FTP user '{ftp_user}' deleted." + RESET)
            except Exception as e: print(WARN + f"Could not delete FTP user '{ftp_user}': {e}" + RESET)
        del_files = input(f"Also delete document root {subs[fqdn]['docroot']} ? [y/N]: ").strip().lower()
        if del_files in ("y","yes"):
            try: shutil.rmtree(subs[fqdn]["docroot"]); print(OK + "Docroot deleted." + RESET)
            except Exception as e: print(ERR + f"Failed to delete docroot: {e}" + RESET)
        remove_ssl_symlinks(fqdn); subs.pop(fqdn, None); write_json(SUBS_JSON, subs)
        print(OK + "Sub-domain removed (vhost + DNS)." + RESET)
    elif opt == "d":
        uname = subs[fqdn].get("ftp_user")
        if not uname: print(ERR + "No FTP user recorded for this sub-domain." + RESET)
        else:
            newpwd = gen_password(); set_user_password(uname, newpwd)
            print(OK + f"Password reset for {uname}" + RESET); print(WARN + f"New password (shown once): {newpwd}" + RESET)
    else: print("Cancelled.")
    box_end()

def subdomain_status(cfg: Dict[str, Any], subs: Dict[str, Any]):
    def check_one(name: str):
        status = {}
        try: status["dns"] = socket.gethostbyname(name)
        except Exception: status["dns"] = "unresolvable"
        status["cert_expires"] = cert_expires_on(name) or "no cert"
        with open(VHOSTS_CONF,"r") as f: txt = f.read()
        status["vhost_http"] = bool(re.search(rf"# --- BEGIN {re.escape(name)} ---", txt))
        status["vhost_ssl"] = bool(re.search(rf"# --- BEGIN SSL {re.escape(name)} ---", txt))
        return status
    all_domains = [cfg.get("main_domain")] if cfg.get("main_domain") else []; all_domains += sorted(subs.keys())
    box_title("Status")
    if not all_domains: print("(nothing configured yet)"); box_end(); return
    for d in all_domains:
        st = check_one(d)
        print(f"{BOLD}{d}{RESET}:"); print(f"  DNS A: {st['dns']}"); print(f"  Cert expires: {st['cert_expires']}"); print(f"  vhost http: {st['vhost_http']}  ssl: {st['vhost_ssl']}"); hr()
    box_end()

def main_menu(cfg: Dict[str, Any], subs: Dict[str, Any], env: Dict[str, str]):
    while True:
        box_title("XAMPP Domain Manager")
        print("1  Add Sub-Domain"); print("2  List Sub-Domains"); print("3  Manage Sub-Domains"); print("4  Sub-Domain Status"); print("q  Exit"); box_end()
        choice = input("> ").strip().lower()
        if choice == "1": add_subdomain(cfg, subs, env)
        elif choice == "2": list_subdomains(subs)
        elif choice == "3": manage_subdomains(cfg, subs, env)
        elif choice == "4": subdomain_status(cfg, subs, env)
        elif choice == "q": print("Goodbye."); break
        else: print("Unknown choice.")

def sanity_checks():
    if not os.path.exists(LAMPP): print(f"{LAMPP} not found. Is XAMPP installed?", file=sys.stderr); sys.exit(1)
    if not os.path.exists(HTTPD_CONF): print(f"{HTTPD_CONF} not found. Unexpected XAMPP layout.", file=sys.stderr); sys.exit(1)

if __name__ == "__main__":
    require_root(); ensure_dirs(); sanity_checks(); one_time_prep()
    env_file = load_env()
    if "CF_API_TOKEN" not in env_file or not env_file["CF_API_TOKEN"]: env_file = prompt_env_and_save(env_file)
    cfg = read_json(CONFIG_JSON, {}); subs = read_json(SUBS_JSON, {})
    if not cfg.get("main_domain"): first_time_setup(cfg, subs, env_file)
    main_menu(cfg, subs, env_file)
