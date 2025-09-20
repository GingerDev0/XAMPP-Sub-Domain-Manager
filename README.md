# XAMPP Domain Manager

A Python-based utility for managing domains and subdomains on an XAMPP stack with automated SSL (Let's Encrypt) provisioning via Cloudflare DNS.

This script helps you:
- Configure your **main domain** and any number of **subdomains**
- Automatically issue and renew SSL certificates with Let's Encrypt using **Cloudflare DNS-01 challenge**
- Manage Apache vhosts and ProFTPD FTP access for each subdomain
- Redirect HTTP → HTTPS automatically
- Create per-subdomain FTP users with secure passwords

---

## ✨ Features

- First-time setup for your main domain with SSL + FTPS
- Add/manage subdomains (vhosts, DNS, SSL, FTP users)
- Automatically configures ProFTPD for FTPS with TLS
- Integration with Cloudflare DNS API for certificate automation
- Handles vhost cleanup and DNS removal on subdomain deletion

---

## 📋 Prerequisites

Make sure you are running this on a **Linux server** with **root privileges**.

### Required software
- **XAMPP** (installed in `/opt/lampp`)
- **Python 3.8+**
- **Certbot** (via Snap) with the Cloudflare DNS plugin
- **systemd** (for managing conflicting services like Apache and vsftpd)

### Services
- A registered domain name managed via **Cloudflare DNS**
- Cloudflare API Token with the following permissions:
  - **Zone: Read**
  - **DNS: Edit**

---

## 🔧 Installation

### 1. Install XAMPP
Download and install XAMPP from [Apache Friends](https://www.apachefriends.org/download.html). It should be installed under `/opt/lampp`.

### 2. Install prerequisites
```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python 3 and pip
sudo apt install -y python3 python3-pip

# Install Snap (if not already installed)
sudo apt install -y snapd

# Install certbot with Cloudflare DNS plugin
sudo snap install core
sudo snap refresh core
sudo snap install --classic certbot
sudo ln -sf /snap/bin/certbot /usr/bin/certbot
sudo snap set certbot trust-plugin-with-root=ok
sudo snap install certbot-dns-cloudflare
```

### 3. Clone this repository
```bash
git clone https://github.com/yourusername/xampp-domain-manager.git
cd xampp-domain-manager
```

### 4. Prepare system
Run the script once to apply one-time preparation:
```bash
sudo python3 domainmgr.py
```

This will:
- Disable system Apache and vsftpd to avoid conflicts
- Configure firewall rules (if using UFW)
- Set up ProFTPD with FTPS support
- Prepare necessary directories

---

## 🚀 Usage

### First-time setup
Run the script and follow prompts to configure your main domain:
```bash
sudo python3 domainmgr.py
```

You’ll be asked for:
- Cloudflare API token
- Public IP (auto-detect or manual)
- Main domain (e.g. `example.com`)
- Admin email for Let's Encrypt

### Add a subdomain
From the menu:
- Choose `1` → Add Sub-Domain
- Enter the subdomain prefix (e.g. `test` → `test.example.com`)
- A system FTP user will be created for that subdomain

### Manage subdomains
Options include:
- Re-issue SSL certificates
- Update DNS A record
- Remove subdomain + vhost
- Reset FTP password

---

## 📂 Directory Layout

- **Config/data:** `/opt/lampp/domainmgr/`
- **Apache vhosts:** `/opt/lampp/etc/extra/httpd-vhosts.conf`
- **Vhosts root:** `/opt/lampp/vhosts/`
- **SSL symlinks:** `/opt/lampp/ssl/live/<domain>`
- **Logs:** `/opt/lampp/logs/`

---

## ⚠️ Notes

- Must be run as **root** (`sudo`)
- Tested with XAMPP on Ubuntu/Debian
- For safety, FTP passwords are shown **once only** when created/reset — store them securely

---

## 📜 License

MIT License — feel free to use, modify, and share.
