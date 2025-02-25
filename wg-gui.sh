#!/bin/bash
# install.sh - Installation and management of WireGuard and WebGUI

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Check if the system is Debian and version is 10 or higher
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" != "debian" ]; then
        echo "This script only supports Debian."
        exit 1
    fi
    if [ "$VERSION_ID" -lt 10 ]; then
        echo "This script requires Debian 10 or higher."
        exit 1
    fi
else
    echo "Cannot detect operating system. Exiting."
    exit 1
fi

# Check virtualization: block OpenVZ and LXC
function checkVirt() {
    virt=$(systemd-detect-virt)
    if [ "$virt" == "openvz" ]; then
        echo "OpenVZ is not supported."
        exit 1
    fi
    if [ "$virt" == "lxc" ]; then
        echo "LXC is not supported."
        exit 1
    fi
}
checkVirt

# Enable IP forwarding (temporarily and persistently)
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# Variables
WG_CONFIG="/etc/wireguard/wg0.conf"
WG_SERVICE="/etc/systemd/system/wg-quick@wg0.service"
WG_WEBGUI_SERVICE="/etc/systemd/system/wg-webgui.service"
NGINX_CONF="/etc/nginx/sites-available/wg-webgui"
INSTALL_DIR="/opt/wireguard-webgui"

# Auto-detect default network interface used for NAT
DEFAULT_NIC=$(ip route | awk '/default/ {print $5; exit}')
DEFAULT_NIC=${DEFAULT_NIC:-eth0}

# Sanity check functions
function check_subnet() {
    if [[ ! $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "Invalid subnet format. Please use format x.x.x.x/y"
        return 1
    fi
    return 0
}
function check_port() {
    if [[ ! $1 =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo "Port must be a number between 1 and 65535."
        return 1
    fi
    return 0
}
function check_ip() {
    if [[ ! $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Invalid IP format. Please use x.x.x.x"
        return 1
    fi
    return 0
}

# Function to prompt with default (editable)
ask() {
    local prompt="$1"
    local default="$2"
    local input
    read -e -i "$default" -p "$prompt " input
    echo "${input:-$default}"
}

# Function to remove the complete installation
remove_installation() {
    echo "WARNING: This will remove all services, configuration files, and the WebGUI app."
    read -p "Are you sure? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Cancelled."
        exit 0
    fi
    echo "Stopping services..."
    systemctl stop wg-quick@wg0 || true
    systemctl stop wg-webgui || true
    systemctl disable wg-quick@wg0 || true
    systemctl disable wg-webgui || true

    echo "Removing configuration files and services..."
    rm -f "$WG_CONFIG" "$WG_WEBGUI_SERVICE" "$NGINX_CONF"
    rm -rf "$INSTALL_DIR"
    rm -f /etc/nginx/sites-enabled/wg-webgui
    systemctl daemon-reload
    systemctl restart nginx || true
    echo "Installation removed."
    exit 0
}

# If services already exist, show a management menu
if [ -f "$WG_WEBGUI_SERVICE" ] || [ -f "$WG_CONFIG" ]; then
    echo "Services already installed. Please choose an option:"
    while true; do
        echo "1) Show status of services"
        echo "2) Restart WireGuard"
        echo "3) Restart WebGUI"
        echo "4) Exit"
        echo "5) Remove complete installation"
        read -p "Choice: " choice
        case "$choice" in
            1)
                systemctl status wg-quick@wg0 --no-pager
                systemctl status wg-webgui --no-pager
                ;;
            2)
                systemctl restart wg-quick@wg0
                echo "WireGuard restarted."
                ;;
            3)
                systemctl restart wg-webgui
                echo "WebGUI restarted."
                ;;
            4)
                exit 0
                ;;
            5)
                remove_installation
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
    done
fi

echo "=============================================="
echo "Welcome to the wg-gui installation!"
echo "=============================================="
echo "Starting initial configuration..."

# Prompt for tunnel parameters with defaults and sanity checks
while true; do
    TUNNEL_SUBNET=$(ask "What subnet would you like to use for your web server?:" "10.0.0.0/24")
    check_subnet "$TUNNEL_SUBNET" && break
done
while true; do
    SERVER_IP=$(ask "Public IP of your server?:" "$(curl -s ifconfig.me || echo 'YOUR_PUBLIC_IP')")
    check_ip "$SERVER_IP" && break
done
while true; do
    SERVER_PORT=$(ask "Which port should the server use?:" "51820")
    check_port "$SERVER_PORT" && break
done
while true; do
    NAT_IF=$(ask "Which network interface for NAT? (auto-detected default is '$DEFAULT_NIC'):" "$DEFAULT_NIC")
    if [[ -n "$NAT_IF" ]]; then
        break
    else
        echo "Please enter a valid network interface."
    fi
done

# Prompt for WebGUI credentials (username and password)
WEBGUI_USER=$(ask "WebGUI username?:" "admin")
WEBGUI_PASS=$(ask "WebGUI password?:" "admin")

echo "Installing required packages..."
apt update && apt upgrade -y
apt install -y wireguard iptables python3 python3-pip python3-venv nginx qrencode

echo "Configuring WireGuard..."
# Generate server keys
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

# Compute the first usable IP from the provided subnet using Python
FIRST_IP=$(python3 -c "import ipaddress; print(list(ipaddress.ip_network('$TUNNEL_SUBNET').hosts())[0])")

# Create WireGuard configuration file for wg0
mkdir -p /etc/wireguard
cat > "$WG_CONFIG" <<EOF
[Interface]
Address = ${FIRST_IP}/${TUNNEL_SUBNET#*/}
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV
# iptables rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NAT_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NAT_IF -j MASQUERADE
EOF

# Set permissions so non-root processes can read the config
chmod 644 "$WG_CONFIG"

echo "Setting up the WebGUI..."
# Create the application directory if it doesn't exist
mkdir -p "$INSTALL_DIR"
chown $SUDO_USER:$SUDO_USER "$INSTALL_DIR" 2>/dev/null || chown $USER:$USER "$INSTALL_DIR"

# Create the WebGUI application (app.py) with full logic.
# The placeholders __SERVER_IP__, __WEBGUI_USER__, __WEBGUI_PASS__ will be replaced below.
cat > "$INSTALL_DIR/app.py" <<'EOF'

# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, flash, session
import subprocess, functools, os, io, base64, ipaddress, re
import qrcode
from jinja2 import DictLoader

app = Flask(__name__)
app.secret_key = 'change_this_key'
app.config['ADMIN_USER'] = '__WEBGUI_USER__'
app.config['ADMIN_PASS'] = '__WEBGUI_PASS__'

CLIENTS_DIR = '/etc/wireguard/clients/'
if not os.path.exists(CLIENTS_DIR):
    os.makedirs(CLIENTS_DIR)
WG_CONF = '/etc/wireguard/wg0.conf'

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def generate_qr_data_uri(data):
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

def get_client_list():
    clients = []
    for filename in os.listdir(CLIENTS_DIR):
        if filename.startswith("wg0-client-") and filename.endswith(".conf"):
            name = filename.replace("wg0-client-", "").replace(".conf", "")
            clients.append(name)
    return sorted(clients)

def get_client_mapping():
    mapping = {}
    if not os.path.exists(WG_CONF):
        return mapping
    with open(WG_CONF) as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("# Client:"):
            client_name = line[len("# Client:"):].strip()
            j = i + 1
            while j < len(lines):
                if lines[j].strip().lower().startswith("publickey"):
                    client_pub = lines[j].split("=", 1)[1].strip()
                    mapping[client_name] = client_pub
                    break
                if lines[j].strip() == "":
                    break
                j += 1
            i = j
        else:
            i += 1
    return mapping

def parse_wg_show():
    try:
        output = subprocess.check_output(["sudo", "wg", "show", "wg0"]).decode()
    except Exception:
        return {}
    lines = output.strip().splitlines()
    data = {}
    current_peer = None
    for line in lines:
        line = line.strip()
        if line.startswith("peer:"):
            current_peer = line.split("peer:")[1].strip()
            data[current_peer] = {}
        elif current_peer and ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip().lower()
            value = parts[1].strip()
            data[current_peer][key] = value
    return data

def handshake_in_seconds(handshake_str):
    """
    Converte una stringa di handshake (es. "7 seconds ago", "2m", "1 hour") in secondi.
    Se il campo non è presente o non è interpretabile, ritorna None.
    """
    if not handshake_str or handshake_str.lower() == "n/a":
        return None
    handshake_str = handshake_str.strip().lower().replace("ago", "").strip()
    m = re.match(r"(\d+)\s*(seconds|second|s|minutes|minute|m|hours|hour|h)?", handshake_str)
    if m:
        num = int(m.group(1))
        unit = m.group(2)
        if not unit or unit in ["seconds", "second", "s"]:
            return num
        elif unit in ["minutes", "minute", "m"]:
            return num * 60
        elif unit in ["hours", "hour", "h"]:
            return num * 3600
    return None

def parse_transfer(transfer_str):
    """
    Converte una stringa di traffico (es. "147.41 MiB received, 218.18 MiB sent")
    in un totale espresso in MiB. Se il campo non è presente, ritorna "N/A".
    """
    if not transfer_str or transfer_str.lower() == "n/a":
        return "N/A"
    total_bytes = 0.0
    matches = re.findall(r"([\d\.]+)\s*(GiB|MiB|KiB|B)", transfer_str, re.IGNORECASE)
    for num, unit in matches:
        value = float(num)
        unit = unit.lower()
        if unit == "gib":
            total_bytes += value * 1073741824
        elif unit == "mib":
            total_bytes += value * 1048576
        elif unit == "kib":
            total_bytes += value * 1024
        else:
            total_bytes += value
    mib = total_bytes / 1048576
    return f"{mib:.2f} MiB"

def get_server_interface():
    if not os.path.exists(WG_CONF):
        return None
    with open(WG_CONF) as f:
        for line in f:
            if line.lower().startswith("address"):
                addr = line.split("=", 1)[1].strip()
                try:
                    return ipaddress.ip_interface(addr)
                except Exception:
                    return None
    return None

def get_next_client_ip():
    server_intf = get_server_interface()
    if server_intf is None:
        return None
    network = server_intf.network
    server_ip = server_intf.ip
    used_ips = set()
    for filename in os.listdir(CLIENTS_DIR):
        path = os.path.join(CLIENTS_DIR, filename)
        with open(path) as f:
            for line in f:
                if line.lower().startswith("address"):
                    ip_str = line.split("=", 1)[1].strip().split("/")[0]
                    try:
                        used_ips.add(ipaddress.ip_address(ip_str))
                    except Exception:
                        pass
                    break
    for host in network.hosts():
        if host == server_ip:
            continue
        if host not in used_ips:
            return str(host)
    return None

def get_server_public_key():
    if not os.path.exists(WG_CONF):
        return None
    server_priv = None
    with open(WG_CONF) as f:
        for line in f:
            l = line.strip()
            if l.lower().startswith("privatekey"):
                server_priv = l.split("=", 1)[1].strip()
                break
    if not server_priv:
        return None
    server_priv = server_priv.replace(" ", "")
    if len(server_priv) % 4 != 0:
        server_priv += "=" * (4 - len(server_priv) % 4)
    try:
        proc = subprocess.run(["wg", "pubkey"], input=server_priv+"\n", capture_output=True, text=True, env={"LC_ALL": "C"})
        pubkey = proc.stdout.strip()
        return pubkey if pubkey else None
    except Exception:
        return None

# ---------------------
# Template Definitions
# ---------------------
templates = {
    'base.html': """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WireGuard Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {% block extra_head %}{% endblock %}
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style> body { padding-top: 70px; } </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}">WireGuard Dashboard</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
         <li class="nav-item">
           <a class="nav-link" href="{{ url_for('new_client') }}">New Client</a>
         </li>
         <li class="nav-item">
           <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
         </li>
      </ul>
    </div>
  </div>
</nav>
<div class="container" style="margin-top:80px;">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">
      {% for message in messages %}
        <p>{{ message }}</p>
      {% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""",
    'login.html': """
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-4">
    <h2 class="mb-4">Login</h2>
    <form method="post" action="{{ url_for('login') }}">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input type="text" class="form-control" name="username" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Password</label>
        <input type="password" class="form-control" name="password" required>
      </div>
      <button type="submit" class="btn btn-primary w-100">Log In</button>
    </form>
  </div>
</div>
{% endblock %}
""",
    'index.html': """
{% extends 'base.html' %}
{% block extra_head %}
<meta http-equiv="refresh" content="5">
{% endblock %}
{% block content %}
<h1 class="mb-4">Clients Dashboard</h1>
<table class="table table-bordered table-striped">
  <thead class="table-light">
    <tr>
      <th>Client Name</th>
      <th>Public Key</th>
      <th>Endpoint</th>
      <th>Latest Handshake</th>
      <th>Transfer</th>
      <th>Status</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    {% for client in clients %}
      {% set pub = client_mapping.get(client, "N/A") %}
      {% set peer = wg_status.get(pub, {}) %}
      {% set hs = handshake_in_seconds(peer.get('latest handshake', 'N/A')) %}
      {% if hs is not none and hs <= 120 %}
         {% set online = True %}
      {% else %}
         {% set online = False %}
      {% endif %}
      <tr>
        <td>{{ client }}</td>
        <td>{{ pub }}</td>
        <td>{{ peer.get('endpoint', 'N/A') }}</td>
        <td>{{ peer.get('latest handshake', 'N/A') }}</td>
        <td>{{ parse_transfer(peer.get('transfer', 'N/A')) }}</td>
        <td>
          {% if online %}
            <span class="text-success">Connected</span>
          {% else %}
            <span class="text-danger">Disconnected</span>
          {% endif %}
        </td>
        <td>
          <a class="btn btn-sm btn-info" href="{{ url_for('client_config', client_name=client) }}">View Config</a>
          <a class="btn btn-sm btn-danger" href="{{ url_for('delete_client', client_name=client) }}">Delete</a>
        </td>
      </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
""",
    'new_client.html': """
{% extends 'base.html' %}
{% block content %}
<h1 class="mb-4">Create New Client</h1>
<form method="post" action="{{ url_for('create_client') }}">
  <div class="mb-3">
    <label class="form-label">Client Name</label>
    <input type="text" class="form-control" name="client_name" required>
  </div>
  <button type="submit" class="btn btn-primary">Create Client</button>
</form>
{% endblock %}
""",
    'client_config.html': """
{% extends 'base.html' %}
{% block content %}
<h1 class="mb-4">Configuration for {{ client_name }}</h1>
<div class="card mb-3">
  <div class="card-header">Client Config</div>
  <div class="card-body">
    <pre>{{ config }}</pre>
  </div>
</div>
<div>
  <h5>QR Code</h5>
  <img src="{{ qr }}" alt="QR Code" class="img-fluid">
</div>
<a class="btn btn-secondary mt-3" href="{{ url_for('index') }}">Back to Dashboard</a>
{% endblock %}
"""
}

app.jinja_loader = DictLoader(templates)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == app.config['ADMIN_USER'] and request.form['password'] == app.config['ADMIN_PASS']:
            session['logged_in'] = True
            session['user'] = request.form['username']
            flash("Logged in successfully!")
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials!")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    clients = get_client_list()
    wg_status = parse_wg_show()
    client_mapping = get_client_mapping()
    return render_template('index.html',
                           clients=clients,
                           wg_status=wg_status,
                           client_mapping=client_mapping,
                           handshake_in_seconds=handshake_in_seconds,
                           parse_transfer=parse_transfer)

@app.route('/new_client', methods=['GET'])
@login_required
def new_client():
    return render_template('new_client.html')

@app.route('/create_client', methods=['POST'])
@login_required
def create_client():
    client_name = request.form.get('client_name').strip()
    if not client_name:
        flash("Client name is required!")
        return redirect(url_for('new_client'))
    
    client_filename = os.path.join(CLIENTS_DIR, f"wg0-client-{client_name}.conf")
    if os.path.exists(client_filename):
        flash("Client already exists!")
        return redirect(url_for('new_client'))
    
    try:
        client_priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
        proc = subprocess.run(["wg", "pubkey"], input=client_priv, capture_output=True, text=True)
        client_pub = proc.stdout.strip()
    except Exception:
        flash("Error generating client keys.")
        return redirect(url_for('new_client'))
    
    client_ip = get_next_client_ip()
    if not client_ip:
        flash("No available IP for new client.")
        return redirect(url_for('new_client'))
    
    server_pub = get_server_public_key()
    if not server_pub:
        flash("Server public key not found.")
        return redirect(url_for('new_client'))
    server_endpoint = "__SERVER_IP__"
    server_port = None
    with open(WG_CONF) as f:
        for line in f:
            if line.lower().startswith("listenport"):
                server_port = line.split("=", 1)[1].strip()
                break
    if server_port:
        server_endpoint = f"{server_endpoint}:{server_port}"
    
    client_config = f"""[Interface]
PrivateKey = {client_priv}
Address = {client_ip}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pub}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    try:
        with open(client_filename, "w") as f:
            f.write(client_config)
    except Exception:
        flash("Error writing client config file.")
        return redirect(url_for('new_client'))
    
    peer_block = f"""

[Peer]
# Client: {client_name}
PublicKey = {client_pub}
AllowedIPs = {client_ip}/32
"""
    try:
        with open(WG_CONF, "a") as f:
            f.write(peer_block)
    except Exception:
        flash("Error updating server configuration.")
        return redirect(url_for('new_client'))
    
    try:
        subprocess.run(["sudo", "systemctl", "restart", "wg-quick@wg0"], check=True)
    except Exception:
        flash("Error restarting WireGuard.")
        return redirect(url_for('new_client'))
    
    flash(f"Client '{client_name}' created successfully!")
    return redirect(url_for('client_config', client_name=client_name))

@app.route('/client/<client_name>')
@login_required
def client_config(client_name):
    client_filename = os.path.join(CLIENTS_DIR, f"wg0-client-{client_name}.conf")
    if not os.path.exists(client_filename):
        flash("Client configuration not found.")
        return redirect(url_for('index'))
    with open(client_filename) as f:
        config = f.read()
    qr_data = generate_qr_data_uri(config)
    return render_template('client_config.html', client_name=client_name, config=config, qr=qr_data)

@app.route('/delete_client/<client_name>')
@login_required
def delete_client(client_name):
    client_filename = os.path.join(CLIENTS_DIR, f"wg0-client-{client_name}.conf")
    if not os.path.exists(client_filename):
        flash("Client configuration not found.")
        return redirect(url_for('index'))
    os.remove(client_filename)
    subprocess.run(["sudo", "sed", "-i", f"/# Client: {client_name}/,+2d", WG_CONF])
    try:
        subprocess.run(["sudo", "systemctl", "restart", "wg-quick@wg0"], check=True)
    except Exception:
        flash("Error restarting WireGuard after deletion.")
        return redirect(url_for('index'))
    flash(f"Client '{client_name}' deleted successfully!")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


EOF

# Rimuove il BOM se presente e forza la codifica in UTF-8
sed -i '1s/^\xEF\xBB\xBF//' "$INSTALL_DIR/app.py"
iconv -f utf-8 -t utf-8 -c "$INSTALL_DIR/app.py" -o "$INSTALL_DIR/app.py.tmp" && mv "$INSTALL_DIR/app.py.tmp" "$INSTALL_DIR/app.py"

# Replace placeholders with actual values from the wizard
sed -i "s/__SERVER_IP__/$SERVER_IP/g" "$INSTALL_DIR/app.py"
sed -i "s/__WEBGUI_USER__/$WEBGUI_USER/g" "$INSTALL_DIR/app.py"
sed -i "s/__WEBGUI_PASS__/$WEBGUI_PASS/g" "$INSTALL_DIR/app.py"

chmod +x "$INSTALL_DIR/app.py"

echo "Creating Python virtual environment and installing dependencies..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install flask qrcode pillow

echo "Creating systemd service for the WebGUI..."
cat > "$WG_WEBGUI_SERVICE" <<EOF
[Unit]
Description=WireGuard WebGUI
After=network.target

[Service]
User=$SUDO_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "Enabling and starting services..."
systemctl daemon-reload
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0
systemctl start wg-webgui
systemctl enable wg-webgui

echo "Configuring Nginx for WebGUI proxy..."
cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $SERVER_IP;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
systemctl restart nginx

echo "Setup complete!"
echo "WebGUI credentials -> Username: $WEBGUI_USER, Password: $WEBGUI_PASS"
echo "WireGuard is running with configuration in $WG_CONFIG"
