# SOUL.PY - DEPLOYMENT GUIDE

## 🚀 Quick Deployment on Ubuntu VPS

### Step 1: Clone the Repository
```bash
git clone https://github.com/vikrant-project/info.git
cd info
```

### Step 2: Install Python Dependencies
```bash
# Ensure Python 3.8+ is installed
python3 --version

# Install pip if not already installed
sudo apt update
sudo apt install python3-pip -y

# Install required packages
pip3 install -r requirements.txt
```

### Step 3: Run SOUL.PY
```bash
# Direct execution
python3 soul.py
```

The application will start on `http://0.0.0.0:9090`

### Step 4: Access the Application
Open your browser and navigate to:
- Local: `http://localhost:9090`
- Remote: `http://YOUR_VPS_IP:9090`

---

## 🔒 Production Deployment (systemd service)

### Create a systemd service file:
```bash
sudo nano /etc/systemd/system/soul.service
```

### Add the following content:
```ini
[Unit]
Description=SOUL.PY Elite Security Audit Platform
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/info
ExecStart=/usr/bin/python3 /path/to/info/soul.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable soul.service
sudo systemctl start soul.service
sudo systemctl status soul.service
```

---

## 🌐 Nginx Reverse Proxy (Optional)

### Install Nginx:
```bash
sudo apt install nginx -y
```

### Create Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/soul
```

### Add this configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/soul /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🔥 Firewall Configuration

### Allow port 9090:
```bash
sudo ufw allow 9090/tcp
sudo ufw reload
```

---

## 📊 Database Location

The SQLite database `soul.sql` is automatically created in the same directory as `soul.py`.

To view audit history:
```bash
sqlite3 soul.sql "SELECT * FROM security_audits;"
```

---

## 🛠️ Troubleshooting

### Check if the service is running:
```bash
sudo systemctl status soul.service
```

### View logs:
```bash
sudo journalctl -u soul.service -f
```

### Check port usage:
```bash
sudo netstat -tulpn | grep 9090
```

---

## 📦 File Structure

```
info/
├── soul.py              # Main application (single file)
├── requirements.txt     # Python dependencies
├── README.md           # Project documentation
└── soul.sql            # SQLite database (auto-created)
```

---

## 🎯 Key Features Checklist

✅ Single-file architecture (soul.py)
✅ FastAPI + Uvicorn server on 0.0.0.0:9090
✅ SQLite database with auto-creation
✅ Async URL scanning
✅ Hyper-Modern Dark UI with glassmorphism
✅ Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
✅ SSL/TLS configuration checks
✅ CVE and OWASP vulnerability cross-reference
✅ Threat intelligence integration
✅ Security scoring (0-100)
✅ Actionable recommendations

---

## 🔐 Security Note

**IMPORTANT**: The GitHub token in your deployment should be revoked immediately after use and replaced with SSH keys or GitHub Actions for future updates.

---

## 📞 Support

For issues or questions, check the application logs or database entries.

**Repository**: https://github.com/vikrant-project/info (Private)
