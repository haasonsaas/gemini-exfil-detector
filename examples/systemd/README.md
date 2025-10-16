# Systemd Deployment

Deploy Gemini Exfil Detector as a systemd service with timer (Linux).

## Installation

```bash
# Copy files to systemd directory
sudo cp gemini-exfil-detector.service /etc/systemd/system/
sudo cp gemini-exfil-detector.timer /etc/systemd/system/

# Create service user
sudo useradd -r -s /bin/false gemini-detector

# Create directories
sudo mkdir -p /opt/gemini-exfil-detector
sudo mkdir -p /var/lib/gemini-exfil-detector
sudo chown gemini-detector:gemini-detector /var/lib/gemini-exfil-detector

# Copy project files
sudo cp -r ../../src /opt/gemini-exfil-detector/
sudo cp -r ../../config /opt/gemini-exfil-detector/
sudo cp ../../requirements.txt /opt/gemini-exfil-detector/

# Setup virtualenv
cd /opt/gemini-exfil-detector
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt

# Set permissions
sudo chown -R gemini-detector:gemini-detector /opt/gemini-exfil-detector

# Reload systemd
sudo systemctl daemon-reload

# Enable and start timer
sudo systemctl enable gemini-exfil-detector.timer
sudo systemctl start gemini-exfil-detector.timer
```

## Management

```bash
# Check timer status
sudo systemctl status gemini-exfil-detector.timer

# Check service status
sudo systemctl status gemini-exfil-detector.service

# View logs
sudo journalctl -u gemini-exfil-detector.service -f

# Manual run
sudo systemctl start gemini-exfil-detector.service

# Stop timer
sudo systemctl stop gemini-exfil-detector.timer

# Disable
sudo systemctl disable gemini-exfil-detector.timer
```

## Configuration

Edit `/opt/gemini-exfil-detector/config/config.json` with your settings.

Restart timer after configuration changes:
```bash
sudo systemctl restart gemini-exfil-detector.timer
```
