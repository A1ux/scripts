# CRTO Cheatsheet

## Cobalt Strike

### Run Server

```bash
c```

### Run as a Service

```bash
sudo vim /etc/systemd/system/teamserver.service

## Paste this
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reload
sudo systemctl start teamserver.service
sudo systemctl enable teamserver.service
```