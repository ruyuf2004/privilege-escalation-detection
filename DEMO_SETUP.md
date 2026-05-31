# Privilege Escalation Detection - Live Demonstration Guide

## 🎯 Network Setup

```
Attacker (Ubuntu)         Network Bridge         Victim (Kali)
  192.168.1.X    <----->   VMware NAT   <-----> 192.168.1.Y
  SSH Client                                    Detector Running
  Attack Tools                                  3 Monitoring Terminals
```

## 📋 Pre-Demo Checklist

### Victim Machine (Kali Linux) - 3 Terminals

**Terminal 1: Start Detector**
```bash
cd ~/privilege-escalation-detection
sudo python3 detector.py
```

**Terminal 2: Watch Detection Logs**
```bash
tail -f logs/detection.log
```

**Terminal 3: Watch Alerts**
```bash
tail -f logs/alerts.log
```

### Attacker Machine (Ubuntu)

**Find Victim IP:**
```bash
arp-scan -l | grep -i kali
# Result: 192.168.1.100 Kali Linux
```

**SSH into Victim:**
```bash
ssh user@192.168.1.100
```

## 🚀 13 Attack Demonstrations

### Attack 1: T1548 - Sudo Abuse
```bash
sudo -u root /bin/bash
```
**Alert:** `[ALERT] T1548 - Elevation control abuse detected`

### Attack 2: T1070 - User Impersonation  
```bash
su - root
```
**Alert:** `[ALERT] T1070 - User impersonation detected`

### Attack 3: T1548.003 - Sudo List
```bash
sudo -l
```
**Alert:** `[ALERT] T1548.003 - Sudo caching abuse detected`

### Attack 4: T1070 - Sudo Run As
```bash
sudo -u nobody id
```
**Alert:** `[ALERT] T1070 - Impersonation detected`

### Attack 5: T1053 - Cron Job
```bash
crontab -l
```
**Alert:** `[ALERT] T1053 - Cron modification detected`

### Attack 6: T1556 - SSH Key
```bash
echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys
```
**Alert:** `[ALERT] T1556 - SSH key modification detected`

### Attack 7: T1547 - Bashrc
```bash
echo 'export PATH=/tmp:$PATH' >> ~/.bashrc
```
**Alert:** `[ALERT] T1547 - RC file modification detected`

### Attack 8: T1574 - LD_PRELOAD
```bash
export LD_PRELOAD=/tmp/evil.so
echo $LD_PRELOAD
```
**Alert:** `[ALERT] T1574 - Hijack Execution Flow detected`

### Attack 9: T1556 - Sudoers
```bash
sudo cat /etc/sudoers
```
**Alert:** `[ALERT] T1556 - Sudoers file accessed`

### Attack 10: T1574.008 - Library Hijack
```bash
ln -s /lib/x86_64-linux-gnu/libc.so.6 ./libc.so
```
**Alert:** `[ALERT] T1574.008 - Library hijacking detected`

### Attack 11: T1547.014 - Auth Hooking
```bash
export LD_PRELOAD=/tmp/auth_hook.so
su - root
```
**Alert:** `[ALERT] T1547.014 - Auth API Hooking detected`

### Attack 12: T1134 - Token Manipulation
```bash
grep -i TOKEN /var/log/auth.log
```
**Alert:** `[ALERT] T1134 - Token manipulation detected`

### Attack 13: T1068 - Kernel Exploit
```bash
dmesg | grep -i segfault
```
**Alert:** `[ALERT] T1068 - Exploitation detected`

## ✅ SSH Configuration

### Enable SSH on Kali
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
sudo systemctl status ssh
```

### Enable SSH on Ubuntu
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
sudo systemctl status ssh
```

### Test Connection
```bash
ssh user@victim_ip
# Should connect successfully
```

## 🔄 Quick Demo Flow

1. **Start 3 terminals on Kali** - detector, detection.log, alerts.log
2. **SSH from Ubuntu** to Kali victim
3. **Execute attack** from Ubuntu terminal
4. **Watch alerts** appear in Kali terminals 2 & 3
5. **Observe** real-time detection and logging

## 📊 Expected Output

**Kali Terminal 2 (detection.log):**
```
2026-05-31 14:23:45 - WARNING - [ALERT] T1548 - Elevation control abuse detected
Process ID: 1847, User ID: 0
```

**Kali Terminal 3 (alerts.log):**
```
2026-05-31 14:23:45 - ALERT - {"technique": "T1548", "severity": "HIGH"}
```

## 🐛 Troubleshooting

**Detector not running?**
```bash
ps aux | grep detector.py
sudo python3 detector.py
```

**SSH not working?**
```bash
sudo systemctl status ssh
ssh -v user@victim_ip
```

**No detections?**
```bash
mkdir -p logs
ls -la config/detection_rules.yaml
```

## ✨ Success Indicators

✅ Detector starts without errors  
✅ Logs directory created  
✅ SSH connection established  
✅ Attack executes  
✅ Alert appears within 1-2 seconds  
✅ All 13 techniques detected  

**Demo Ready!** 🎯
