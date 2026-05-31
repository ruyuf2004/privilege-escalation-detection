#!/usr/bin/env python3
"""
Unified Privilege Escalation Detection System
MITRE ATT&CK Framework - 13 Privilege Escalation Techniques

Author: ruyuf2004
Date: 2026-05-31
"""

import os
import sys
import psutil
import subprocess
import logging
import yaml
import time
import re
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Set
import signal

# Setup logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{log_dir}/detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

alert_logger = logging.getLogger('alerts')
alert_handler = logging.FileHandler(f'{log_dir}/alerts.log')
alert_handler.setFormatter(logging.Formatter('%(asctime)s - ALERT - %(message)s'))
alert_logger.addHandler(alert_handler)
alert_logger.setLevel(logging.WARNING)


class PrivilegeEscalationDetector:
    """
    Unified detector for all 13 MITRE ATT&CK privilege escalation techniques
    """
    
    def __init__(self, config_file='config/detection_rules.yaml'):
        self.config = self.load_config(config_file)
        self.detections = defaultdict(list)
        self.process_cache = {}
        self.file_cache = {}
        self.suspicious_patterns = self._init_patterns()
        self.baseline = self._get_baseline()
        logger.info("[*] Privilege Escalation Detector Initialized")
        logger.info("[*] Monitoring 13 MITRE ATT&CK Privilege Escalation Techniques")
    
    def load_config(self, config_file: str) -> Dict:
        """Load YAML configuration file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def _init_patterns(self) -> Dict:
        """Initialize suspicious patterns for each technique"""
        return {
            'T1548': {
                'name': 'Abuse Elevation Control Mechanism',
                'patterns': [
                    r'sudo.*NOPASSWD',
                    r'sudo\s+-u\s+root',
                    r'pkexec',
                    r'polkit',
                    r'UAC.*bypass',
                ]
            },
            'T1134': {
                'name': 'Access Token Manipulation',
                'patterns': [
                    r'TOKEN',
                    r'ImpersonateLoggedOnUser',
                    r'DuplicateTokenEx',
                    r'CreateProcessWithTokenW',
                ]
            },
            'T1547': {
                'name': 'Boot or Logon Autostart Execution',
                'patterns': [
                    r'/etc/rc.local',
                    r'/etc/init.d/',
                    r'cron',
                    r'systemd.*service',
                    r'~/.bashrc',
                    r'~/.bash_profile',
                ]
            },
            'T1543': {
                'name': 'Create or Modify System Process',
                'patterns': [
                    r'systemctl.*create',
                    r'/etc/systemd/system/',
                    r'service.*create',
                    r'/etc/init.d/',
                ]
            },
            'T1556': {
                'name': 'Modify Authentication Process',
                'patterns': [
                    r'/etc/pam.d/',
                    r'/etc/nsswitch.conf',
                    r'~/.ssh/authorized_keys',
                    r'/etc/sudoers',
                ]
            },
            'T1068': {
                'name': 'Exploitation for Privilege Escalation',
                'patterns': [
                    r'CVE-\d{4}-\d{4,5}',
                    r'Segmentation fault',
                    r'kernel.*panic',
                    r'SIGSEGV',
                ]
            },
            'T1574': {
                'name': 'Hijack Execution Flow',
                'patterns': [
                    r'LD_PRELOAD',
                    r'LD_LIBRARY_PATH',
                    r'RPATH',
                    r'RUNPATH',
                ]
            },
            'T1070': {
                'name': 'Impersonate User/Process',
                'patterns': [
                    r'su\s+',
                    r'sudo\s+-u',
                    r'setuid',
                    r'seteuid',
                ]
            },
            'T1547.014': {
                'name': 'Modify Authentication Process (API Hooking)',
                'patterns': [
                    r'hook.*auth',
                    r'LD_PRELOAD.*auth',
                    r'dlopen.*auth',
                ]
            },
            'T1574.008': {
                'name': 'Library Search Order Hijacking',
                'patterns': [
                    r'./libc.so',
                    r'./lib.*\.so',
                    r'current.*dir.*library',
                ]
            },
            'T1053': {
                'name': 'Scheduled Task/Job',
                'patterns': [
                    r'crontab',
                    r'/etc/cron',
                    r'systemd-timer',
                    r'at\s+',
                ]
            },
            'T1543.003': {
                'name': 'Create or Modify System Process (Service)',
                'patterns': [
                    r'sc\.exe',
                    r'HKLM.*Services',
                    r'driver.*install',
                ]
            },
            'T1548.003': {
                'name': 'Sudo and Sudo Caching',
                'patterns': [
                    r'sudo.*-l',
                    r'sudoedit',
                    r'timestamp',
                    r'SUDO_ASKPASS',
                ]
            }
        }
    
    def _get_baseline(self) -> Dict:
        """Get baseline system state"""
        baseline = {
            'processes': set(p.info['pid'] for p in psutil.process_iter(['pid'])),
            'users': set(psutil.users()),
        }
        return baseline
    
    def detect(self) -> None:
        """Main detection loop"""
        logger.info("[+] Starting unified detection engine...")
        try:
            while True:
                self._monitor_processes()
                self._monitor_filesystem()
                self._monitor_network()
                self._monitor_authentication()
                self._monitor_system_calls()
                time.sleep(self.config.get('detection', {}).get('check_interval', 1))
        except KeyboardInterrupt:
            logger.info("[!] Detector stopped by user")
            sys.exit(0)
    
    def _monitor_processes(self) -> None:
        """Monitor running processes for suspicious activities"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'uids', 'status']):
                try:
                    info = proc.info
                    cmdline = ' '.join(info['cmdline'] or [])
                    
                    # T1548 - Abuse Elevation Control Mechanism
                    if self._check_pattern(cmdline, 'T1548'):
                        self._alert("T1548", f"Elevation control abuse detected: {cmdline}", proc.pid, info.get('uids').real)
                    
                    # T1070 - Impersonate User/Process
                    if self._check_pattern(cmdline, 'T1070'):
                        self._alert("T1070", f"User impersonation detected: {cmdline}", proc.pid, info.get('uids').real)
                    
                    # T1548.003 - Sudo and Sudo Caching
                    if self._check_pattern(cmdline, 'T1548.003'):
                        self._alert("T1548.003", f"Sudo caching abuse detected: {cmdline}", proc.pid, info.get('uids').real)
                    
                    # T1134 - Access Token Manipulation
                    if self._check_pattern(cmdline, 'T1134'):
                        self._alert("T1134", f"Token manipulation detected: {cmdline}", proc.pid, info.get('uids').real)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f"Process monitoring error: {e}")
    
    def _monitor_filesystem(self) -> None:
        """Monitor filesystem for suspicious modifications"""
        suspicious_files = [
            '/etc/rc.local',
            '/etc/init.d/',
            '/etc/systemd/system/',
            '/etc/pam.d/',
            '/etc/sudoers',
            '/var/spool/cron/',
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.bash_profile'),
            os.path.expanduser('~/.ssh/authorized_keys'),
        ]
        
        for filepath in suspicious_files:
            if not os.path.exists(filepath):
                continue
            
            try:
                stat_info = os.stat(filepath)
                current_time = time.time()
                
                # Check if file was recently modified (within last minute)
                if current_time - stat_info.st_mtime < 60:
                    if filepath.endswith('.bashrc') or filepath.endswith('authorized_keys'):
                        if 'bashrc' in filepath:
                            self._alert("T1547", f"RC file modification detected: {filepath}", os.getpid(), os.getuid())
                        else:
                            self._alert("T1556", f"SSH key modification detected: {filepath}", os.getpid(), os.getuid())
                    
                    elif 'sudoers' in filepath:
                        self._alert("T1556", f"Sudoers file modified: {filepath}", os.getpid(), os.getuid())
                    
                    elif 'cron' in filepath:
                        self._alert("T1053", f"Cron job modification detected: {filepath}", os.getpid(), os.getuid())
                    
                    elif 'systemd' in filepath or 'init.d' in filepath:
                        self._alert("T1543", f"System process modification: {filepath}", os.getpid(), os.getuid())
            except (OSError, PermissionError):
                pass
    
    def _monitor_network(self) -> None:
        """Monitor network connections for suspicious patterns"""
        try:
            connections = psutil.net_connections()
            for conn in connections:
                # Look for suspicious remote connections
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Could indicate C2 communication during privilege escalation
                    pass
        except (psutil.AccessDenied, OSError):
            pass
    
    def _monitor_authentication(self) -> None:
        """Monitor authentication logs"""
        try:
            if os.path.exists('/var/log/auth.log'):
                with open('/var/log/auth.log', 'r') as f:
                    lines = f.readlines()[-10:]  # Last 10 lines
                    for line in lines:
                        # T1070 - Impersonate User
                        if 'su[' in line or 'sudo' in line:
                            if 'incorrect password' in line.lower():
                                self._alert("T1070", f"User impersonation attempt: {line.strip()}", os.getpid(), os.getuid())
                        
                        # T1548 - Elevation attempt
                        if 'sudo' in line and 'root' in line:
                            self._alert("T1548", f"Privilege escalation attempt: {line.strip()}", os.getpid(), os.getuid())
        except (OSError, PermissionError):
            pass
    
    def _monitor_system_calls(self) -> None:
        """Monitor system calls for suspicious patterns"""
        try:
            # T1068 - Exploitation detection (look for segfaults, kernel issues)
            with open('/var/log/syslog', 'r') as f:
                lines = f.readlines()[-5:]
                for line in lines:
                    if 'segfault' in line.lower() or 'kernel' in line.lower():
                        self._alert("T1068", f"Potential exploitation detected: {line.strip()}", os.getpid(), os.getuid())
        except (OSError, PermissionError):
            pass
    
    def _check_pattern(self, text: str, technique: str) -> bool:
        """Check if text matches suspicious patterns for a technique"""
        if technique not in self.suspicious_patterns:
            return False
        
        patterns = self.suspicious_patterns[technique]['patterns']
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _alert(self, technique: str, message: str, pid: int, uid: int) -> None:
        """Generate alert for detected technique"""
        alert_msg = {
            'timestamp': datetime.now().isoformat(),
            'technique': technique,
            'technique_name': self.suspicious_patterns.get(technique, {}).get('name', 'Unknown'),
            'message': message,
            'process_id': pid,
            'user_id': uid,
            'severity': 'HIGH'
        }
        
        alert_logger.warning(json.dumps(alert_msg))
        logger.warning(f"[ALERT] {technique} - {message}")
        
        self.detections[technique].append({
            'timestamp': datetime.now(),
            'message': message,
            'pid': pid,
            'uid': uid
        })
    
    def print_summary(self) -> None:
        """Print detection summary"""
        logger.info("\n" + "="*60)
        logger.info("PRIVILEGE ESCALATION DETECTION SUMMARY")
        logger.info("="*60)
        for technique, events in self.detections.items():
            logger.info(f"{technique}: {len(events)} detections")
        logger.info("="*60 + "\n")


def signal_handler(sig, frame):
    """Handle graceful shutdown"""
    logger.info("[!] Shutting down detector...")
    sys.exit(0)


def main():
    """Main entry point"""
    if os.geteuid() != 0:
        logger.error("[!] This detector requires root privileges to run")
        logger.error("[!] Usage: sudo python3 detector.py")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    detector = PrivilegeEscalationDetector()
    try:
        detector.detect()
    except Exception as e:
        logger.error(f"Detector error: {e}")
        sys.exit(1)
    finally:
        detector.print_summary()


if __name__ == "__main__":
    main()
