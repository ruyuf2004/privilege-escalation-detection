#!/usr/bin/env python3
"""
Simulate privilege escalation attacks for testing detection

WARNING: Use only in authorized test environments (Kali Linux VM)
"""

import subprocess
import os
import sys
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackSimulator:
    """Simulate various privilege escalation attacks"""
    
    def __init__(self):
        if os.geteuid() != 0:
            logger.error("[!] Attack simulator requires root privileges")
            sys.exit(1)
        logger.info("[+] Attack Simulator Initialized")
    
    def simulate_T1548_sudo_abuse(self):
        """Simulate T1548 - Sudo abuse"""
        logger.info("[*] Simulating T1548 - Abuse Elevation Control Mechanism")
        try:
            subprocess.run(['sudo', '-l'], check=False, capture_output=True)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def simulate_T1547_cron_job(self):
        """Simulate T1547 - Cron job creation"""
        logger.info("[*] Simulating T1547 - Boot or Logon Autostart Execution")
        try:
            cron_cmd = "(crontab -l 2>/dev/null; echo '* * * * * /bin/echo test') | crontab -"
            subprocess.run(cron_cmd, shell=True, check=False, capture_output=True)
            time.sleep(1)
            subprocess.run("crontab -r", shell=True, check=False, capture_output=True)
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def simulate_T1556_sudoers(self):
        """Simulate T1556 - Sudoers modification"""
        logger.info("[*] Simulating T1556 - Modify Authentication Process")
        try:
            with open('/etc/sudoers', 'r') as f:
                content = f.read()
            logger.info("[*] Sudoers file accessed (not modified for safety)")
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def simulate_T1070_su_command(self):
        """Simulate T1070 - User impersonation"""
        logger.info("[*] Simulating T1070 - Impersonate User/Process")
        try:
            subprocess.run(['sudo', '-u', 'nobody', 'id'], check=False, capture_output=True)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def simulate_T1053_scheduled_task(self):
        """Simulate T1053 - Scheduled task creation"""
        logger.info("[*] Simulating T1053 - Scheduled Task/Job")
        try:
            cron_cmd = "(crontab -l 2>/dev/null; echo '0 0 * * * /bin/echo backup') | crontab -"
            subprocess.run(cron_cmd, shell=True, check=False, capture_output=True)
            time.sleep(1)
            subprocess.run("crontab -r", shell=True, check=False, capture_output=True)
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def simulate_T1543_service(self):
        """Simulate T1543 - Service creation"""
        logger.info("[*] Simulating T1543 - Create or Modify System Process")
        try:
            service_content = """[Unit]
Description=Test Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/echo test

[Install]
WantedBy=multi-user.target
"""
            logger.info("[*] Service file creation attempted (audit log generated)")
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def simulate_all_attacks(self):
        """Simulate all attack scenarios"""
        logger.info("\n" + "="*60)
        logger.info("PRIVILEGE ESCALATION ATTACK SIMULATION")
        logger.info("="*60 + "\n")
        
        self.simulate_T1548_sudo_abuse()
        time.sleep(2)
        
        self.simulate_T1547_cron_job()
        time.sleep(2)
        
        self.simulate_T1556_sudoers()
        time.sleep(2)
        
        self.simulate_T1070_su_command()
        time.sleep(2)
        
        self.simulate_T1053_scheduled_task()
        time.sleep(2)
        
        self.simulate_T1543_service()
        time.sleep(2)
        
        logger.info("\n" + "="*60)
        logger.info("SIMULATION COMPLETE")
        logger.info("="*60 + "\n")


def main():
    simulator = AttackSimulator()
    simulator.simulate_all_attacks()
    logger.info("[+] Check logs/detection.log and logs/alerts.log for detections")


if __name__ == "__main__":
    main()
