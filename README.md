# Network-Traffic-Analysis-Using-Snort-and-Splunk

## Overview
This project simulates a real-world attack scenario where an Ubuntu attacker performs an SSH brute-force attack against a Windows victim machine. Network traffic is monitored using Snort, and logs are analyzed in Splunk to detect malicious activity and identify Indicators of Compromise (IOCs).

---

## Lab Environment
- **Attacker:** Ubuntu VM  
- **Victim:** Windows 11 Host  
- **Monitoring Tool:** Snort (IDS/IPS)  
- **Log Analysis:** Splunk  
- **Network:** Same subnet (VirtualBox NAT)

---

## Attack Simulation
Steps performed in the lab:
1. Configure Snort rules to detect ICMP and SSH traffic.
2. Launch brute-force attack using Hydra.
3. Detect attack attempts via Snort alerts.
4. Analyze Windows log data in Splunk.
5. Identify attacker behavior and timeline.

---

## Detection Highlights
- Multiple failed logins followed by success
- Encoded PowerShell execution
- Suspicious command activity
- File access and staging
- Outbound connection to attacker IP

---

## Skills Demonstrated
- IDS rule creation
- Network traffic monitoring
- Log analysis
- Incident investigation
- IOC identification
- Basic SOC workflow

---

## Disclaimer
This lab is for **educational and defensive security training purposes only**. Do not perform these techniques on systems without permission.
