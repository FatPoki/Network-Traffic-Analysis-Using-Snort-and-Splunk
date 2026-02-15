
---

## Summary

**This lab demonstrates how to create a vulnerable Windows machine and configure its network on the same subnet so that we can analyze its network activity using Snort and review logs using Splunk.**  
**In this scenario, the attacker machine is running Ubuntu OS and the victim machine is running Windows 11 OS. We will configure Snort on the Ubuntu system within the same subnet as the Windows machine so that we can monitor network alerts. Then, we will analyze those logs using Splunk and create Indicators of Compromise (IOCs) based on the detected attack.**

---
## Objective

**To demonstrate the working of Snort (IDS/IPS) and Splunk (a log analysis platform) through a practical lab with real examples.**

---

## Prerequisite

**My Ubuntu is running in Virtual Box and its network configuration is set to NAT (Network Address Translation). For the victim machine, I created a new domain on my host machine just for this lab purpose and configured its firewall with some custom inbound rules. We need to allow SSH on port 22 from Windows and select NAT in VirtualBox (see attachment for reference).**

#### Reference

![[ss.png]]

---

## Ubuntu

### Step 1

![[Screenshot from 2026-02-13 00-49-22.png]]

**To install Snort and other tools, use the following commands:**

```
sudo apt install snort -y
sudo apt install hydra -y
sudo apt install ssh -y
```

**This will install tools like Snort, Hydra, and SSH.**

---

### Step 2

**Configuring rules in Snort initially to detect pings**

**Our rule will be:**

```
alert icmp any any -> any any (msg:"ICMP ping detected"; sid:1000001; rev:1;)

# any any : source IP and port 
# -> direction (arrow)
# any any : destination IP and port 
# msg : shows this message
# sid : unique ID
# rev : revision number
```

**Now, we check our config file before running Snort using the command:**

```
sudo snort -T -c /etc/snort/snort.conf
```

**If it gives output like “Snort successfully validated the configuration”, we are good to go. Otherwise, you will need to fix the config file.**

---

### Step 3

**Checking if Snort works**

In a terminal tab, run:

```
sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3
```

**Understanding the command**

- **-A** : Alert mode (console output)
    
- **-q** : Quiet mode (hides unnecessary info like banners and stats)
    
- **-c** : Config file path / rule files
    
- **-i** : Network interface name to monitor
    

---

### Step 4

**Executing Snort on the Windows host**

![[snort.png]]

**I am running Snort in quiet mode so it won’t display any banners.**

Now I will ping the Windows host from Ubuntu to check if Snort is working, as I have already added the ICMP rule in the rules file.

```
ping 192.168.56.4
```

---

### Attachment

![[icmp.png]]

We can see the alert showing that ICMP traffic is detected from **192.168.56.3 → 192.168.56.4**.  
Now I will try to brute-force SSH on the host and write a custom rule to detect it.

---

### Rule

```
alert tcp any any -> any 22 (msg:"SSH attempt detected"; sid:1000002; rev:1;)
```

I will add this rule to the **local.rules** file and execute a Hydra attack on the SSH server of my Windows host.

**Command:**

```
sudo hydra -l victim -P password.txt ssh://192.168.56.4
```

---

### Attachment

![[ssh.png]]

We can see in the attachment that the password was detected from our wordlist, and we also received the alert. Now we can set the **drop flag** so Snort blocks the requests.

> **Remember:** Snort provides packet dropping only on Linux. On Windows it can detect traffic but cannot drop it.

---

### Rule to Drop Packets

```
drop tcp any any -> any 22 (msg:"SSH attempt detected & dropped"; flags:S; sid:1000003; rev:1;)
```

---

### Steps to Drop Packets

**1. Enable IP forwarding**

```
sudo sysctl -w net.ipv4.ip_forward=1
```

**2. Send packets to Snort**

```
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

**3. Run Snort in IPS mode**

```
sudo snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf -i eth0
```

> Now if we try again, the packet will be dropped. To verify, we can check iptables and Snort using:

```
snort --daq-list
iptables -L
```

---

## Splunk

**In this scenario, we retrieved the victim system log file. Now we will use that log file in Splunk to analyze what happened and what the attacker did.**

---

**Open and log in to Splunk and upload the log file via:**  
`Settings > Add Data > Upload File > Search`

![[splunk.png]]

At this point, it is hard to determine what happened, so I will apply a filter to see what we can find. I am using:

```
EventID=* 
| table _time _raw
```

![[failed.png]]

This tells us that there was a brute-force attempt and the attacker logged in after several attempts. Upon closer inspection we find:

```
02/15/2026 02:14:20 AM Sysmon EventID=1 Process Create Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe CommandLine=powershell -enc SQBleABwAGwAbwBpAHQAIABjAG8AZABlAA==
```

**This shows a malicious command executed using the `-enc` encoding flag with a Base64 value.**

![[commands.png]]

We can see that the attacker executed an exploit in the Temp directory, gained privileged access, and obtained read access to sensitive files stored in the Documents folder. After obtaining the files, the attacker attempted to delete some files from the `/Temp` folder to hide their presence, and then the SSH session was terminated.

![[logout.png]]

---

### **Indicators of Compromise 

1.  **Attacker IP :** 192.168.56.3

#### **Authentication**

1.  Multiple failed logins (EventID 4625) from 192.168.56.3    
2.  Successful login (EventID 4624) from same IP
    
#### **Post-Exploitation Commands**

1. **cmd.exe execution**
2. **whoami**
3. **net user**
4. **systeminfo**    
#### **Data Access**

 **Access to sensitive files  :** salary.xlsx, passwords.txt
### **Attack Pattern**

- Brute force → login → recon → exploit → file access → exfiltration

---

## Conclusion of lab

**Snort and Splunk play a crucial role in the daily work of a SOC analyst or cyber security professional. With some minor configurations, they can effectively detect and drop requests and provide alerts through various methods such as console or email. This lab was designed to demonstrate the functionality and potential of Snort and Splunk, and I hope it achieved its purpose.**

---
