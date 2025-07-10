# FUTURE_CS_02

# SECURITY ALERT MONITORING & INCIDENT RESPONSE

# 📌 About the Project

It simulates the day-to-day tasks of a Security Operations Center (SOC) analyst. The main goal is to monitor security alerts, analyze suspicious activities, and draft incident response actions to help an organization stay secure against cyber threats.

# ✅ Tasks Performed

- **Set up a SIEM Tool:** Splunk Free Trial used to ingest, parse, and analyze log data.
- **Prepared & Uploaded Logs:** Created and uploaded simulated logs (`auth.log`, `network.log`, `malware.log`, `firewall.log`).
- **Analyzed Security Alerts:** Ran SPL (Search Processing Language) queries to detect suspicious activities.
- **Classified Incidents:** Categorized alerts by severity (High, Medium, Low) for triage.
- **Created Visual Dashboards:** Built Splunk dashboards to visualize alerts and trends.
- **Drafted Incident Response:** Prepared a detailed Incident Response Report with evidence, impact, and remediation suggestions.

# SOC Alert Monitoring & Incident Response Simulation

## 📌 Project Objective

The main goal is to monitor security alerts, analyze suspicious activities, and draft incident response actions to help an organization stay secure against cyber threats.

# Intern Details
**Name:** Dhrumi Sonani

**Role:** Cybersecurity

**Program:** Future Interns - Cybersecurity Internship

**Task:**  Security Alert Monitoring & Incident Response


## ✅ Tasks Performed

- **Set up a SIEM Tool:** Splunk Free Trial used to ingest, parse, and analyze log data.
- **Prepared & Uploaded Logs:** Created and uploaded simulated logs (`auth.log`, `network.log`, `malware.log`, `firewall.log`).
- **Analyzed Security Alerts:** Ran SPL (Search Processing Language) queries to detect suspicious activities.
- **Classified Incidents:** Categorized alerts by severity (High, Medium, Low) for triage.
- **Created Visual Dashboards:** Built Splunk dashboards to visualize alerts and trends.
- **Drafted Incident Response:** Prepared a detailed Incident Response Report with evidence, impact, and remediation suggestions.


## 🛠️ Tools Used

- **Splunk Enterprise (Free Trial)** — SIEM for log ingestion, analysis, and dashboards.
- **Sample Logs** — Auth logs, network logs, malware logs, firewall logs.
- **Google Docs / MS Word** — For drafting the incident response report.


# 📁 Log Files Included

| Log File | Description |
|----------------|-------------------------------------------|
| `auth.log` | Authentication attempts (login success/fail) |
| `network.log` | Network connections (source/destination IPs, ports) |
| `malware.log` | Malware detection alerts (threat type, severity) |
| `firewall.log` | Firewall actions (allowed/blocked connections) |



## 🔍 Example  Queries Used

# Filter by Source Type
index=soc_index sourcetype="auth_logs"

# Find failed logins
index=soc_index sourcetype="auth_logs" status=failed

# Brute force attempts from same IP
index=soc_index sourcetype="auth_logs" status=failed 
| stats count by user, ip | where count >= 3

# Try filtering for unusual ports:
index=soc_index sourcetype="network_logs" dest_port=4444

# High & Critical Malware Alerts
index=soc_index sourcetype="malware_logs" severity=High OR severity=Critical

# Blocked connections by source IP
index=soc_index sourcetype="firewall_logs" action=Blocked 

# External Authentication Attempts
index=soc_index sourcetype="auth.logs" 
| search NOT ip="192.168.*"

# Frequent Firewall Blocks
index=soc_index sourcetype="firewall_logs" action=Blocked
| stats count by src_ip
| sort – count

# Failed Logins by User
index=soc_index sourcetype="auth_logs" status=failed 
| stats count by user


# Failed Malware Remediation
index=soc_index sourcetype="malware_logs" status=Failed

# Unusual Network Port
index=soc_index sourcetype="network_logs" NOT dest_port=22 NOT dest_port=80 NOT dest_port=443

# Classify Alerts
•  IP, user, host
•  Description (e.g., brute force, malware)
•  Priority (High, Medium, Low)

Incident ID	Description         Source Type	      Host/IP	          Priority	      Action
INC001	Multiple failed logins	auth_logs	       203.0.113.5	      High	          Block IP, reset password
INC002	Ransomware detected	    malware_logs	   PC-45	            Critical	      Isolate, clean, patch
INC003	Suspicious port used	  network_logs	   192.168.1.20	      Medium	        Investigate



# 🚩 How to Run This Project

Install Splunk (free trial) locally or on a VM.
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/45d10026ea255490af568c4b89023c9328c0cfe9/Screenshots/s1.png)

Upload sample log files via Settings > Add Data > Upload.
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/s2.png)
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/s3.png)

Create an index, e.g., soc_index.

Use Search & Reporting to test your SPL queries.
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/s9.png)
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/t1.png)
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/t2.png)
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/t3.png)

Save searches as Dashboard Panels to visualize results.
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/t4.png)

Monitor and analyze alerts from the dashboard.
![image alt](https://github.com/dhrumi06/FUTURE_CS_02/blob/9e3436304f8fc378991d1e8422978e2aff9fd9b0/Screenshots/t5.png)


## Future Enhancements  
• Automate log ingestion using forwarders.  
• Add real-time alert notifications with emails or Slack integration.  
• Integrate threat intelligence feeds to correlate IOCs.  
• Implement playbooks for automated incident response actions.  
• Improve dashboards with geo-location mapping and advanced visualizations.  
• Expand to additional log sources (Windows Event Logs, Cloud Logs).  
