# Splunk Alert: Brute Force Followed by Success (5-minute window)

**Search**
```spl
index=security sourcetype=auth:csv (action=fail OR action=success)
| bin _time span=5m
| stats sum(eval(action="fail")) as failed sum(eval(action="success")) as success values(host) as hosts by src_ip, user, _time
| where failed>=10 AND success>=1
```

**Save As → Alert**  
- Title: Brute Force - Success Achieved (5m)  
- Schedule: Run every 5 minutes (Cron: `*/5 * * * *`)  
- Trigger condition: Number of Results > 0  
- Throttle: 30 minutes (to prevent spamming)  
- Severity: High  
- Actions: Email / Slack / Create notable event (if ES)

**Fields to include in notification:** `src_ip`, `user`, `failed`, `success`, `hosts`, `_time`

**MITRE ATT&CK:** T1110 (Brute Force)
