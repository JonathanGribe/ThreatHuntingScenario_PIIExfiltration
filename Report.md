# Threat Hunt Report: PII Exfiltration

---
## Platforms and Languages Leveraged

## Scenario
Company A has recently observed indications that employees' personally identifiable information (PII) may be at risk due to a string of phishing attacks. The types of data potentially exposed include home addresses, email addresses, and phone numbers. This sensitive information is stored on a Linux server in a hidden file, accessible only to users with root or sudo privileges. A recent incident was reported in which an employee was seen tampering with a computer while the root administrator had briefly stepped away. As a result, the company has launched a formal investigation.
In this lab exercise, we’ll simulate a situation where an unauthorized user gains root access to a computer and executes a script. This script performs the following actions:

--
## High Level IoC Plan
Step 1: DeviceProcessEvents - Security team ran script to detect any instance of file script adding or modifying, script processes that can detect privilege escalations or exfiltration
Step 2: DeviceNetworkEvents - Detect evidence of exfiltration to blob storage account
Step 3: DeviceFileEvents - Created files created for the exfiltration



### Steps Taken

### Step 1 - Table 1

### Step 2 - Table 2

### Step 3 - Table 3

### Step 4 - Table 4

---

## Chronology Event Timeline

---
## Summary

---

## Response Taken
