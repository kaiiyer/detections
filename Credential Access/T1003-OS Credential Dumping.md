# OS Credential Dumping: LSASS Memory

Language: Lucene

Product: ELK

Required: Sysmon


## Description

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material.


**Query:**
---

```
event_data.CommandLine:(mimikatz* OR mimilib* OR *eo\\.oe\\.* OR sekurlsa\:\:logonpasswords* OR *lsadump\:\:sam* OR *lsadump\:\:secrets* OR mimidrv\.sys*) OR 
message:((*comsvcs\.dll* AND MiniDump*) OR ("rdrleakdiag\.exe" AND fullmemdmp*) OR ("TTTracer\.exe" AND "dumpFull")) OR 
(event_data.OriginalFileName: "procdump" AND message: "ma") OR event_data.OriginalFileName: ("ProcessDump\.exe" OR "WriteMiniDump\.exe") OR 
((event_id:10 AND event_data.TargetImage:C\:\\*lsass\.exe AND event_data.GrantedAccess:(0x1410 OR 0x1010)) OR 
(event_data.OriginalFileName:"SqlDumper\.exe" AND event_data.GrantedAccess:0x01100*) 
AND NOT event_data.SourceImage:(*\\Windows\ Defender\\* OR *\\Suppressions\\*))
 ```
