# Windows Management Instrumentation.md

Language: Lucene

Product: ELK

Required: Sysmon


## Description

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. 

**Query:**
---

```
// WMI Lateral Movement
event_id:1 AND event_data.CommandLine:(*wmic*process*create*)
```

```
// WMI execution
event_id:1 AND event_data.Image:(*\\WmiPrvSE\.exe) AND NOT Suppressions
```
