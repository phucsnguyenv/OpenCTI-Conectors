# OpenCTI-Connector 

## Introduction
This is only personal projects. If you are develop the same connector, just save time and use it. 
It was developed to used with `OpenCTII 3.0.3`

Check out my code on github and let me know if there are any problems. 

## Changed logs
### v1.4.1
- update `internal-import` v1.3.5
  + fix bug while archiving file that already exist in the `archive` folder

### v1.4.0
- Add new connector `virustotal-reference`
  + This connector will add link search on virustotal to obervable as external reference.

### v1.3.4
- Interval_scan time can be change from docker-compose.yml for `internal-import` connector

### v1.3.3
- Modified Docker file

### v1.3.2
- Add readme file for each connector
- Fix some smal bugs

### v1.3.1
- fix bugs `internal-import`

### v1.3.0
- Add feature `internal-import`
  + Add Virustotal, Threatcrowd as external refrences to created observable
- Fix bugs on `internal-import`
  + Observables and Indicators is now added to report

### v1.2.0
- Add feature `talosip`
  + Add Virustotal, Threatcrowd as external refrences to created observable

### v1.1.0
- Adding `internal-import` connector

### v1.0.0
- Init release `talosip` connector - the TalosIntelligence IPv4 blacklist importing
