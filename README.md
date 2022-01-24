# filemonitor

ebpf based Filemonitoring

```
usage: filemonitor.py [-h] [-f FILE]

Monitors file actions

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  give config filepath

Usage:
    ./filemonitor                       # traces /var/log/syslog
    ./filemonitor -f /path/to/config    # pass a file with new line separated filepaths to monitor 
```
