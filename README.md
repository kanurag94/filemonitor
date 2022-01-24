# filemonitor

ebpf based Filemonitoring

```
usage: filemonitor.py [-h] [-f FILE] [-r] [-w] [-p] [-c] [-d]

Monitors file actions

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  give config filepath
  -r, --read            trace read events
  -w, --write           trace write events
  -p, --rename          trace rename events
  -c, --create          trace create events
  -d, --delete          trace delete events

Example:
    ./filemonitor -r                         # traces read of /var/log/syslog
    ./filemonitor -f /path/to/config         # traces filepaths in path for all events
    ./filemonitor -f /path/to/config -d      # traces filepaths in path for delete events
```
