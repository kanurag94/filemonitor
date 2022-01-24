# filemonitor

ebpf based Filemonitoring

### Usage
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

### Output
```
PID    UID  CPU  PROC         FPATH                            COMM            OPRN
11351  1000 1                 test_file_12.txt                 cat             READ
11375  1000 1                 test_file_12.txt                 vi              READ
11397  1000 0                 test_file_12.txt                 vi              READ
11397  1000 0                 test_file_12.txt                 vi              WRITE
11441  1000 0                 test_file_12.txt                 mv              RENAME
11463  1000 0                 a                                rm              DELETE
```

## How to run?
1. Clone the repository `git clone https://github.com/kanurag94/filemonitor.git`
2. `cd filemonitor`
3. For debian and ubuntu: `sudo make all`
4. `filemonitor -h` to check
5. For other distributions visit: https://github.com/iovisor/bcc/blob/master/INSTALL.md and run `sudo run.sh`

## How this works?
1. A BPFHASH map keeps inode entries of the files supplied as config.
2. Listens to read, create, delete, rename, write events on the inodes.

## To fix
1. `process path` to be added
2. `user tty id` to be added
