#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import c_uint32

import sys
import subprocess

sys.path.append('/usr/local/etc/filemonitor/cli.py')
import cli

BPF_C_PROG = "filemonitor.c"

def init():
    global BPF_C_PROG
    try:
        if(open("/usr/local/etc/filemonitor/filemonitor.c")):
            BPF_C_PROG = "/usr/local/etc/filemonitor/filemonitor.c"
    except:
        pass

def update_inodemap(inodemap, config_file):
    if not config_file:
        raise FileNotFoundError

    file = open(config_file, 'r')
    filepaths = file.readlines()
    for filepath in filepaths:
        inode_id = get_inode_from_filepath(filepath.strip())
        if inode_id != "":
            inodemap[c_uint32(int(inode_id))] = c_uint32(int(inode_id))
          
def main():
    args = cli.parser.parse_args()

    try:
        # initialize bpf program
        global BPF_C_PROG
        b = BPF(src_file = BPF_C_PROG)

        # update inodemap
        update_inodemap(b["inodemap"], args.file)

        # attach probes
        b.attach_kprobe(event="vfs_read", fn_name="trace_read")
        b.attach_kprobe(event="vfs_write", fn_name="trace_write")
        b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")
        b.attach_kprobe(event="security_inode_create", fn_name="trace_create")
        b.attach_kprobe(event="vfs_unlink", fn_name="trace_delete")

        # header
        print("%-6s %-4s %-4s %-32s %-32s %-32s %-4s" % ("PID", "UID", "CPU", "PROC", "FPATH", "COMM", "OPRN"))

        # process event
        def print_event(cpu, data, size):
            event = b["events"].event(data)
            print("%-6d %-4d %-4d %-32s %-32s %-32s %-4s" % (event.pid, event.uid, cpu,
                event.pname.decode('utf-8', 'replace'), event.fname.decode('utf-8', 'replace'),
                event.comm.decode('utf-8', 'replace'), event.otype.decode('utf-8', 'replace')))

        b["events"].open_perf_buffer(print_event)
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit(0)
    except FileNotFoundError:
        print("Exception occured, Is filepath correct?")
    except Exception as e:
        print("Exception occured, Are you root? Is BPF installed?", e)


def get_inode_from_filepath(filepath):
  cmd = f'ls {filepath} 2>&1 1>/dev/null && ls -i {filepath}'
  cmd += ' | awk \'{print $1}\''
  try:
    output = subprocess.check_output(cmd, shell=True)
    output = output.decode()
    return output.split('\n')[0]
  except:
      return ""

if __name__ == "__main__":
    init()
    main()