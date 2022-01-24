#!/usr/bin/python

from __future__ import print_function
import json
from bcc import BPF
from ctypes import c_uint32

import sys
import subprocess

sys.path.append('/usr/local/etc/filemonitor/cli.py')
import cli

BPF_C_PROG = "filemonitor.c"

# initialize global variables
def init():
    global BPF_C_PROG
    try:
        if(open("/usr/local/etc/filemonitor/filemonitor.c")):
            BPF_C_PROG = "/usr/local/etc/filemonitor/filemonitor.c"
    except:
        pass

# update_inodemap function takes BPFHASH inodemap, config file as arguments
# reads config file, finds the inode and updates inodemap
def update_inodemap(inodemap, config_file):
    if not config_file:
        raise FileNotFoundError

    file = open(config_file, 'r')
    filepaths = file.readlines()
    for filepath in filepaths:
        inode_id = get_inode_from_filepath(filepath.strip())
        if inode_id != "":
            inodemap[c_uint32(int(inode_id))] = c_uint32(int(inode_id))

# main function reads args and attaches bpf program
# prints output of bpf events
def main():
    args = cli.parser.parse_args()
    noflags = cli.noflags(args)

    try:
        # initialize bpf program
        global BPF_C_PROG
        b = BPF(src_file = BPF_C_PROG)

        # update inodemap
        update_inodemap(b["inodemap"], args.file)

        # attach probes
        if noflags or args.read:
            b.attach_kprobe(event="vfs_read", fn_name="trace_read")
        if noflags or args.write:
            b.attach_kprobe(event="vfs_write", fn_name="trace_write")
        if noflags or args.rename:
            b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")
        if noflags or args.create:
            b.attach_kprobe(event="security_inode_create", fn_name="trace_create")
        if noflags or args.delete:
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

# get_inode_from_filepath takes a filepath as argument
# and returns inode associated with that file path
def get_inode_from_filepath(filepath):
  cmd = f'ls {filepath} 2>&1 1>/dev/null && ls -i {filepath}'
  cmd += ' | awk \'{print $1}\''
  try:
    output = subprocess.check_output(cmd, shell=True)
    output = output.decode()
    return output.split('\n')[0]
  except:
      return ""

# starts program
if __name__ == "__main__":
    init()
    main()