import argparse
from distutils.command.config import config

# sample_config traces /var/log/syslog
sample_config = "config.txt"

try:
    if open("/usr/local/etc/filemonitor/config.txt"):
        sample_config = "/usr/local/etc/filemonitor/config.txt"
except:
    pass

examples = """
Example:
    ./filemonitor -r                         # traces read of /var/log/syslog
    ./filemonitor -f /path/to/config         # traces filepaths in path for all events
    ./filemonitor -f /path/to/config -d      # traces filepaths in path for delete events
"""
parser = argparse.ArgumentParser(
    description="Monitors file actions",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-f", "--file", default=sample_config, help="give config filepath")
parser.add_argument("-r", "--read", action="store_true", help="trace read events")
parser.add_argument("-w", "--write", action="store_true", help="trace write events")
parser.add_argument("-p", "--rename", action="store_true", help="trace rename events")
parser.add_argument("-c", "--create", action="store_true", help="trace create events")
parser.add_argument("-d", "--delete", action="store_true", help="trace delete events")

def noflags(args):
    if(args.read or args.write or args.rename or args.create or args.delete):
        return False
    return True