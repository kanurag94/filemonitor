import argparse
from distutils.command.config import config

sample_config = "config.txt"

try:
    if open("/usr/local/etc/filemonitor/config.txt"):
        sample_config = "/usr/local/etc/filemonitor/config.txt"
except:
    pass

examples = """Usage:
    ./filemonitor                       # traces /var/log/syslog
    ./filemonitor -f /path/to/config    # pass a file with new line separated filepaths to monitor 
"""
parser = argparse.ArgumentParser(
    description="Monitors file actions",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-f", "--file", default=sample_config, help="give config filepath")