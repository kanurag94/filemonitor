#!/usr/bin/env bash

all:
	@echo "\033[92minstalling required packages not including python3\033[0m"
	sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
	@echo "\033[92mcopying files to /usr/local/etc/filemonitor\033[0m"
	mkdir -p /usr/local/etc/filemonitor
	sudo cp $(PWD)/config.txt /usr/local/etc/filemonitor/config.txt
	sudo cp $(PWD)/cli.py /usr/local/etc/filemonitor/cli.py
	sudo cp $(PWD)/filemonitor.c /usr/local/etc/filemonitor/filemonitor.c
	sudo cp $(PWD)/filemonitor.py /usr/local/etc/filemonitor/filemonitor.py
	sudo cp $(PWD)/run.sh /usr/local/bin/filemonitor
	sudo chmod 755 /usr/local/bin/filemonitor
	@echo "\033[92mInstall Success:\n\033[0m Usage: filemonitor\n NOTE: Use sudo when required"