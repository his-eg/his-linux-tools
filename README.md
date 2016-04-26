# his-linux-tools
Scripts for Linux based systems


## listsecissues.py

Lists known security issue for the ubuntu packages installed on the system.

Simple Usage: `python listsecissues.py > out.html`

To analyse a copy of `/var/lib/dpkg/status` from another system named example-status use: `python listsecissues.py example-status > out.html`

