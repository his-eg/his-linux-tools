#!/usr/bin/python

import httplib
import os
import re
import subprocess
import sys

try:
    from subprocess import DEVNULL # py3k
except ImportError:
    DEVNULL = open(os.devnull, 'wb')



class SecurityIssueLister:


    def discover_installed_packages(self):
        """Gets a list of all installed packages"""

        print("Looking up installed packages")
        process = subprocess.Popen(["dpkg", "--get-selections"], stderr=DEVNULL, stdout=subprocess.PIPE)
        stdout = process.communicate()[0]
        packages = []
        for row in stdout.splitlines():
            found = re.search('^([^:\t]*)', row).group(1)
            packages.append(found)
        self.packages = packages
        process.wait()


    def lookup_all_source_packages(self):
        """Get a list of the source package names for the installed packages"""

        ## TODO: Is there a better way to get the list without invoking one process per package?
        print("Looking up name of source packages")
        sources = set()
        c = len(self.packages)
        i = 0
        for package in self.packages:
            i = i + 1
            if i % 100 == 0:
                print("   " + str(i) + "/" + str(c))
            process = subprocess.Popen(["apt-cache", "show", package], stderr=DEVNULL, stdout=subprocess.PIPE)
            stdout = process.communicate()[0]
            packages = []
            for row in stdout.splitlines():
                matcher = re.search('^Source: (.*)', row)
                if matcher:
                    sources.add(matcher.group(1))
        self.sources = sources
        process.wait()

lister = SecurityIssueLister()

lister.discover_installed_packages()
lister.lookup_all_source_packages()

print lister.sources
