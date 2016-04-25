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


# http://stackoverflow.com/a/22272587
class Multimap(dict):
    def __setitem__(self, key, value):
        if key not in self:
            dict.__setitem__(self, key, [value])
        else:
            self[key].append(value)



class SecurityIssueLister:


    def get_security_issues_from_website(self):
        """Gets a list of security issue from the website"""

        sys.stderr.write("Download list of known security issue from Ubuntu\n")
        self.known_issues = ""
        self.download("/~ubuntu-security/cve/main.html")
        self.download("/~ubuntu-security/cve/universe.html")
        self.download("/~ubuntu-security/cve/partner.html")


    def download(self, url):
        """downloads a file from the ubuntu webserver and appends the content to known_issues"""

        con = httplib.HTTPSConnection("people.canonical.com", 443)
        con.request("GET", url)
        res = con.getresponse()
        self.known_issues = self.known_issues + "\n" + res.read()


    def parse_known_issues(self):
        """parses the ubuntu known issue list"""

        # <tr><th>CVE</th><th>Package</th><th>Ubuntu 12.04 LTS (Precise Pangolin)</th><th>Ubuntu 14.04 LTS (Trusty Tahr)</th><th>Ubuntu Touch 15.04</th><th>Ubuntu Core 15.04</th><th>Ubuntu 15.10 (Wily Werewolf)</th><th>Ubuntu 16.04 (Xenial Xerus)</th><th>Ubuntu 16.10 (Yakkety Yak)</th><th>Links</th></tr>
        # <tr class="low"> <td class="cve"><a href="CVE-2002-2439">CVE-2002-2439</a></td> <td class="pkg"><a href="pkg/gcc-4.4-armel-cross.html">gcc-4.4-armel-cross</a></td> <td class="needs-triage">needs-triage</td> <td class="DNE">DNE</td> <td class="DNE">DNE</td> <td class="DNE">DNE</td> <td class="DNE">DNE</td> <td class="DNE">DNE</td> <td class="DNE">DNE</td> <td style="font-size: small;"><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439">Mitre</a> <a href="https://launchpad.net/bugs/cve/CVE-2002-2439">LP</a> <a href="http://security-tracker.debian.net/tracker/CVE-2002-2439">Debian</a></td> </tr>

        issue_map = Multimap()
        for line in self.known_issues.splitlines():
             matcher = re.search('<td class="pkg"><a href="[^"]*">([^<]*)</a></td>', line)
             if matcher:
                 issue_map[matcher.group(1)] = line
             else:
                 if "<th" in line:
                    self.table_header = line
        self.issue_map = issue_map


    def discover_installed_packages(self):
        """Gets a list of all installed packages"""

        sys.stderr.write("Looking up installed packages\n")
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
        sys.stderr.write("Looking up name of source packages\n")
        sources = set()
        c = len(self.packages)
        i = 0
        for package in self.packages:
            i = i + 1
            if i % 100 == 0:
                sys.stderr.write("   " + str(i) + "/" + str(c) + "\n")
            process = subprocess.Popen(["apt-cache", "show", package], stderr=DEVNULL, stdout=subprocess.PIPE)
            stdout = process.communicate()[0]
            packages = []
            for row in stdout.splitlines():
                matcher = re.search('^Source: (.*)', row)
                if matcher:
                    sources.add(matcher.group(1))
        self.sources = sources
        process.wait()


    def output_header(self):
        """Write html header of output"""

        sys.stderr.write("Generating output\n")
        print("<!DOCTYPE html><html><head><base href=\"https://people.canonical.com/~ubuntu-security/cve/\"><title>Security Issues</title>");
        print("<link rel=\"StyleSheet\" href=\"toplevel.css\" type=\"text/css\" /></head><body><table>")
        print(self.table_header)


    def output_result(self):
        """Writes the output"""

        for pkg in sorted(self.sources):
            if pkg in self.issue_map:
                issues = self.issue_map[pkg]
                for issue in issues:
                    print issue


    def process(self):
        self.get_security_issues_from_website()
        self.parse_known_issues()
        self.discover_installed_packages()
        self.lookup_all_source_packages()
        self.output_header()
        self.output_result()
        sys.stderr.write("Done\n")




if __name__ == "__main__":
    SecurityIssueLister().process()


