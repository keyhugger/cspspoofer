# cspspoofer
Automatic CSP Report-URI report spoofing tools

# Description
CSP Flare (Spoofer) will automatically send fake CSP violation reports to a report-uri. Violations, URIs and User-Agents can be chosen from a file.

# Usage
usage: flare.py [-h] [--agents AGENTS] [--reporturis REPORTURIS]
                [--violations VIOLATIONS] [--minwait MINWAIT]
                [--maxwait MAXWAIT]
                URL

# Requirements
 - Requests
pip3 install requests
