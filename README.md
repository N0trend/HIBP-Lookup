# HIBP-Lookup
Quick and dirty python script to query HIBP

# Usage

usage: hibp-lookup.py [-h] [-k API_KEY] [-e EMAIL] [-bd BREACHDOMAIN] [-bi BREACHINFO] [-lb LISTBREACHES] [-f FILE]

HIBP API Query Tool

options:
  -h, --help            show this help message and exit
  -k API_KEY, --api_key API_KEY
                        HIBP API Key
  -e EMAIL, --email EMAIL
                        User Account search
  -bd BREACHDOMAIN, --breachdomain BREACHDOMAIN
                        Subscription Domain Lookup
  -bi BREACHINFO, --breachinfo BREACHINFO
                        Breached Domain Lookup (by Name)
  -lb LISTBREACHES, --listbreaches LISTBREACHES
                        List Breachs (by Name)
  -f FILE, --file FILE  Bulk File input for Breach Lookup (email addresses)
