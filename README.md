# HIBP-Lookup
Quick and dirty python script to query HIBP

# Usage
```
usage: hibp-lookup.py [-h] [-k API_KEY] [-e EMAIL] [-bd BREACHDOMAIN] [-bi BREACHINFO] [-lb LISTBREACHES] [-f FILE]

HIBP API Query Tool

options:
  -h, --help            show this help message and exit
  -k, --api_key API_KEY
                        Will be ignored if env var is present hibp-api-key=APIKEY
  -e, --email EMAIL     User Account search
  -bd, --breachdomain BREACHDOMAIN
                        Subscription Domain Lookup
  -bi, --breachinfo BREACHINFO
                        Breached Domain Lookup (by Name)
  -lb, --listbreaches LISTBREACHES
                        List Breachs (by Name)
  -f, --file FILE       Bulk File input for Breach Lookup (email addresses)
```

# 
