from argparse import ArgumentParser
import requests 
import os
import time
import json

#    Script:    hibp-lookup.py
#    Created:   02/10/2025
#    Purpose:   Check if an email address has been breached on HaveIBeenPwned.com via API
#    Version:   1.2

#    Usage: hibp-lookup.py [-h] [-k API_KEY] [-e EMAIL] [-bd BREACHDOMAIN] [-bi BREACHINFO] [-f FILE]



def parse_command_line():
    parser = ArgumentParser(description="HIBP API Query Tool")
    parser.add_argument("-k", "--api_key",
                        help="Will be ignored if env var is present hibp-api-key=APIKEY",
                        required=False
                        )
    parser.add_argument("-e", "--email",
                        help="User Account search",
                        required=False
                        )
    parser.add_argument("-bd","--breachdomain",
                        help="Subscription Domain Lookup",
                        required=False
                        )
    parser.add_argument("-bi","--breachinfo",
                        help="Breached Domain Lookup (by Name)",
                        required=False
                        )
    parser.add_argument("-lb","--listbreaches",
                        help="List Breachs (by Name)",
                        required=False
                        )
    parser.add_argument("-f","--file",
                        help="Bulk File input for Breach Lookup (email addresses)",
                        required=False
                        )

    return parser.parse_args()




def output_files(output_file, data, format):
    if format == 'json':
        output_file = output_file + '.json'
        purty_json = json.dumps(data, indent=2)
        with open(output_file, 'w') as file:
            file.write(purty_json)


def email_run(headers, email):
    if email:
        resp = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers)
        if resp.status_code == 200:
            export_file = "hibp-email-" + email
            response_dict = resp.json()

            print("Email >> {0}\nBreached Domains: {1}".format(email, response_dict))
            print("Email >> Writing results to local file: {0}".format(export_file))
            output_files(export_file, response_dict, 'json')
        elif resp.status_code == 404:
            #404 Not found — the account could not be found and has therefore not been pwned
            print("User {0} NOT found in breached domains".format(email))
        elif resp.status_code == 429:
            # 429 Too many requests — the rate limit has been exceeded
            print("{0} - Too many requests - rate limit has been exceeded.".format(resp.status_code))
        else:
            print("Something went wrong homie => {0}".format(resp.status_code))


def domain_run(headers, domain_string):
    if domain_string:
        resp = requests.get(f'https://haveibeenpwned.com/api/v3/breacheddomain/{domain_string}', headers=headers)
        if resp.status_code == 200:
            export_file = "hibp-domain-" + domain_string
            response_dict = resp.json()

            print("Domain >> {0}\nBreached Domain: {1}".format(domain_string, json.dumps(response_dict, indent=2)))
            print("Domain >> Writing output to local file: {0}".format(export_file))
            output_files(export_file, response_dict, 'json')   
        elif resp.status_code == 404:
            #404 Not found — the account could not be found and has therefore not been pwned
            print("Breached Domain {0} NOT found in database".format(domain_string))
        elif resp.status_code == 429:
            # 429 Too many requests — the rate limit has been exceeded
            print("{0} - Too many requests - rate limit has been exceeded.".format(resp.status_code))
        else:
            print("Something went wrong homie => {0}".format(resp.status_code))

def breach_info_run(headers, breachinfo):
    if breachinfo:
        resp = requests.get(f'https://haveibeenpwned.com/api/v3/breach/{breachinfo}', headers=headers)
        if resp.status_code == 200:
            export_file = "hibp-info-" + breachinfo
            response_dict = resp.json()

            print("BreachInfo >> {0}\nBreached Domain: {1}".format(breachinfo, json.dumps(response_dict, indent=2)))
            print("BreachInfo >> Writing output to local file: {0}".format(export_file))
            output_files(export_file, response_dict, 'json')
        elif resp.status_code == 404:
            #404 Not found — the account could not be found and has therefore not been pwned
            print("Breached Domain {0} !-NOT-! found in database".format(breachinfo))
        else:
            print("Something went wrong homie => {0}".format(resp.status_code))


def listbreaches_run(headers, listbreaches):
    if listbreaches:
        resp = requests.get(f'https://haveibeenpwned.com/api/v3/breaches/', headers=headers)
        if resp.status_code == 200:
            export_file = "hibp-list-" + "breaches"
            response_dict = resp.json()
            response_dict.sort(key=lambda date: date['BreachDate'], reverse=True)
            for breach in response_dict:
                print("Breach: {0} Domain: {1} PwnCount: {2} BreachDate: {3} ".format(breach['Name'], breach['Domain'], breach['PwnCount'], breach['BreachDate']))
                print("ListBreaches >> HIBP Breaches sorted by BreachDate in reverse [-]")    
                print("ListBreaches >> Total HIBP Breaches: {0}".format(len(response_dict)))
                print("ListBreaches >> Latest HIBP Breach Name: {0}".format(response_dict[0]['Name']))
                print("ListBreaches >> Writing to local file HIBP: {0}".format(export_file))
                output_files(export_file, response_dict, 'json')
        elif resp.status_code == 404:
            #404 Not found — the account could not be found and has therefore not been pwned
            print("{0} not found".format(listbreaches))
        else:
            print("Something went wrong homie => {0}".format(resp.status_code))
            print("{}".format(resp.json()))


def file_run(headers, file):
    if file:
        # Non-Preimum API key is limited to 10 requests per 1 minute
        # Number of requests to send
        batch_size = 10

        # Interval between batches of requests (in seconds) to stay within rate limits
        request_interval = 60  # 1 minute

        # Empty array to hold the accounts
        account_array = []

        # Output file
        output_file = 'hibp-output-new.txt'

        try:
            with open(file, 'r') as f:
                for acct in f:
                    account_array.append(acct.strip())
        except FileNotFoundError:
            print(f"The file '{file}' does not exist.")
        except Exception as e:
            print(f"An error occurred: {e}")

        for i in range(0, len(account_array), batch_size):
            batch = account_array[i:i + batch_size] #get a batch of emails from text file.
            
            for email in batch:
                resp = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers)
                
                if resp.status_code == 200:
                    with open(output_file, 'a+') as f:
                        line = "User {0} found in breached domains {1}\n".format(email, resp.json())
                        f.write(line)
                    print("User {0} found in breached domains {1}".format(email, resp.json()))
                elif resp.status_code == 404:
                    #404 Not found — the account could not be found and has therefore not been pwned
                    print("User {0} NOT found in breached domains".format(email))
                elif resp.status_code == 429:
                    # 429 Too many requests — the rate limit has been exceeded
                    print("{0} - Too many requests - rate limit has been exceeded.".format(resp.status_code))
                elif resp.status_code == 400:
                    # Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)
                    print("{0} - Bad request — the account does not comply with an acceptable format.".format(resp.status_code))
                else:
                    print("Something went wrong homie => {0}".format(resp.status_code))
                
            
            time.sleep(request_interval)


def headers_key(key):
    return {
        'hibp-api-key': key
    }

if __name__ == "__main__":
    args = parse_command_line()

    if args.api_key:
        api_key = headers_key(args.api_key)
    elif (os.environ.get('hibp-api-key') is not None ):
        get_env_api_key=os.getenv("hibp-api-key")
        api_key = headers_key(get_env_api_key)
    else:
        print("No API key provided, puto!")
        exit(1)

    if args.email:
        email = args.email
        email_run(api_key, email)

    if args.breachdomain:
        domain_string = args.breachdomain
        domain_run(api_key, domain_string)

    if args.breachinfo:
        breachinfodomain = args.breachinfo
        breach_string_full = "?domain=" + breachinfodomain
        truncate_string = "?truncateResponse=false"
        breach_info_run(api_key, breach_string_full)

    if args.file:
        file = args.file
        file_run(api_key, file)

    if args.listbreaches:
        listbreaches = args.listbreaches
        listbreaches_run(api_key, listbreaches)
