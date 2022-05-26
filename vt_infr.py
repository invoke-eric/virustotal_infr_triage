import requests
import sys
import re
import os

API_KEY = os.getenv('API_KEY')

request_headers = {
    'x-apikey': API_KEY,
}


iplist = []
domainlist = []

ipregex = re.compile(r'(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?')

domainregex = re.compile(r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b')

input = sys.stdin.readlines()

for line in input:
    line = line.strip()
    
    match_ipregex = ipregex.match(line)
    if match_ipregex:
        iplist.append(line)
    
    match_domainregex = domainregex.match(line)

    if match_domainregex:
        domainlist.append(line)

    elif not match_ipregex and not match_domainregex:
        print(line + " is probably not a domain or an IP")

positive_list = []
no_positive_list =[]

communicating_list =[]
no_communicating_list = []

downloads_list = []
no_downloads_list = []




for ip in iplist:
    try:
        print("\n")
        
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
        r = requests.get(url, headers=request_headers)
        data = r.json()

        data_dict = data["data"]
        attributes = data_dict["attributes"]
        last_analysis_stats = attributes["last_analysis_stats"]
        malicious = last_analysis_stats["malicious"]

        print(ip + " has " + str(malicious) + " malicious verdict(s)")

        if malicious == 0:
            no_positive_list.append(ip)
        elif malicious != 0:
            positive_list.append(ip)

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/communicating_files"
        r = requests.get(url, headers=request_headers)
        data = r.json()

        meta = data["meta"]
        count = meta['count']

        if count == 0:
            print(ip + " has no communicating files")
            no_communicating_list.append(ip)
        elif count != 0:
            print(ip + " has " + str(count) + " communicating files")
            communicating_list.append(ip)
        
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/downloaded_files"
        r = requests.get(url, headers=request_headers)
        data = r.json()

        meta = data["meta"]
        count = meta['count']
        if count == 0:
            print(ip + " has no downloaded files")
            no_downloads_list.append(ip)
        elif count != 0:
            print(ip + " has " + str(count) + " downloaded files")
            downloads_list.append(ip)

    except:
        print("unable to obtain expected VT API response for " + ip)

for domain in domainlist:
    try:
        print("\n")
        
        url = "https://www.virustotal.com/api/v3/domains/" + domain
        r = requests.get(url, headers=request_headers)
        data = r.json()
        
        data_dict = data["data"]
        attributes = data_dict["attributes"]
        last_analysis_stats = attributes["last_analysis_stats"]
        malicious = last_analysis_stats["malicious"]

        print(domain + " has " + str(malicious) + " malicious verdict(s)")

        if malicious == 0:
            no_positive_list.append(domain)
        elif malicious != 0:
            positive_list.append(domain)

        url = "https://www.virustotal.com/api/v3/domains/" + domain + "/communicating_files"
        r = requests.get(url, headers=request_headers)
        data = r.json()

        meta = data["meta"]
        count = meta['count']
        if count == 0:
            print(domain + " has no communicating files")
            no_communicating_list.append(domain)
        elif count != 0:
            print(domain + " has " + str(count) + " communicating files")
            communicating_list.append(domain)
        
        url = "https://www.virustotal.com/api/v3/domains/" + domain + "/downloaded_files"
        r = requests.get(url, headers=request_headers)
        data = r.json()

        meta = data["meta"]
        count = meta['count']
        if count == 0:
            print(domain + " has no downloaded files")
            no_downloads_list.append(domain)
        elif count != 0:
            print(domain + " has " + str(count) + " downloaded files")
            downloads_list.append(domain)
    except:
        print("unable to obatain expected VT API response for " + domain)

print("\n")
print("No Positive Verdicts:")
print(*no_positive_list, sep= "\n")

print("\n")
print("Positive Verdicts:")
print(*positive_list, sep = "\n")

print("\n")
print("No Communicating Files:")
print(*no_communicating_list, sep = "\n")

print("\n")
print("Communicating Files:")
print(*communicating_list, sep = "\n")

print("\n")
print("No Downloaded Files:")
print(*no_downloads_list, sep = "\n")

print("\n")
print("Downloaded Files:")
print(*downloads_list, sep = "\n")
print("\n")