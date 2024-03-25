# HTB Headless CTF Exploit

This Python script is designed to exploit a vulnerability in the "Headless CTF" challenge on Hack The Box (HTB). It utilizes a combination of blind Cross-Site Scripting (XSS), command injection, and a reverse shell payload to gain unauthorized access to the system.

## Overview

The script performs the following steps to exploit the target system:

1. **Exploit Blind XSS**: Injects a malicious script to steal the admin's session cookie.
2. **Receive Admin Cookie**: Sets up a listener to receive the stolen admin cookie.
3. **Exploit Command Injection**: Uses the admin cookie to perform a command injection on the vulnerable parameter.
4. **Receive Shell**: Opens a reverse shell connection to the attacker's machine, providing shell access to the target system.

## Requirements

- Python 3
- `requests` library
- Network access to the target system
- Ability to receive incoming connections on specified ports

## Installation

Ensure Python 3 and pip are installed on your system. Install the required Python packages using pip:

```bash
pip install requests
```

## Usage

To use the exploit script, you need to specify your listener IP address (`--lhost`), the port for the reverse shell (`--lport`), and optionally, the port to receive the blind XSS connection (`--http-port`).

```bash
./exploit.py --lhost <your-ip> [--lport <reverse-shell-port>] [--http-port <xss-connection-port>]
```

- `--lhost`: Your listener IP address (tun0 IP address).
- `--lport`: The port on which you want to receive the reverse shell connection (default: 1337).
- `--http-port`: The port on which you want to receive the blind XSS connection (default: 80).

Ensure your firewall allows incoming connections on both the `--lport` and `--http-port`.

## Disclaimer

This script is intended for educational purposes and ethical testing only. Unauthorized access to computer systems is illegal. The user is responsible for obtaining all necessary permissions from the rightful owners of the systems being tested.

---

By using this script, you agree to do so at your own risk. The author assumes no liability for any misuse or damage caused by this script.
