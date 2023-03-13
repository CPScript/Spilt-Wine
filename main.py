import pyfiglet
from termcolor import colored

ascii_banner = pyfiglet.figlet_format("SpiltWine")
print(ascii_banner)

text = colored("Find any open ports on a IP address", "blue")
print(text)


import socket
from IPy import IP


def check_ip(address):
    try:
        IP(address)
        return address
    except ValueError:
        return socket.gethostbyname(address)


def scan(target):
    ip_address = check_ip(target)
    print(f"\n-_0 looking for all open Ports on IP:{str(target)}")
    for port in range(1, 100):
        scan_port(ip_address, port)


def scan_port(ipaddress_, port_):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ipaddress_, port_))
        print(f'[+] Port {str(port_)} is open')
    except:
        pass


targets = input("[+] Enter IP address to scan: ")

if ',' in targets:
    for target in targets.split(','):
        scan(target.strip(' '))

else:
    scan(targets)
