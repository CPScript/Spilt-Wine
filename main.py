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
import time
print(" ")
print(" ")
print(" ")
print("Would you like to get premeium?")
time.sleep(2)
print("Premium comes with")
time.sleep(5)
print("[+]Faster connection?")
time.sleep(1)
print("[+]IP geoLocater?")
time.sleep(1)
print("[+]DDOS attack script?")
time.sleep(1)
print("[+]VPN")
time.sleep(1)
print("[+]Protection service ")
time.sleep(1)
print("[+]Phishing tool for other APPLICATIONS")
time.sleep(1)
print("[+]AD blocker")
time.sleep(1)
print("[+]Black listed on our public Servers and IP pullers")
time.sleep(1)
print("[+]RAT tools")
print("[+]Free malwares that we have made.")
print(" ")
print(" ")
time.sleep(3)
text = colored("Price started at 30$ a month or 250$ a year!", "blue")
print(text)
print(" ")
print(" ")
print ("Yes or No")
choice = input("")

if choice == "yes":
    print("Please message this user on discord: Fe4RLess#0001")

if choice == "no":
  print("-_- OK -_-")
