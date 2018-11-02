import os
import re
import sh
import sys
import time
import fcntl
import manuf
import thread
import socket
import struct
import logging
import threading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from socket import *
from scapy.all import *
from random import randint
from threading import Thread
from termcolor import colored
from subprocess import Popen, PIPE

lock = threading.Lock()
manuf_inst = manuf.MacParser()	


def getMac(iface):
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	i = fcntl.ioctl(s.fileno(),0x8927,struct.pack('256s',iface[:15]))
	return ':'.join(['%02x' %ord(char) for char in i[18:24]])


def getMacFromIp(ip):
	ip = ip.strip()
	Popen(["ping","-c 1", ip], stdout=PIPE)
	pid = Popen(["arp","-n", ip], stdout=PIPE)
	s = pid.communicate()[0]
	mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return mac


def getLocalIp(iface):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sockfd = sock.fileno()
	SIOCGIFADDR = 0x8915

	ifreq = struct.pack('16sH14s', iface, socket.AF_INET, '\x00'*14)
	try:
		res = fcntl.ioctl(sockfd, SIOCGIFADDR, ifreq)
	except:
		return None
	ip = struct.unpack('16sH2x4s8x', res)[2]
	return socket.inet_ntoa(ip)


def thread_print(msg):
	lock.acquire()
	if("ACTIVE" in msg):
		print colored(msg,"green")
	else:
		print msg
	lock.release()


def indexAll(string,sub):
	start = 0
	while True:
		start = string.find(sub,start)
		if(start == -1):
			return
		yield start
		start += len(sub)


def getIps():
	ips = []
	for i in range(0,255):
		ips.append("192.168.1.%s" %i)
	return ips


def checkIPS(ips):
	for ip in ips:
		print "ip %s" %ip
		ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2)
		
		for snd,rcv in ans:
			mac = rcv.sprintf(r"%Ether.src%").upper()
			ip = rcv.sprintf(r"%ARP.psrc%")
			hostname = getfqdn(ip)
			#print hostname
			if(hostname == ip):
				hostname = "?"
			manufacturer = manuf_inst.get_comment(mac)
			if(manufacturer is None):
				manufacturer = "?"
			num_spaces = first_block_len-len(ip)+1
			spaces = ""
			for i in range(0,num_spaces):
				spaces += " "
			thread_print("[ACTIVE] %s%s| %s | %s | %s" %(ip,spaces,mac,manufacturer,hostname))


def checkActiveIPs(gateway):
	ips = getIps()
	print colored("\n[+] Checking active IP addresses..\n","blue")
	dot_indexes = list(indexAll(gateway,"."))
	first_block_len = len(gateway[:dot_indexes[len(dot_indexes)-1]])+4 # conto gia' lo spazio anche	
	conf.verb = 0
	#splits = splitIps()
	first_block_distance = first_block_len-len("IP Address")
	spaces = ""

	for i in range(0,first_block_distance):
		spaces += " "
	print colored("[STATUS]  IP Address%s|    MAC Address    |  Manufacturer  |  Hostname\n" %spaces,"yellow")

	checkIPS(ips)

	'''for ip in ips:
		try:
			thread = Thread(target=checkIPS, args=(ips,))
			thread.start()
		except:
			print "Error: Unable to start thread"
			pass
	'''

	myip = getLocalIp()
	if(myip in ips):
		mymac = getMac().upper()
		manufacturer = manuf_inst.get_comment(mymac)
		if manufacturer is None:
			manufacturer = "?"
		num_spaces = first_block_len-len(myip)+1
		spaces = ""
		for i in range(0,num_spaces):
			spaces += " "	
		thread_print("[ACTIVE] %s%s| %s | %s | %s" %(myip,spaces,mymac,manufacturer,getfqdn(myip)))


checkActiveIPs("192.168.1.1")
