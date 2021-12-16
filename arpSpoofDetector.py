from scapy.all import sniff
from mitm_helper_func import scan, get_mac, get_ip
import argparse

def identify_attacker(MAC):
	attacker_ip = get_ip(net, MAC)
	if attacker_ip:
		print(f"\t\t[+] Attacker IP: {attacker_ip}")
	else:
		print("[-] Attacker IP could NOT be found.")
	print(f"\t\t[+] Attacker MAC: {response_mac}")

def process_sniffed_packet(pkt):
	if pkt.haslayer(ARP) and pkt[ARP].op == 2:
		real_mac = get_mac(pkt[ARP].psrc)
		response_mac = pkt[ARP].hwsrc

		if real_mac != response_mac:
			print(f"[-] You are under attack!!! ARP Spoof Detected!!!")
			identify_attacker(response_mac)

def sniff_packet(interface):
	sniff(iface=interface, store=False, prn=process_sniffed_packet)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-net', '--network', help="Network IP In CIDR Notation")
	parser.add_argument('-i', '--interface', help="Interface to sniff")
	args = parser.parse_args()
	interface = args.interface
	net = args.network

	global net

	sniff_packet(interface)

if __name__ == '__main__':
	main()
