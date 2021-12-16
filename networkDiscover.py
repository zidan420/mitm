from mitm_helper_func import scan
import argparse

def print_result(scan_result_list):
	print("IP\t\t\tMAC")
	print("-----------------------------------------")
	for client in scan_result_list:
		print(client['IP'] + '\t' + client['MAC'])

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', help="Target IP")
	args = parser.parse_args()

	target = args.target
	scan_result_list = scan(target)
	print_result(scan_result_list)

if __name__ == '__main__':
	main()
