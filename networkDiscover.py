# Our custom library - we are importing the scan function only.
from mitm_helper_func import scan

# a builtin library to get user input through command line arguments
import argparse

def print_result(scan_result_list):
	print("IP\t\t\tMAC")
	print("-----------------------------------------")
	for client in scan_result_list:
		print(client['IP'] + '\t' + client['MAC'])

def main():
	# Initialize the argparse
	parser = argparse.ArgumentParser()
	
	# Add argument(s) to args
	parser.add_argument('-t', '--target', help="Target IP")
	args = parser.parse_args()
	
	# Store the target argument to target variable
	target = args.target

	# Scan the target with our custom function
	scan_result_list = scan(target)

	# Prints the result of our scan
	print_result(scan_result_list)

if __name__ == '__main__':
	main()
