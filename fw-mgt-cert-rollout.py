###################################################################################
## This script automates the entire process for pushing management certificates  ##
## to PAN firewalls throughout the enterprise. The workflow is as follows:       ##
## 1) Generate CSRs - You can do this in two ways, by adding attributes and      ##
##    crypto settings through the menus in the script, or by populating a CSV    ##
##	  with the values corresponding to their firewall address. You can also use  ##
## 	  a combo of both. If you specify the attributes and crypto settings using   ##
##    the menus, you will need to provide a list of addresses using the menus as ##
##    well. If you provide attributes and crypto setting through a CSV file, the ##
## 	  address list should be apart of the CSV.									 ##
## 2) Use the scipt to push the CSRs to your Microsoft ADCS CA server - The      ##
##    script supports basic and NTLM authentication. It also supports the use    ##
##    of CA manager approval. If no manager approval is necessary, then it       ##
##    downloads the signed PEM certs. If CA manager approval is necessary, then  ##
##    the saves the request ID information for each cert request. Once pending   ##
##    requests are approved, you can enter the script's CA server menu again and ##
## 	  automatically recognize that it has cert requests pending, and it will     ##
##    download the signed PEM certs for you. If you don't use MS ADCS or don't 	 ##
##    want to use this feature, just place your signed certs in a folder called  ##
##    'PAN-FW-PEMs' (within the folder where you run this script).               ##
## 3) Push signed certs to firewalls - Just choose the menu option to do so, the ##
##    script will handle this for you.											 ##
## 4) Choose the option to create and apply the SSL/TSL cert profiles. This will ##
##    also associate the firewall's cert to the profile and apply the profile to ##
##    the management interface.													 ##
## 5) Commit the firewalls - This can be done using the menu option in the       ##
##    script. You will have the option to step through validation on each, or    ##
##    push and pray.															 ##
## 6) Sit back, relax, and enjoy all the time that this script saved you :)      ##
###################################################################################
###################################################################################
#
#!/usr/bin/python
#
############################################################################
# Library Import and execution argument handling
############################################################################
import os
import re
import sys
import time
import datetime
import getpass
from xml.etree import ElementTree as ET
try:
	from lxml import html
except ImportError:
	raise ValueError("lxml support not available, please install module - run 'pip install lxml'")
try:
	import requests
	from requests_ntlm import HttpNtlmAuth
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
	raise ValueError("requests support not available, please install module - run 'pip install requests' and 'pip install request_ntlm'")
try:
	import certsrv
except ImportError:
	raise ValueError("certsrv support not available, please install module - run 'pip install certsrv'")



##Global Variables##
fw_addr_list = []
fw_csr_list = []
mainkey = ''
country = ''
state = ''
locality = ''
organization = ''
department = ''
email = ''
hostname = ''
ip = ''
altEmail = ''
algorithm = 'RSA'
bits = '2048'
digest = 'sha256'
expiration = '365'


# Prompts the user to enter the IP/FQDN of a firewall
def getfwipfqdn():
	while True:
		try:
			fwipraw = raw_input("Please enter a comma separated list of IP/FQDNs (These will be the CN on the certs): ")
			ipr = re.match(r"^(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?=.{4,253})(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})))(,\s*(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?=.{4,253})(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})))*$", fwipraw)
			if ipr:
				break
			else:
				time.sleep(1)
				print("\nThere was something wrong with your entry. Please try again...\nThe format should look like this: 10.11.12.13, 20.21.22.23, 42.42.42.42, foo.bar.com\n\n")
		except:
			print("\nThere was some kind of problem entering your IP. Please try again...\n")
	return fwipraw

	
# Prompts the user to enter their username to retrieve the api key
def getuname():
	while True:
		try:
			username = raw_input("Please enter your user name: ")
			usernamer = re.match(r"^[a-zA-Z0-9_-]{3,24}$", username) # 3 - 24 characters {3,24}
			if usernamer:
				break
			else:
				print("\nThere was something wrong with your entry. Please try again...\n")
		except:
			print("\nThere was some kind of problem entering your user name. Please try again...\n")
	return username

	
# Prompts the user to enter their password to retrieve the api key
def getpassword():
	while True:
		try:
			password = getpass.getpass("Please enter your password: ")
			passwordr = re.match(r"^.{5,50}$", password) # simple validate PANOS has no password characterset restrictions
			if passwordr:
				break
			else:
				print("\nThere was something wrong with your entry. Please try again...\n")
		except:
			print("\nThere was some kind of problem entering your password. Please try again...\n")
	return password


# Retrieves the user's api key
def getkey(fwip):
	while True:
		try:
			fwipgetkey = fwip
			username = getuname()
			password = getpassword()
			keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwipgetkey,username,password)
			r = requests.get(keycall, verify=False)
			tree = ET.fromstring(r.text)
			if tree.get('status') == "success":
				apikey = tree[0][0].text
				break
			else:
				print("\nYou have entered an incorrect username or password. Please try again...\n")
		except requests.exceptions.ConnectionError as e:
			print("\nThere was a problem connecting to the firewall.  Please check the IP or FQDN and try again...\n")
			exit()
	return apikey


# Prompts the user with the option to commit each firewall individually, after validating the config
def fwCommit_withValidation(fwip, mainkey):
	while True:
		commit = raw_input("\n\nWe'll now validate and commit the config for %s, are you ok with this? [Y/n]   " % (fwip))
		if commit == 'n' or commit == 'N':
			print '\nPlease login to %s and commit your changes manaully\n' % (fwip)
			break
		elif commit == 'y' or commit == 'Y' or commit == '':
			fw_url = 'https://' + fwip + '/api/?type=op&cmd=<validate><full></full></validate>&key=' + mainkey
			r = requests.get(fw_url, verify=False)
			tree = ET.fromstring(r.text)
			if tree.get('status') == "success":
				print '\nValidating the config, please hold...',
				job = tree.find('./result/job').text
				count = 1
				while True:
					fw_url = 'https://' + fwip + '/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s' % (job,mainkey)
					r = requests.get(fw_url, verify=False)
					tree = ET.fromstring(r.text)
					if tree.find('./result/job/result').text == 'PEND':
						if count % 8 == 0:
							print '\nStill waiting for validation...',
						else:
							sys.stdout.write('.')
						count += 1
						time.sleep(1)
					elif tree.find('./result/job/result').text == 'OK' and tree.find('./result/job/details/line').text == 'Configuration is valid':
						fw_url = 'https://' + fwip + '/api/?type=commit&cmd=<commit></commit>&key=' + mainkey 
						r = requests.get(fw_url, verify=False)
						print '\n\nCongrats the config is valid!\n\n', '\n-----The commit job was successfully sent to %s-----\n' % (fwip)
						break
					else:
						print 'Could not validate the config, please login to the firewall and commit manaully\n\n'
						break
			else:
				print 'Could not validate the config, please login to the firewall and commit manaully\n\n'
				break
			break
		else:
			time.sleep(1)
			print "\nYou seemed to have chosen the wrong key. Please try \"y\" or \"n\" this time...\n"


# Allows the user to commit the firewalls without first validating the config
def fwCommit_withoutValidation(fwip, mainkey):
	fw_url = 'https://' + fwip + '/api/?type=commit&cmd=<commit></commit>&key=' + mainkey 
	r = requests.get(fw_url, verify=False)
	tree = ET.fromstring(r.text)
	if tree.get('status') == "success":
		time.sleep(1)
		print('-----A commit job was successfully sent to %s-----' % (fwip))
		time.sleep(1)
	else:
		time.sleep(1)
		print('\n-----PLEASE NOTE THERE WAS A PROBLEM WITH SENDING A COMMIT JOB TO %s-----' % (fwip))
		time.sleep(1)


# Function to allow user to choose cert attributes
def menu_1():
	global country, state, locality, organization, department, email, hostname, ip, altEmail
	print('\n\n')
	while True:
		try:
			attrMenuChoice = int(raw_input('Choose an option below to add or modify certificate attributes\nChoose exit when finished...\n\n1.  Country\n2.  State\n3.  Locality\n4.  Organization\n5.  Department\n6.  Email\n7.  Hostname\n8.  IP Address\n9.  Alt Email\n10. Exit to Main Menu\n\nEnter your choice: '))
			if attrMenuChoice == 1:
				country = raw_input('\nWhat would you like to set the country to? [US] ')
				if country == '':
					country = 'US'
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
			elif attrMenuChoice == 2:
				state = raw_input('\nWhat would you like to set the state to? ')
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
			elif attrMenuChoice == 3:
				locality = raw_input('\nWhat would you like to set the locality to? ')
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
			elif attrMenuChoice == 4:
				organization = raw_input('\nWhat would you like to set the organization to? ')
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
			elif attrMenuChoice == 5:
				department = [raw_input('\nWhat would you like to set the department to? ')]
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
				while True:
					anotherItem = raw_input('Would you like to add another department entry? [y/N] ')
					if anotherItem == 'Y' or anotherItem == 'y':
						department.append(raw_input('\nWhat department entry would you like to add? '))
						time.sleep(1)
						print('\nOk, got it...\n\n')
					elif anotherItem == '' or anotherItem == 'N' or anotherItem == 'n':
						print('\n')
						break
			elif attrMenuChoice == 6:
				email = raw_input('\nWhat would you like to set the email to? ')
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
			elif attrMenuChoice == 7:
				hostname = [raw_input('\nWhat would you like to set the hostname to? ')]
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
				while True:
					anotherItem = raw_input('\nWould you like to add another hostname entry? [y/N] ')
					if anotherItem == 'Y' or anotherItem == 'y':
						hostname.append(raw_input('\nWhat hostname entry would you like to add? '))
						time.sleep(1)
						print('\nOk, got it...\n\n')
					elif anotherItem == '' or anotherItem == 'N' or anotherItem == 'n':
						print('\n')
						break
			elif attrMenuChoice == 8:
				ip = [raw_input('\nWhat would you like to set the IP address to? ')]
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
				while True:
					anotherItem = raw_input('\nWould you like to add another IP Address entry? [y/N] ')
					if anotherItem == 'Y' or anotherItem == 'y':
						ip.append(raw_input('\nWhat IP Address entry would you like to add? '))
						time.sleep(1)
						print('\nOk, got it...\n\n')
					elif anotherItem == '' or anotherItem == 'N' or anotherItem == 'n':
						print('\n')
						break
			elif attrMenuChoice == 9:
				altEmail = [raw_input('\nWhat would you like to set the altEmail to? ')]
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
				while True:
					anotherItem = raw_input('\nWould you like to add another altEmail entry? [y/N] ')
					if anotherItem == 'Y' or anotherItem == 'y':
						altEmail.append(raw_input('\nWhat altEmail entry would you like to add? '))
						time.sleep(1)
						print('\nOk, got it...\n\n')
					elif anotherItem == '' or anotherItem == 'N' or anotherItem == 'n':
						print('\n')
						break
			elif attrMenuChoice == 10:
				time.sleep(1)
				print('\n\n')
				break
				continue
			else:
				time.sleep(1)
				print("\nYou've entered a number that is not in the list, try again...\n")
				time.sleep(1)
				continue
		except ValueError:
			time.sleep(1)
			print('\nYou must enter a number, try again...\n')
			time.sleep(1)
			continue


# Function to allow user to choose crypto settings
# Default setting for crypto if nothing chosen are: RSA, 2048 bits, sha256
def menu_2():
	global algorithm, bits, digest
	while True:
		try:
			algorithm = int(raw_input('\nWhat algorithm would you like to use?\n\n1. RSA\n2. Elliptic Curve DSA\n\nEnter your choice: '))
			if algorithm == 1:
				algorithm = 'RSA'
				while True:
					try:
						bits = int(raw_input('\nWhat number of bits would you like to use? [2048]\n\n1. 512\n2. 1024\n3. 2048\n4. 3072\n5. 4096\n\nEnter your choice: '))
						if bits == 1:
							bits = '512'
						elif bits == 2:
							bits = '1024'
						elif bits == 3:
							bits = '2048'
						elif bits == 4:
							bits = '3072'
						elif bits == 5:
							bits = '4096'
						else:
							time.sleep(1)
							print("\nYou've entered a number that is not in the list, try again...\n")
							time.sleep(1)
							continue
					except ValueError as e:
						## Handles the default value, which isn't an integer (enter key) ##
						if str(e) == "invalid literal for int() with base 10: ''":
							bits = '2048'
							time.sleep(1)
							print('\nOk, got it...\n\n')
							time.sleep(1)
							break
						else:
							time.sleep(1)
							print('\nYou must enter a number, try again...\n')
							time.sleep(1)
							continue
					time.sleep(1)
					print('\nOk, got it...\n\n')
					time.sleep(1)
					break
				while True:
					try:
						digest = int(raw_input('What digest would you like to use? [sha256]\n\n1. sha1\n2. sha256\n3. sha384\n4. sha512\n5. md5\n\nEnter your choice: '))
						if digest == 1:
							digest = 'sha1'
						elif digest == 2:
							digest = 'sha256'
						elif digest == 3:
							digest = 'sha384'
						elif digest == 4:
							digest = 'sha512'
						elif digest == 5:
							digest = 'md5'
						else:
							time.sleep(1)
							print("\nYou've entered a number that is not in the list, try again...\n")
							time.sleep(1)
							continue
					except ValueError as e:
						## Handles the default value, which isn't an integer (enter key) ##
						if str(e) == "invalid literal for int() with base 10: ''":
							digest = 'sha256'
							time.sleep(1)
							print('\nOk, got it...\n\n')
							time.sleep(1)
							break
						else:
							time.sleep(1)
							print('\nYou must enter a number, try again...\n')
							time.sleep(1)
							continue
					time.sleep(1)
					print('\nOk, got it...\n\n')
					time.sleep(1)
					break
				break
			elif algorithm == 2:
				algorithm = 'Elliptic Curve DSA'
				while True:
					try:
						bits = int(raw_input('\nWhat number of bits would you like to use? [256]\n\n1. 256\n2. 384\n\nEnter your choice: '))
						if bits == 1:
							bits = '256'
						elif bits == 2:
							bits = '384'
						else:
							time.sleep(1)
							print("\nYou've entered a number that is not in the list, try again...\n")
							time.sleep(1)
							continue
					except ValueError as e:
						## Handles the default value, which isn't an integer (enter key) ##
						if str(e) == "invalid literal for int() with base 10: ''":
							bits = '256'
							time.sleep(1)
							print('\nOk, got it...\n\n')
							time.sleep(1)
							break
						else:
							time.sleep(1)
							print('\nYou must enter a number, try again...\n')
							time.sleep(1)
							continue
					time.sleep(1)
					print('\nOk, got it...\n\n')
					time.sleep(1)
					break
				while True:
					try:
						digest = int(raw_input('What digest would you like to use? [sha256]\n\n1. sha256\n2. sha384\n3. sha512\n\nEnter your choice: '))
						if digest == 1:
							digest = 'sha256'
						elif digest == 2:
							digest = 'sha384'
						elif digest == 3:
							digest = 'sha512'
						else:
							time.sleep(1)
							print("\nYou've entered a number that is not in the list, try again...\n")
							time.sleep(1)
							continue
					except ValueError as e:
						## Handles the default value, which isn't an integer (enter key) ##
						if str(e) == "invalid literal for int() with base 10: ''":
							digest = 'sha256'
							time.sleep(1)
							print('\nOk, got it...\n\n')
							time.sleep(1)
							break
						else:
							time.sleep(1)
							print('\nYou must enter a number, try again...\n')
							time.sleep(1)
							continue
					time.sleep(1)
					print('\nOk, got it...\n\n')
					time.sleep(1)
					break
				break
			else:
				time.sleep(1)
				print("\nYou've entered a number that is not in the list, try again...\n")
				time.sleep(1)
				continue
		except ValueError:
			time.sleep(1)
			print('\nYou must enter a number, try again...\n')
			time.sleep(1)
			continue
		break


# Function to allow user to set the expiration
def menu_3():
	global expiration
	while True:
		try:
			expiration = int(raw_input('\nWhat would you like to set the expiration to (in days)? [365] '))
			if 1 <= expiration <= 7200:
				expiration = str(expiration)
			else:
				time.sleep(1)
				print('\nThe expiration must be set between 1 and 7200 days\n')
				time.sleep(1)
				continue
		except ValueError as e:
			## Handles the default value, which isn't an integer (enter key) ##
			if str(e) == "invalid literal for int() with base 10: ''":
				expiration = '365'
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)
				break
			else:
				time.sleep(1)
				print('\nYou must enter a number, try again...\n')
				time.sleep(1)
				continue
		time.sleep(1)
		print('\nOk, got it...\n\n')
		time.sleep(1)
		break


# Allows user to clear all attributes and sets crypto settings to default
def menu_4():
	global country, state, locality, organization, department, email, hostname, ip, altEmail, algorithm, bits, digest, expiration
	country = ''
	state = ''
	locality = ''
	organization = ''
	department = ''
	email = ''
	hostname = ''
	ip = ''
	altEmail = ''
	algorithm = 'RSA'
	bits = '2048'
	digest = 'sha256'
	expiration = '365'
	time.sleep(1)
	print('\nAll attributes were cleared, and crypto settings were set to default\n\n')
	time.sleep(1)


# Prints all attributes and crypto settings
def menu_5():
	global country, state, locality, organization, department, email, hostname, ip, altEmail, algorithm, bits, digest, expiration
	print("\n\nOk, here's your stuff...\n")
	time.sleep(1)
	if country == '':
		print('Country:      None')
	else:
		print('Country:      ' + country)
	if state == '':
		print('State:        None')
	else:
		print('State:        ' + state)
	if locality == '':
		print('Locality:     None')
	else:
		print('Locality:     ' + locality)
	if organization == '':
		print('Organization: None')
	else:
		print('Organization: ' + organization)
	if department == '':
		print('Department:   None')
	else:
		if len(department) > 1:
			print('Department:   ' + str(department))
		else:
			print('Department:   ' + department[0])
	if email == '':
		print('Email:        None')
	else:
		print('Email:        ' + email)
	if hostname == '':
		print('Hostname:     None')
	else:
		if len(hostname) > 1:
			print('Hostname:     ' + str(hostname))
		else:
			print('Hostname:     ' + hostname[0])
	if ip == '':
		print('IP Address:   None')
	else:
		if len(ip) > 1:
			print('IP Address:   ' + str(ip))
		else:
			print('IP Address:   ' + ip[0])
	if altEmail == '':
		print('Alt Email:    None')
	else:
		if len(altEmail) > 1:
			print('Alt Email:    ' + str(altEmail))
		else:
			print('Alt Email:    ' + altEmail[0])
	print('Algorithm:    ' + algorithm + '\nBits:         ' + bits + '\nDigest:       ' + digest + '\nExpiration:   ' + expiration + '\n\n')
	time.sleep(1)
	raw_input('\nPress Enter to continue...')
	print('\n\n')


# Allows user to input IP or FQDN addresses via terminal or via CSV file
def menu_6():
	global fw_addr_list, fw_csr_list
	print('\n\n')
	fwListCheck = False
	while True:
		try:
			addrMenuChoice = int(raw_input('Choose an option below to input or print addresses\nChoose exit when finished...\n\n1. Input Addresses Via Terminal\n2. Input Addresses/Attributes/Crypto Settings Via CSV File\n3. Print Addresses/Attributes/Crypto Settings\n4. Exit to Main Menu\n\nEnter your choice: '))
			if addrMenuChoice == 1:
				print('')
				fw_addr_list = getfwipfqdn()
				fwListCheck = True

				## Changes the firewall list from string to list format, removing any spaces if they exist, then makes each entry its own list ##
				fw_addr_list = fw_addr_list.replace(' ', '') 
				fw_addr_list = fw_addr_list.split(',')
				index = 0
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)

			## Input addresses from CSV file ##
			elif addrMenuChoice == 2:
				while True:
					csvChoice = raw_input('\nWhat is the name of your CSV file? ')
					if not os.path.exists(csvChoice):
						time.sleep(1)
						print('\n\nCould not find ' + csvChoice + '\nMake sure your CSV file is in the same directory as this script...')
					else:
						readFile = open(csvChoice, 'r')
						csvList = readFile.readlines()
						readFile.close()
						break
				for item in csvList:
					item = item.replace(', ', ',')
					item = item.replace('\n', '')
					multiLists = re.findall(r'(?<=\[)([^\]]+)(?=\])', item)
					item_temp = re.sub(r'(\[)([^\]]+)(\])', '_regVar_', item).split(',')
					item_new = []
					count = 0
					index = 0
					for i in item_temp:
					    if i == '_regVar_':
					        item_new.append(multiLists[count].split(','))
					        count += 1
					        index += 1
					    else:
					        item_new.append(item_temp[index])
					        index += 1
					fw_csr_list.append(item_new)
				time.sleep(1)
				print('\nOk, got it...\n\n')
				time.sleep(1)

			## Prints addresses entered from terminal, and addresses/attributes/crypto settings from CSV file ##
			elif addrMenuChoice == 3:
				time.sleep(1)
				print('\n')
				if len(fw_csr_list) > 0:
					print('\nAddresses input via CSV file:')
					for item in fw_csr_list:
						print(item[0] + ' - ' + str(item[1:]))
				if fwListCheck == True:
					print('\nAddresses input via terminal:')
					for addr in fw_addr_list:
						print(addr)
				if len(fw_csr_list) == 0 and fwListCheck == False:
					print('\nThere are no addresses input through terminal and CSV file')
				print('\n\n')
				time.sleep(1)
			elif addrMenuChoice == 4:
				time.sleep(1)
				print('\n\n')
				break
				continue
			else:
				time.sleep(1)
				print("\nYou've entered a number that is not in the list, try again...\n")
				time.sleep(1)
				continue
		except ValueError:
			time.sleep(1)
			print('\nYou must enter a number, try again...\n')
			time.sleep(1)
			continue


# Allows the user to generate CSRs
def menu_7():
	global fw_addr_list, fw_csr_list, mainkey, country, state, locality, organization, department, email, hostname, ip, altEmail, algorithm, bits, digest, expiration
	csrPath = 'PAN-FW-CSRs'

	## Create the CSR dir if it doesn't already exist ##
	if not os.path.exists(csrPath):
		os.mkdir(csrPath)
	certVals = []

	## If there were addresses entered via the terminal, add them to fw_csr_list, addresses from CSV would have already been added if they exist ##
	if len(fw_addr_list) > 0:
		[certVals.append(x) for x in [country, state, locality, organization, department, email, hostname, ip, altEmail, algorithm, bits, digest, expiration]]
		for item in fw_addr_list:
			x = [val for val in certVals]
			x.insert(0, item)
			fw_csr_list.append(x)

	## If the list is not empty (if the user didn't forget to add addresses) ##
	if len(fw_csr_list) > 0:
		if mainkey != '':
				print('\n\nAuthenticating to the first firewall in the list using your cached credentials...\n\n')
				time.sleep(1)
		else:
			print('\nEnter your credentials below, and you will be authenticated against the first firewall in the list...\n\n')
			mainkey = getkey(fw_csr_list[0][0])
			print('\n\n')
		## Process each firewall in the list, building the API call for each for generating CSRs ##
		for item in fw_csr_list:
			if item[10] == 'RSA':
				attributesXML = '<request><certificate><generate><certificate-name>PAN-FW_' + item[0] + '</certificate-name><name>' + item[0] + '</name><algorithm><RSA><rsa-nbits>' + item[11] + '</rsa-nbits></RSA></algorithm><digest>' + item[12] + '</digest><days-till-expiry>' + item[13] + '</days-till-expiry><signed-by>external</signed-by><ca>no</ca>'
			else:
				attributesXML = '<request><certificate><generate><certificate-name>PAN-FW_' + item[0] + '</certificate-name><name>' + item[0] + '</name><algorithm><ECDSA><ecdsa-nbits>' + item[11] + '</ecdsa-nbits></ECDSA></algorithm><digest>' + item[12] + '</digest><days-till-expiry>' + item[13] + '</days-till-expiry><signed-by>external</signed-by><ca>no</ca>'
			if item[1] != '':
				attributesXML = attributesXML + '<country-code>' + item[1] + '</country-code>'
			if item[2] != '':
				attributesXML = attributesXML + '<state>' + item[2] + '</state>'
			if item[3] != '':
				attributesXML = attributesXML + '<locality>' + item[3] + '</locality>'
			if item[4] != '':
				attributesXML = attributesXML + '<organization>' + item[4] + '</organization>'
			if item[6] != '':
				attributesXML = attributesXML + '<email>' + item[6] + '</email>'
			if item[5] != '':
				attributesXML = attributesXML + '<organization-unit>'
				if type(item[5]) == list:
					for i in item[5]:
						attributesXML = attributesXML + '<member>' + i + '</member>'
				else:
					attributesXML = attributesXML + '<member>' + item[5] + '</member>'
				attributesXML = attributesXML + '</organization-unit>'
			if item[7] != '':
				attributesXML = attributesXML + '<hostname>'
				if type(item[7]) == list:
					for i in item[7]:
						attributesXML = attributesXML + '<member>' + i + '</member>'
				else:
					attributesXML = attributesXML + '<member>' + item[7] + '</member>'
				attributesXML = attributesXML + '</hostname>'
			if item[8] != '':
				attributesXML = attributesXML + '<ip>'
				if type(item[8]) == list:
					for i in item[8]:
						attributesXML = attributesXML + '<member>' + i + '</member>'
				else:
					attributesXML = attributesXML + '<member>' + item[8] + '</member>'
				attributesXML = attributesXML + '</ip>'
			if item[9] != '':
				attributesXML = attributesXML + '<alt-email>'
				if type(item[9]) == list:
					for i in item[9]:
						attributesXML = attributesXML + '<member>' + i + '</member>'
				else:
					attributesXML = attributesXML + '<member>' + item[9] + '</member>'
			attributesXML = attributesXML + '</generate></certificate></request>'
			xmlURL_generate = 'https://' + item[0] + '/api/?type=op&cmd=' + attributesXML + '&key=' + mainkey

			## Send the API call to generate the CSR ##
			try:
				r = requests.get(xmlURL_generate, verify=False)
				tree = ET.fromstring(r.text)
				if tree.get('status') == "success":
					print('Certificate signing request was successfully generated for ' + item[0])
					xmlURL_export = 'https://' + item[0] + '/api/?type=export&category=certificate&certificate-name=PAN-FW_' + item[0] + '&format=pkcs10&include-key=no&key=' + mainkey
					r = requests.get(xmlURL_export, verify=False)
					csrFile = open(csrPath + '/PAN-FW_' + item[0] + '.csr', 'wb+')
					csrFile.write(r.content)
					csrFile.close()
					if os.path.exists(csrPath + '/PAN-FW_' + item[0] + '.csr'):					
						print('CSR file (PAN-FW_'  + item[0] +  '.csr) was exported and placed in the ' + csrPath + ' directory\n')
						if item[0] == fw_csr_list[-1][0]:
							raw_input('\nHit the Enter key to continue... ')
							print('\n\n')
					else:
						time.sleep(1)
						print('\n\n################ There was a problem with exporting the certificate signing request for ' + item[0] + ' ################')
						print("\nHere's the API call that went wonky:\n" + xmlURL_export)
						raw_input('\nHit the Enter key to continue... ')
						print('\n\n')
				else:
					time.sleep(1)
					print('\n\n################ There was a problem with generating the certificate signing request for ' + item[0] + ' ################')
					print("\nHere's the API call that went wonky:\n" + xmlURL_generate)
					raw_input('\nHit the Enter key to continue... ')
					print('\n\n')
			except Exception as e:
				time.sleep(1)
				print('\n\n[ERROR]: ' + str(e.message))
				time.sleep(1)
				raw_input('\nThis firewall will be skipped, hit the Enter key to continue... ')
		fileCheck = True

	## Just in cases the user forgot upload any address info ##
	else:
		time.sleep(1)
		print('\nYou forgot to input your firewall adresses, make sure you do that first...')
		time.sleep(1)
		raw_input('\n\nPress Enter to continue...\n\n')
		fileCheck = False

	## Saves the information from cert requests being generated, this will be used for pushing the signed certs back to the firewalls ##
	if fileCheck == True:
		datFile = open(csrPath + '/fw-list_mgt-certs.txt', 'w')
		datFile.write('##This file contains data from the last set of firewalls for which certificate signing requests were generated. This data will be used by the fw-mgt-cert rollout script for pushing the signed certificates back out to the firewalls listed in this file##\n')
		for item in fw_csr_list:
			for i in item:
				datFile.write(str(i) + ',')
			datFile.write('\n')
		datFile.close()


# Allows user to export CSR files to be signed by CA server
def menu_8():
	csrPath = 'PAN-FW-CSRs'
	pemPath = 'PAN-FW-PEMs'
	if not os.path.exists(pemPath):
		os.mkdir(pemPath)
	raw_input("\n\nThe script will pull CSR files from the PAN-FW-CSRs folder, and upload to an enterprise CA server\n\n\nHit the Enter key to continue...")
	print('\n\n')
	allReqIDs = []
	run = True
	while run:
		if not os.path.exists(csrPath):
			time.sleep(1)
			print('\n\nThe PAN-FW-CSRs directory does not exist...\nMake sure the directory exists and is populated with CSRs\n')
			time.sleep(1)
			break
		## Create a list of CSRs in the directory, removing the fw-list_mgt-certs.txt file from the list ##
		fwCSRs = os.listdir(csrPath)
		if os.path.exists(csrPath + '/fw-list_mgt-certs.txt'):
			fwCSRs.remove('fw-list_mgt-certs.txt')
		if fwCSRs == []:
			time.sleep(1)
			print('\n\nThe PAN-FW-CSRs directory is empty...\nMake sure the directory is populated with CSRs\n')
			time.sleep(1)
			break
		while True:
			caSvr_Address = raw_input('Enter the IP/FQDN address of your CA server: ')
			ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", caSvr_Address)
			fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", caSvr_Address)
			if ipr:
				break
			elif fqdnr:
				break
			else:
				print("There was something wrong with your entry. Please try again...\n")
		caSvr_uname = raw_input('Enter the username to perform CSR import: ')
		caSvr_password = getpass.getpass('Please enter your password: ')
		while True:
			caSvr_authType = raw_input('Enter the authentication type: [NTLM/basic]  ')
			if caSvr_authType == 'NTLM' or caSvr_authType == 'ntlm' or caSvr_authType == '':
				caSvr_authType = 'ntlm'
				caSvr_domain = raw_input('Enter your domain: ')
				break
			elif caSvr_authType == 'basic':
				break
			else:
				time.sleep(1)
				print("\n\nYou've entered an incorrect option, try 'ntlm' or 'basic' this time...\n")
				time.sleep(1)

		## Prompts the user to enter the name of the CA cert on the server, and checks to make sure it exists in the current directory ##
		while True:
			caSvr_caCert = raw_input("\nYou'll neeed to provide the root CA certificate for the CA server,\nmake sure you put it in the same directory as this script\n\nEnter the name of the cert: ")
			pwd = os.getcwd()
			if os.path.exists(pwd + '/' + caSvr_caCert):
				break
			else:
				time.sleep(1)
				print('The file does not exist (' + pwd.replace('\\\\', '\\') + '\\' + caSvr_caCert + ')\n\nPlease try again...')
				time.sleep(1)

		## Authenticates the user to the CA server, using the specified auth type and CA cert ##
		ca_server = certsrv.Certsrv(caSvr_Address, caSvr_uname, caSvr_password, auth_method=caSvr_authType, cafile=caSvr_caCert)

		## Checks the user's credentials to see if we can successfully authenticate to the CA server ##
		while True:
			try:
				credCheck = ca_server.check_credentials()
			except requests.exceptions.SSLError as e:
				time.sleep(1)
				print('\n\n' + str(e.message))
				print('\nThere was an issue with connecting over HTTPS - either the CA cert that you provided does not match the\nCA cert on the ADCS server, or the cert is not trusted for some reason. Check the cert and try again\n\n')
				time.sleep(1)
				exit()
			if credCheck == False:
				time.sleep(1)
				print("\n\nAuthentication to the CA server failed with the user credentials you provided, please try again...\n\n")
				caSvr_uname = raw_input('Enter the username to perform CSR import: ')
				caSvr_password = getpass.getpass('Please enter your password: ')
				ca_server = certsrv.Certsrv(caSvr_Address, caSvr_uname, caSvr_password, auth_method=caSvr_authType, cafile=caSvr_caCert)
			else:
				break

		## Pulls the html from the CA server to get the list of templates available to the user ##
		if caSvr_authType == 'ntlm':
			r = requests.get('https://' + caSvr_Address + '/certsrv/certrqxt.asp', auth=HttpNtlmAuth(caSvr_domain + '\\' + caSvr_uname, caSvr_password), verify=False)
		else:
			r = requests.get('https://' + caSvr_Address + '/certsrv/certrqxt.asp', auth=HTTPBasicAuth(caSvr_uname, caSvr_password), verify=False)
		tree = html.fromstring(r.content)
		templateOptions_display = tree.xpath('//*[@id="lbCertTemplateID"]/option/text()')		## Display values for template ##
		templateOptions = []
		for i in range(len(templateOptions_display)):
			templateOptions.append(tree.xpath('//*[@id="lbCertTemplateID"]/option')[i].get('value').split(';')[1])	## Actual template names ##

		## Displays a menu for the user to choose the template ##
		while True:
			time.sleep(1)
			print('\nPlease choose a template:\n')
			count = 1
			for item in templateOptions_display:
				print(str(count) + '. ' + item)
				count += 1
			try:
				templateChoice = int(raw_input('\nEnter your choice: '))
			except ValueError:
				time.sleep(1)
				print('\nYou must enter a number, try again...\n')
				time.sleep(1)
				continue
			if 0 >= templateChoice >= len(templateOptions_display):
				time.sleep(1)
				print("\nYou've entered a number that is not in the list, try again...\n")
				time.sleep(1)
				continue
			else:
				break
		caSvr_template = templateOptions[templateChoice - 1]

		## If there are are requests that are pending approval from previous sessions... ##
		reqIDcheck = True
		if os.path.exists(pemPath + '/reqIDs.txt'):
			reqFile = open(pemPath + '/reqIDs.txt', 'r')
			reqData = reqFile.read()
			reqFile.close()
			reqData = reqData.split(',')[:-1]
			run = True
			while run:
				reqIDprompt = raw_input('\n\nIt looks like there are requests that were pending approval.\nWould you like to attempt to retrieve the certs based off of those request IDs? [Y/n]  ')
				if reqIDprompt == 'n' or reqIDprompt == 'N':
					time.sleep(1)
					raw_input('\nOk, the CSRs in the ' + csrPath + ' directory will be uploaded to the CA server to be signed\n\nHit Enter to continue...')
					time.sleep(1)
					os.rename(pemPath + '/reqIDs.txt', pemPath + '/reqIDs_processed.txt')
					print('\n\nThe reqIDs.txt file was renamed to reqIDs_processed.txt')
					break

				## Query the CA server for each of the request IDs to see if they have been approved... ##
				elif reqIDprompt == 'y' or reqIDprompt == 'Y' or reqIDprompt == '':
					time.sleep(1)
					print('\n\n')
					for reqID in reqData:
						try:
							pemName = reqID.split('/')[0].replace('.csr', '.pem')
							pemFile = ca_server.get_existing_cert(reqID.split('/')[1], encoding='b64')
							certFile = open(pemPath + '/' + pemName, 'w')
							certFile.write(pemFile.replace('\r', ''))
							certFile.close()
							print(pemName + ' (request ID ' + reqID.split('/')[1] + ') was successfully saved to the ' + pemPath + ' directory')
							if reqID == reqData[-1]:
								if os.path.exists(pemPath + '/reqIDs_processed.txt'):
									os.remove(pemPath + '/reqIDs_processed.txt')
								os.rename(pemPath + '/reqIDs.txt', pemPath + '/reqIDs_processed.txt')
								print('\n\nThe reqIDs.txt file was renamed to reqIDs_processed.txt')
								run = False
								reqIDcheck = False
						except certsrv.CouldNotRetrieveCertificateException as e:
							time.sleep(1)
							print('\n\nSomething went wrong while attempting to fetch the cert, you may need to try again\n\n')
							time.sleep(1)
							run = False
							reqIDcheck = False
							break
						except:
							time.sleep(1)
							print('\n\nThere was an unknown error, you may need to try again\n\n')
							time.sleep(1)
							run = False
							reqIDcheck = False
							break
				else:
					time.sleep(1)
					print("\nYou did not enter one of the correct options, try 'y' or 'n'...")
					time.sleep(1)

		## If there were no requests pending approval, proceed with signing requests to CA server ##
		## The script will handle many of the error exections that can be generated from the CA server ##
		if reqIDcheck == True:
			print('\n\n')
			time.sleep(1)
			print('Contacting CA server...\n\n')
			time.sleep(1)
			for fw in fwCSRs:
				csrFile = open(csrPath + '/' + fw, 'r')
				csrData = csrFile.read()
				csrFile.close()
				try:
					pemFile = ca_server.get_cert(csrData, caSvr_template, encoding='b64', attributes=None)
					certFile = open(pemPath + '/' + fw.replace('.csr', '.pem'), 'w')
					certFile.write(pemFile.replace('\r', ''))
					certFile.close()
					print(fw.replace('.csr', '.pem') + ' was successfully saved to the ' + pemPath + ' directory')
					if fw == fwCSRs[-1]:
						run = False
				except certsrv.RequestDeniedException as e:
					time.sleep(1)
					print("\n\nYour request was denied by the ADCS server\n\n")
					print(e.message)
					time.sleep(1)
					break
				except certsrv.CertificatePendingException as e:
					time.sleep(1)
					req_id = e.req_id
					#allReqIDs.append(req_id)
					print('Your signing request for ' + fw + ' was placed, but it needs to be approved by a CA admin. The ID for this request is: ' + req_id)
					time.sleep(1)
					if fw == fwCSRs[0]:
						reqFile = open(pemPath + '/reqIDs.txt', 'w')
					reqFile.write(fw + '/' + req_id + ',')
					if fw == fwCSRs[-1]:
						reqFile.close()
						print('\nAll of your request IDs have been saved to a text file called reqIDs.txt in the ' + pemPath + ' directory.\nOnce the requests are approved and certs issued, run the script again and it will pull the certs based on the IDs in the file.')
						run = False
				except certsrv.CouldNotRetrieveCertificateException as e:
					time.sleep(1)
					print('\n\nSomething went wrong while fetching the cert, you may need to try again\n\n')
					time.sleep(1)
					break
				except requests.exceptions.SSLError as e:
					time.sleep(1)
					print('\n\nThere was an issue with connecting over HTTPS - either the CA cert that you provided does not match the\nCA cert on the ADCS server, or the cert is not trusted for some reason. Check the cert and try again\n\n')
					time.sleep(1)
					break
				except requests.exceptions.HTTPError as e:
					time.sleep(1)
					print('\n\n' + str(e.message))
					print('Your request failed authentication. Either your credentials are incorrect, or you chose the wrong authentication type\n\n')
					time.sleep(1)
					break
				except:
					time.sleep(1)
					print('\n\nThere was an unknown error, you may need to try again\n\n')
					time.sleep(1)
					break
	print('\n\n')
	time.sleep(1)


# Allows user to push signed certificates to firewalls
def menu_9():
	global fw_csr_list, mainkey
	csrPath = 'PAN-FW-CSRs'
	pemPath = 'PAN-FW-PEMs'
	fileCheck = True
	if os.path.exists(csrPath + '/fw-list_mgt-certs.txt'):
		datFile = open(csrPath + '/fw-list_mgt-certs.txt', 'r')
	else:
		time.sleep(1)
		print('The data file containing CSR info for your firewalls (fw-list_mgt-certs.txt) seems to be missing.\nYou will need this file in order to push your signed certificates using this script. If you cannot\nfind it, then you will need to import the certs manually or generate new CSRs.\n\n\n')
		time.sleep(1)
		fileCheck = False
	if fileCheck == True:
		lines = datFile.readlines()
		lines = lines[1:]
		datFile.close()
		fw_csr_list = []
		for line in lines:
			fw_csr_list.append(line.split(',')[:-1])

		if mainkey != '':
				print('\n\nAuthenticating to the first firewall in the list using your cached credentials...\n\n')
				time.sleep(1)
		else:
			print('\nEnter your credentials below, and you will be authenticated against the first firewall in the list...\n\n')
			mainkey = getkey(fw_csr_list[0][0])
		print('\n\n')

		## Process through each firewall in the list, pushing the corresponding cert to each ##
		for item in fw_csr_list:
			pemFile = 'PAN-FW_' + item[0] + '.pem'
			pemName = 'PAN-FW_' + item[0]
			if not os.path.exists(pemPath + '/' + pemFile):
				time.sleep(1)
				print('\n\nThere is a certificate missing (' + pemFile + ')')
			else:
				params = {'file': (pemFile, open(pemPath + '/' + pemFile, 'rb'))}
				xmlURL_import = 'https://' + item[0] + '/api/?type=import&category=certificate&certificate-name=' + pemName + '&format=pem&key=' + mainkey
				try:
					r = requests.post(xmlURL_import, files=params, verify=False)
					tree = ET.fromstring(r.text)
					if tree.get('status') == "success":
						print('The cert import succeeded for ' + item[0])
					else:
						time.sleep(1)
						print('\n\n################ There was a problem with pushing the certificate to ' + item[0] + ' ################')
						print("\nHere's the API call that went wonky:\n" + xmlURL_import)
						raw_input('\nHit the Enter key to continue... ')
						print('\n\n')
				except Exception as e:
					time.sleep(1)
					print('\n\n[ERROR]: ' + str(e.message))
					time.sleep(1)
					raw_input('\nThis firewall will be skipped, hit the Enter key to continue... ')
		print('\n\n')


# Allows user to create SSL/TLS cert profiles, associate cert, and apply to management interface
def menu_10():
	global fw_csr_list, mainkey
	raw_input('\n\nThe script will pull a list of firewall addresses from the fw-list_mgt-certs.txt\nfile saved in the PAN-FW-CSRs folder. SSL/TLS cert profiles will be created, for\nwhich management certs will be associated, then attached to the management interface.\n\n\nHit the Enter key to continue...')
	print('\n\n')
	fileCheck = True
	if os.path.exists('PAN-FW-CSRs/fw-list_mgt-certs.txt'):
		datFile = open('PAN-FW-CSRs/fw-list_mgt-certs.txt', 'r')
	else:
		time.sleep(1)
		print('The data file containing CSR info for your firewalls (fw-list_mgt-certs.txt) seems to be missing.\nYou will need this file in order to create SSL/TLS cert profiles using this script. If you cannot\nfind it, then you will need to create the file and populate it with a header and list of addresses.\n\n\n')
		time.sleep(1)
		fileCheck = False
	if fileCheck == True:
		lines = datFile.readlines()
		lines = lines[1:]
		datFile.close()
		fw_csr_list = []
		for line in lines:
			fw_csr_list.append(line.split(',')[:-1])
		if mainkey != '':
				print('\n\nAuthenticating to the first firewall in the list using your cached credentials...\n\n')
				time.sleep(1)
		else:
			print('\nEnter your credentials below, and you will be authenticated against the first firewall in the list...\n\n')
			mainkey = getkey(fw_csr_list[0][0])
		print('\n\n')
		for item in fw_csr_list:
			xmlURL_addCertProf = "https://" + item[0] + "/api/?type=config&action=set&xpath=/config/shared/ssl-tls-service-profile/entry[@name='PAN-FW-Mgt_cert-profile']&element=<protocol-settings><min-version>tls1-0</min-version><max-version>max</max-version></protocol-settings><certificate>PAN-FW_" + item[0] + "</certificate>&key=" + mainkey
			xmlURL_profAdd2Mgt = 'https://' + item[0] + '/api/?type=config&action=set&xpath=/config/devices/entry/deviceconfig/system&element=<ssl-tls-service-profile>PAN-FW-Mgt_cert-profile</ssl-tls-service-profile>&key=' + mainkey
			try:
				r = requests.get(xmlURL_addCertProf, verify=False)
				tree = ET.fromstring(r.text)
				if tree.get('status') == "success":
						print('The cert profile was created, and cert associated for ' + item[0])
				else:
					time.sleep(1)
					print('\n\n################ There was a problem with creating the cert profile for ' + item[0] + ' ################')
					print("\nHere's the API call that went wonky:\n" + xmlURL_addCertProf)
					raw_input('\nHit the Enter key to continue... ')
					print('\n\n')
					continue
			except Exception as e:
				time.sleep(1)
				print('\n\n[ERROR]: ' + str(e.message))
				time.sleep(1)
				raw_input('\nThis firewall will be skipped, hit the Enter key to continue... ')
			try:
				r = requests.get(xmlURL_profAdd2Mgt, verify=False)
				tree = ET.fromstring(r.text)
				if tree.get('status') == "success":
						print('The cert profile was applied to the management interface for ' + item[0] + '\n')
				else:
					time.sleep(1)
					print('\n\n################ There was a problem with applying the cert profile for ' + item[0] + ' ################')
					print("\nHere's the API call that went wonky:\n" + xmlURL_profAdd2Mgt)
					raw_input('\nHit the Enter key to continue... ')
					print('\n\n')
			except Exception as e:
				time.sleep(1)
				print('\n\n[ERROR]: ' + str(e.message))
				time.sleep(1)
				raw_input('\nThis firewall will be skipped, hit the Enter key to continue... ')
		print('\n\n')
		time.sleep(1)


# Give the user the option to commit the firewalls, with or without validation
def menu_11():
	global fw_csr_list, mainkey
	raw_input("\n\nThe script will pull a list of firewall addresses from the fw-list_mgt-certs.txt\nfile saved in the PAN-FW-CSRs folder. You'll have the option to send commits to\nall the firewalls on the list, with or without validation.\n\n\nHit the Enter key to continue...")
	print('\n\n')
	fileCheck = True
	if os.path.exists('PAN-FW-CSRs/fw-list_mgt-certs.txt'):
		datFile = open('PAN-FW-CSRs/fw-list_mgt-certs.txt', 'r')
	else:
		time.sleep(1)
		print('The data file containing CSR info for your firewalls (fw-list_mgt-certs.txt) seems to be missing.\nYou will need this file in order to create SSL/TLS cert profiles using this script. If you cannot\nfind it, then you will need to create the file and populate it with a header and list of addresses.\n\n\n')
		time.sleep(1)
		fileCheck = False
	if fileCheck == True:
		lines = datFile.readlines()
		lines = lines[1:]
		datFile.close()
		fw_csr_list = []
		for line in lines:
			fw_csr_list.append(line.split(',')[:-1])
		if mainkey != '':
				print('\n\nAuthenticating to the first firewall in the list using your cached credentials...\n\n')
				time.sleep(1)
		else:
			print('\nEnter your credentials below, and you will be authenticated against the first firewall in the list...\n\n')
			mainkey = getkey(fw_csr_list[0][0])
		commitCheck1 = True
		commitCheck2 = True
		for item in fw_csr_list:
			if commitCheck1 == True and len(fw_csr_list) > 1:
				while True:
					## ENSURES THE USER WILL ONLY BE PROMPTED FOR THE FIRST FIREWALL COMMIT ##
					if commitCheck2 == True:
						commitInput = raw_input("\n\nWould you like to step through validation on each firewall during the commit process?\n(A 'No' answer will automatically send commits without validation to the firewalls once config is pushed) [y/n]  ")
						print('')
						if commitInput == 'Y' or commitInput == 'y':
							fwCommit_withValidation(item[0], mainkey)
							commitCheck1 = False
							break
						elif commitInput == 'N' or commitInput == 'n':
							fwCommit_withoutValidation(item[0], mainkey)
							commitCheck2 = False
							break
						else:
							time.sleep(1)
							print('\nYou seemed to have chosen the wrong key. Please try \"y\" or \"n\" this time...\n')
					else:
						fwCommit_withoutValidation(item[0], mainkey)
						break
			else:
				fwCommit_withValidation(item[0], mainkey)
		print('\n')


# Exits the script
def menu_12():
	time.sleep(1)
	print('\n\nBye for now, have a great day!!\n\n\n')
	time.sleep(1)
	exit()


# Ties the menu option chosen by the user to the corresponding function
def mainMenuOptions(menuChoice):
	options = {
		1: menu_1,
		2: menu_2,
		3: menu_3,
		4: menu_4,
		5: menu_5,
		6: menu_6,
		7: menu_7,
		8: menu_8,
		9: menu_9,
		10: menu_10,
		11: menu_11,
		12: menu_12,
	}
	# Get the function from options dictionary
	if 12 >= menuChoice >= 1:
		func = options.get(menuChoice)
		# Executes the function
		return func()
	else:
		return 0


def main():
	print('\n\n*********************************************************************************************************************************\n*********************************************************************************************************************************')
	print("This script will enable you to create certificate signing requests for any number of firewalls, then push the signed certificates\nback out to each firewall once they are signed by your enterprise CA. You will have the ability to provide attribute information\nfor the CSRs. This can either be done with a CSV file, or the info can be provided through menus within this script. Use a CSV\nfile if the attributes differ among the firewalls. If the attributes are the same across all firewalls, or you don't need to add\nattributes, then you should use the menus. The CN field within certificates will be the IP/FQDN that you provide either in the\nlist that follows, or in the CSV file.\n\n\nIf you choose to use a CSV file, the format should be the following for each entry:\n\nIP/FQDN, country, state, locality, organization, [department], email, [hostname], [IP], [alt email], algorithm, bits, digest, expiration\n--Attributes with brackets have an option to add multiples, be sure to enclose comma-separated entries with brackets if there are multiples--")
	print('*********************************************************************************************************************************************\n*********************************************************************************************************************************************\n\n')

	raw_input('\nPress Enter to continue...')
	print('\n\n')

	## Displays the menu options to the user ##
	while True:
		try:
			x = mainMenuOptions(menuChoice = int(raw_input('--------------------------------------------------------------------------------\nChoose an option below to add certificate attributes and crypto settings,\nand add addresses via the terminal and/or CSV file. Choose exit when finished...\n--------------------------------------------------------------------------------\n\n1.  Add/Modify Attributes\n2.  Modify Crypto Settings\n3.  Modify Expiration\n4.  Clear Attributes/Crypto Settings\n5.  Print Attributes/Crypto Settings\n6.  Input Addresses\n7.  Create Certificate Signing Requests\n8.  Interface with Enterprise CA Server\n9.  Push Signed Certificates to Firewalls\n10. Create/Apply Cert Profiles to Firewalls\n11. Validate/Commit Firewalls\n12. Exit\n\n--------------------------------------------------------------------------------\n\nEnter your choice: ')))
		except ValueError:
			time.sleep(1)
			print('\nYou must enter a number, try again...\n\n')
			time.sleep(1)
			continue
		if x == 0:
			time.sleep(1)
			print("\nYou've entered a number that is not in the list, try again...\n\n")
			time.sleep(1)

if __name__ == '__main__':
	main()