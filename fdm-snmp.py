#!/usr/local/bin/python3

import getpass
import json
import sys
import requests
import warnings

VERSION = "1.0.7"
interface_counter = 0
valid_interface = []
headers = {}
device = ""

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def do_auth():
	global device
	global headers

	device = input("Enter the FDM Management IP address: ")
	#device = "172.16.0.10"
	username = "admin"
	password = getpass.getpass("Enter the admin password for FDM: ")
	#password = ""

	url = "https://"+device+"/api/fdm/latest/fdm/token"
	payload = ('{ "grant_type": "password","username": "%s", "password": "%s" }'%(username,password))
	headers = {
							'Content-Type': 'application/json',
							'Accept': 'application/json'
					}
	response=None
	try:
		response = requests.post(url, headers=headers, data = payload, verify=False)
		#print('Auth-Status code is ',response.status_code)
		auth_body=json.loads(response.text)
		if response.status_code==500:
			print('Internal Server Error')
			sys.exit()
		auth_token = auth_body.get('access_token')
		if auth_token == None:
			print("auth_token not found. Exiting...")
			#print(auth_body)
			sys.exit()
		elif response.status_code==200:
			print('Successfully Authenticated')
			headers = { 'Authorization': 'Bearer '+auth_token,
						'Content-Type': 'application/json',
						'Accept': 'application/json'
						}
			#return(auth_token)
	except Exception as err:
		print ("Error generated from auth() function --> "+str(err))
		sys.exit()

def create_hostobj(name,ip):
	url = "https://"+device+"/api/fdm/latest/object/networks"
	payload={ "name": name,
					  "description": "SNMP Server Host",
					  "subType": "HOST",
					  "value": ip,
					  "dnsResolution": "IPV4_ONLY",
					  "type": "networkobject"}
	response=None
	try:
		response = requests.post(url, headers=headers, data = json.dumps(payload), verify=False)
		response_body=json.loads(response.text)
		if response.status_code==200:
			return response_body
		else:
			print(response_body)
			sys.exit()

	except Exception as err:
		print ("Error creating Host --> "+str(err))
		sys.exit()

def create_snmpv3user(snmpv3_payload):
	url = "https://"+device+"/api/fdm/latest/object/snmpusers"
	response=None
	try:
		response = requests.post(url, headers=headers, data = json.dumps(snmpv3_payload), verify=False)
		response_body=json.loads(response.text)
		if response.status_code==200:
			return response_body
		else:
			print(response_body)

	except Exception as err:
		print ("Error creating Host --> "+str(err))
		sys.exit()

def get_ipAddress(iface):
	if iface['ipv4']['ipAddress'] == None or iface['ipv4']['ipAddress']['ipAddress'] == None:
		return "n/a"
	else:
		return iface['ipv4']['ipAddress']['ipAddress']

def print_interface(iface):
	ipAddr = get_ipAddress(iface)
	print ("{:<5} {:<18} {:<20} {:<20} {:<40}".format(interface_counter+1, iface['name'], iface['hardwareName'], ipAddr, iface['id']))
	#print ("{:<5} {:<18} {:<20} {:<40}".format(interface_counter+1, iface['name'], iface['hardwareName'], iface['id']))


def enumerate_interfaces (url, subint):
	global valid_interface
	global interface_counter
	try:
		responses=[]
		int_url = url + "?limit=25"
		get_int = requests.get(int_url, headers=headers, verify=False)
		responses.append(get_int)

		if get_int.status_code==200:
			# Enumerate the interfaces
			for response in responses:
				for interface in response.json()['items']:
					if interface['name'] is not None:
						if interface['name'] !='':
							valid_interface.append(interface)
							print_interface(valid_interface[interface_counter])
							interface_counter+=1
					# if subint is True, lets try to enumerate the subinterfaces
					if subint == True:
						sub_responses=[]
						int_id = interface['id']
						subint_url = url + "/" + int_id + "/subinterfaces?limit=25"
						get_subinterfaces = requests.get(subint_url, headers=headers, verify=False)
						if get_subinterfaces.status_code==200:
							sub_responses.append(get_subinterfaces)
							for sub_resp in sub_responses:
								for subint in sub_resp.json()['items']:
									if subint['name'] is not None and subint['name'] !='':
										valid_interface.append(subint)
										print_interface(valid_interface[interface_counter])
										interface_counter+=1
		elif get_int.status_code==404:
			# remote device may not support some interface types - bugfix thanks to Saurabh Pawar 10-04-2022
			return()
		else:
			print(responses)
			sys.exit()

	except Exception as err:
		print ("Error in interface selection --> "+str(err))
		sys.exit()

def select_interface():
	global interface_counter
	interface_counter=0
	enumerate_interfaces("https://"+device+"/api/fdm/latest/devices/default/interfaces", True)
	enumerate_interfaces("https://"+device+"/api/fdm/latest/devices/default/vlaninterfaces", False)
	enumerate_interfaces("https://"+device+"/api/fdm/latest/devices/default/etherchannelinterfaces", True)

	while True:
		try:
			interface_selection = int(input("\nSelect the interface facing your SNMP server [1-{:<1}]: ".format(interface_counter))) -1 # -1 because that's how they're stored
			if interface_selection > 0 and interface_selection < interface_counter:
				return valid_interface[interface_selection]
		except ValueError:
			print ("\nInvalid selection...")

def create_snmphost(sec_Configuration,host):
	interface=select_interface() #version, name, id and type
	snmp_hostname=input('Enter SNMP host object name : ')
	url = "https://"+device+"/api/fdm/latest/object/snmphosts"
	payload={
				"name": snmp_hostname,
				"managerAddress": {
										"version": host['version'],
										"name": host['name'],
										"id": host['id'],
										"type": host['type']
									},
				"pollEnabled": True,
				"trapEnabled": True,
				"securityConfiguration": sec_Configuration,
				"interface": {
									"version": interface['version'],
									"name": interface['name'],
									"id": interface['id'],
									"type": interface['type']
								},
				"type": "snmphost"
			}
	response=None

	try:
		response = requests.post(url, headers=headers, data = json.dumps(payload), verify=False)
		#print('\nHTTP RESPONSE CODE', r.status_code)
		response_body=json.loads(response.text)
		if response.status_code==200:
			print('Successfully Created, please deploy and check SNMP config')
		else:
			print(response_body)

	except Exception as err:
		print ("Error creating Host --> "+str(err))
		sys.exit()

def get_networkHost_IP(object_id):
	url="https://"+device+"/api/fdm/latest/object/networks/"+object_id
	try:
		get_host = requests.get(url, headers=headers, verify=False)
		if get_host.status_code==200:
			return get_host.json()['value']
		else:
			print(json.loads(get_host.text))
	except Exception as err:
		print ("Error fetching networkHost information --> "+str(err))
		sys.exit()

def print_snmp_config(config_count,config):
	if config_count	== 0:
		print ("\n>>> SNMP Configurations on " + device +" >>>")
		print ("{:<5} {:<20} {:<10} {:<15} {:<20} {:<12}".format("#","snmpHost", "nameif", "interface", "networkObject", "ipAddress"))
	serverIP=get_networkHost_IP(config['managerAddress']['id'])
	print ("{:<5} {:<20} {:<10} {:<15} {:<20} {:<12}".format(config_count+1,config['name'], config['interface']['name'], config['interface']['hardwareName'], config['managerAddress']['name'], serverIP))

def delete_SNMP_config(networkObject_id, snmpHost_id):
	try:
		print("deleting snmpHost_id - " + snmpHost_id, end='')
		resp = requests.delete("https://"+device+"/api/fdm/v6/object/snmphosts/"+snmpHost_id, headers=headers, verify=False)
		if resp.status_code != 204:
			print ("Error deleting snmpHost ("+resp.status_code+") object id -- "+snmpHost_id)
			print (resp.json)
		else:
			print (".... deleted")

		print("deleting networkObject_id - " + networkObject_id, end='')
		resp = requests.delete("https://"+device+"/api/fdm/v6/object/networks/"+networkObject_id, headers=headers, verify=False)
		if resp.status_code != 204:
			print ("Error deleting networkObject ("+resp.status_code+") object id -- "+networkObject_id)
			print (resp.json)
		else:
			print (".... deleted")
	except Exception as err:
		print ("Error in snmp config delection --> "+str(err))
		sys.exit()

def new_SNMP_config():
	while True:
		snmp_version=int(input("\nSelect SNMP version to configure...\n\n 2. SNMPv2\n 3. SNMPv3\n [2-3]: "))
		if snmp_version in [2,3]:
			break
	name=input("\nEnter the SNMP Server object name : ")
	ip= input("Enter the SNMP Server object IP : ")
	host=create_hostobj(name, ip) #version, name, id and type

	sec_Configuration={}

	if snmp_version==2: #SNM v2
		community_str=input('Enter SNMPv2 community string : ')
		sec_Configuration= {
								"community": community_str,
								"type": "snmpv2csecurityconfiguration"
							}
	elif snmp_version==3: # SNMPv3
		snmpv3_payload={}
		snmpv3_payload['type']='snmpuser'
		snmpv3_payload['name'] = input('Enter SNMPv3 username : ')

		while True:
			snmpv3_payload['securityLevel'] = input("Enter Security Level => Options ['AUTH', 'NOAUTH', 'PRIV'] :  ")
			if snmpv3_payload['securityLevel'] in ['AUTH','NOAUTH','PRIV']:
				break

		if snmpv3_payload['securityLevel'] in ['AUTH','PRIV']:
			while True:
				snmpv3_payload['authenticationAlgorithm'] = input("Enter authentication Algorithm => Options ['SHA', 'SHA256'] : ")
				if snmpv3_payload['authenticationAlgorithm'] in ['SHA','SHA256']:
					break
			while True:
				snmpv3_payload['authenticationPassword']=getpass.getpass("Enter authentication password : ")
				if not snmpv3_payload['authenticationPassword'] == "":
					break

		if snmpv3_payload['securityLevel'] == "PRIV":
			while True:
				snmpv3_payload['encryptionAlgorithm']= input("Enter encryption Algorithm => Options ['AES128', 'AES192', 'AES256', '3DES'] : ")
				if snmpv3_payload['authenticationAlgorithm'] in ['AES128','AES192','AES256','3DES']:
					break
			while True:
				snmpv3_payload['encryptionPassword']=getpass.getpass("Enter encryption password : ")
				if not snmpv3_payload['encryptionPassword'] == "":
					break

		user=create_snmpv3user(snmpv3_payload) #version, name, id and type

		sec_Configuration = {
								"authentication": {
														"version": user['version'],
														"name": user['name'],
														"id": user['id'],
														"type": user['type']
													},
								"type": "snmpv3securityconfiguration"
							}

	create_snmphost(sec_Configuration,host)

def edit_SNMP_configs(do_edit):
	try:
		url="https://"+device+"/api/fdm/v6/object/snmphosts"
		get_resp = requests.get(url+"?limit=25", headers=headers, verify=False)

		if get_resp.status_code==200:
			configs=[]
			config_count=0

			for line in get_resp.json()['items']:
				if line['name'] is not None:
					configs.append(line)
					print_snmp_config(config_count,line)
					config_count+=1
		else:
			print (get_resp)
			sys.exit()
		print ()
		while do_edit:
			if get_resp.json()['paging']['count'] == 0:
				print ("No SNMP Configurations Present")
				return
			else:
				while True:
					try:
						selection = int(input("Enter line to delete, or 0 to exit [0-" + str(config_count) + "]: "))

						if selection == 0:
							return
						elif selection <= config_count:
							delete_SNMP_config(configs[selection-1]['managerAddress']['id'],configs[selection-1]['id'])
							break
					except ValueError:
						print ("\nInvalid selection...\n")

	except Exception as err:
		print ("Error in snmp config retrieval --> "+str(err))
		sys.exit()

def main():

	def print_menu():       # Your menu design here
		edit_SNMP_configs(False)
		print(" 1. Add a new SNMP Configuration")
		print(" 2. Delete a current SNMP Configuration")
		print(" 0. Exit")

	print (" **********************************************")
	print (" *                                            *")
	print (" * FDM SNMP Configuration Tool                *")
	print (" *   version {:<32} *".format(VERSION))
	print (" *                   (c) Tony Mattke 2022     *")
	print (" *                                            *")
	print (" **********************************************")
	do_auth()

	while True:
		print_menu()
		choice = input("\n>Enter your choice [0-2]: ")

		if choice == '1':
			new_SNMP_config()
		elif choice == '2':
			edit_SNMP_configs(True)
		elif choice == '0':
			print("\nExiting..")
			sys.exit()
		else:
			input("Invalid selection, press enter to continue..")

###################################################################################################################
###################################################################################################################
###################################################################################################################
###################################################################################################################
###################################################################################################################

main()

print ("Error: How did we get here....")
sys.exit()
