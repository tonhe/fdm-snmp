#!/usr/local/bin/python3
import sys
import os
import json
import getpass
import keyring
import requests
import warnings
import argparse

DEBUG = False

class FDM:
    def __init__(self, hostname):
        self.hostname = hostname
        self.headers=""
        self.interface_counter = 0
        self.valid_interface = []
        self.SNMPconfigs = []

    def do_auth(self, username, password):
        url = "https://"+self.hostname+"/api/fdm/latest/fdm/token"
        payload = ('{ "grant_type": "password","username": "%s", "password": "%s" }' % (username, password))
        self.headers = {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json'
                        }
        response=None
        try:
            response = requests.post(url, headers=self.headers, data = payload, verify=False)
            auth_body=response.json()
            if response.status_code==500:
                print ("\n!! Error - Internal Server Error\n")
                return False
            auth_token = auth_body.get('access_token')
            if auth_token == None: 
                print("Invalid Password\n")
                return False
            elif response.status_code==200:
                print('Successfully Authenticated')
                self.headers = { 'Authorization': 'Bearer '+auth_token,
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                            }
                return True
        except Exception as err:
            print ("Error generated from auth() function --> "+str(err))
            sys.exit()


    def get(self, url):
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            if response.status_code==200:
                return response
        except Exception as e:
            print ("!! ERROR API Get - "+str(e))
            sys.exit()
        return

    def post(self, url, data):
        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(data), verify=False)
            response_body=response.json()
            if response.status_code==200:
                return response_body
            else:
                print(response_body)
        except Exception as e:
            print ("!! ERROR API Post - "+str(e))
            sys.exit()
        return

    def delete(self, url):
        try:
            response = requests.delete(url, headers=self.headers, verify=False)
            if response.status_code != 204:
                print (response.json)
        except Exception as e:
            print ("!! ERROR in API Delete - "+str(e))
            sys.exit()
        return

    def close(device): # NEEDS FINISHED
    #https://developer.cisco.com/docs/ftd-api-reference/latest/#!authenticating-your-rest-api-client-using-oauth/refreshing-an-access-token
        header={
            "grant_type": "revoke_token",
            "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MDI5MDQzMjQsInN1YiI6ImFkbWluIiwianRpIjoiZTMzNGIxOWYtODJhNy0xMWU3LWE4MWMtNGQ3NzY2ZTExMzVkIiwibmJmIjoxNTAyOTA0MzI0LCJleHAiOjE1MDI5MDYxMjQsInJlZnJlc2hUb2tlbkV4cGlyZXNBdCI6MTUwMjkwNjcyNDExMiwidG9rZW5UeXBlIjoiSldUX0FjY2VzcyIsIm9yaWdpbiI6InBhc3N3b3JkIn0.OVZBT9yVZc4zxZfZiiLH4SZcFclaHyCPbZJC_Gyd5FE",
            "custom_token_subject_to_revoke": "api-client"
        }
        return

###################################################################################################
###################################################################################################

def dprint(line):
    if DEBUG:
        print("(d) %s" % line)

def refreshSNMPconfigs(device):
    device.SNMPconfigs=[]
    url="https://%s/api/fdm/v6/object/snmphosts?limit=25" % device.hostname
    response = device.get(url)
    if response.status_code==200:
        for line in response.json()['items']:
            if line['name'] is not None:
                device.SNMPconfigs.append(line)

def printSNMPconfigs(device):
    if len(device.SNMPconfigs) == 0:
        print("\nNo SNMP Configurations Present")
        return
    print("\n>>> SNMP Configurations on " + device.hostname +" >>>")
    print("{:<5} {:<20} {:<10} {:<15} {:<20} {:<12}".format("#","snmpHost", "nameif", "interface", "networkObject", "ipAddress"))
    line = 0
    for config in device.SNMPconfigs:
        line = +1
        serverIP=get_networkHost_IP(device, config['managerAddress']['id'])
        print ("{:<5} {:<20} {:<10} {:<15} {:<20} {:<12}".format(line,config['name'], config['interface']['name'], config['interface']['hardwareName'], config['managerAddress']['name'], serverIP))
 
def create_hostobj(device, name, ip):
    url = "https://"+device.hostname+"/api/fdm/latest/object/networks"
    payload={ "name": name,
              "description": "SNMP Server Host",
              "subType": "HOST",
              "value": ip,
              "dnsResolution": "IPV4_ONLY",
              "type": "networkobject"}
    dprint("creating host object")
    response_body = device.post(url, payload)
    return response_body

def create_snmpv3user(device, snmpv3_payload):
    url = "https://"+device.hostname+"/api/fdm/latest/object/snmpusers"
    response_body = device.post(url, snmpv3_payload)
    return response_body

def get_ipAddress(iface):
    if iface['ipv4']['ipAddress'] == None or iface['ipv4']['ipAddress']['ipAddress'] == None:
        return "n/a"
    else:
        return iface['ipv4']['ipAddress']['ipAddress']

def print_interface(device, iface):
    ipAddr = get_ipAddress(iface)
    print ("{:<5} {:<18} {:<20} {:<20} {:<40}".format(device.interface_counter+1, iface['name'], iface['hardwareName'], ipAddr, iface['id']))

def find_interfaces (device, nameif=""): # Populates valid interfaces, if nameif is sent, we return a matching interface
    # This is a list of API URLs for the interface types we want to retrieve, True/False = if they can have subinterfaces
    INT_OPS = [
        ("https://"+device.hostname+"/api/fdm/latest/devices/default/interfaces", True),
        ("https://"+device.hostname+"/api/fdm/latest/devices/default/vlaninterfaces", False),
        ("https://"+device.hostname+"/api/fdm/latest/devices/default/etherchannelinterfaces", True)]
    device.interface_counter = 0
    for url, subint in INT_OPS:
        try:
            responses=[]
            int_url = url + "?limit=25"
            #get_int = device.get(int_url)
            response = device.get(int_url)
            if response.status_code==200:
                for interface in response.json()['items']: # There has to be a better way to iterate through this
                    if interface['name'] is not None and interface['name'] != '':
                        device.valid_interface.append(interface) # Add this to the list of valid interfaces
                        if nameif and (interface['name'] == nameif): # If we're searching for a name and we found it
                            print_interface(device, device.valid_interface[device.interface_counter])
                            return interface
                        elif not nameif:
                            print_interface(device, device.valid_interface[device.interface_counter])
                        device.interface_counter+=1
                    if subint == True: # if subint is True, lets try to enumerate the subinterfaces
                        sub_responses=[]
                        int_id = interface['id']
                        subint_url = url + "/" + int_id + "/subinterfaces?limit=25"
                        sub_response = device.get(subint_url)
                        if sub_response.status_code==200:
                            for subint in sub_response.json()['items']:
                                if subint['name'] is not None and subint['name'] !='':
                                    device.valid_interface.append(subint)
                                    if nameif and (subint['name'] == nameif):
                                        print_interface(device, device.valid_interface[device.interface_counter])
                                        return subint
                                    elif not nameif:
                                        print_interface(device, device.valid_interface[device.interface_counter])
                                    device.interface_counter+=1
            elif response.status_code==404: # remote device may not support some interface types - bugfix thanks to Saurabh Pawar 10-04-2022
                continue
            else:
                print("!! Error: %s" % responses)
        except Exception as err:
            print ("Error in interface selection --> "+str(err))
            sys.exit()
    
def select_interface(device, nameif=""):
    my_interface = find_interfaces(device, nameif) # This will search for a nameif (if specified) or print a list of interfaces
    if nameif: # if we're searching for a nameif, return that interface
        return my_interface
    while True: # Otherwise, have the user select one
        try:
            interface_selection = int(input("\nSelect the interface facing your SNMP server [1-{:<1}]: ".format(device.interface_counter))) -1 # -1 because that's how they're stored
            if (interface_selection > 0) and (interface_selection <= device.interface_counter):
                return device.valid_interface[interface_selection]
        except ValueError:
            print ("\nInvalid selection...")

def create_snmphost(device, secConfig, host, interface, snmp_hostname):
    url = "https://"+device.hostname+"/api/fdm/latest/object/snmphosts"
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
                "securityConfiguration": secConfig,
                "interface": {
                                    "version": interface['version'],
                                    "name": interface['name'],
                                    "id": interface['id'],
                                    "type": interface['type']
                                },
                "type": "snmphost"
            }
    device.post(url, payload)

def get_networkHost_IP(device, object_id):
    url="https://"+device.hostname+"/api/fdm/latest/object/networks/"+object_id
    get_host = device.get(url)
    if get_host.status_code==200:
        return get_host.json()['value']
    else:
        print(json.loads(get_host.text))
        sys.exit()

def delete_SNMP_config(device, networkObject_id, snmpHost_id):
    print("\nDeleting snmpHost_id - " + snmpHost_id, end='')
    url = "https://"+device.hostname+"/api/fdm/v6/object/snmphosts/"+snmpHost_id
    device.delete(url)
    
    print("\nDeleting networkObject_id - " + networkObject_id, end='')
    url="https://"+device.hostname+"/api/fdm/v6/object/networks/"+networkObject_id
    device.delete(url)

def getSNMPv2_config(community_str):
    secConfig = {
                                "community": community_str,
                                "type": "snmpv2csecurityconfiguration"
        }
    return secConfig

def getSNMPv3_config(user):
    secConfig = {
                                "authentication": {
                                                        "version": user['version'],
                                                        "name": user['name'],
                                                        "id": user['id'],
                                                        "type": user['type']
                                                    },
                                "type": "snmpv3securityconfiguration"
                            }
    return secConfig

def getSNMPv3_payload(username):
    payload={}
    payload['type']='snmpuser'
    payload['name'] = username
    while True:
        payload['securityLevel'] = input("Enter Security Level ['AUTH', 'NOAUTH', 'PRIV']: ")
        if payload['securityLevel'] in ['AUTH','NOAUTH','PRIV']:
            break
    if payload['securityLevel'] in ['AUTH','PRIV']:
        while True:
            payload['authenticationAlgorithm'] = input("Enter authentication Algorithm ['SHA', 'SHA256']: ")
            if payload['authenticationAlgorithm'] in ['SHA','SHA256']:
                break
        while True:
            payload['authenticationPassword']=getpass.getpass("Enter authentication password: ")
            if not payload['authenticationPassword'] == "":
                break
        if payload['securityLevel'] == "PRIV":
            while True:
                payload['encryptionAlgorithm']= input("Enter encryption Algorithm ['AES128', 'AES192', 'AES256', '3DES']: ")
                if payload['authenticationAlgorithm'] in ['AES128','AES192','AES256','3DES']:
                    break
            while True:
                payload['encryptionPassword']=getpass.getpass("Enter encryption password: ")
                if not payload['encryptionPassword'] == "":
                    break
    return payload

def newSNMPconfig_menu(device):
    name = ""
    while not name:
        name = input("\nEnter the SNMP Server object name : ")
    ip = ""
    while not ip:
        ip = input("Enter the SNMP Server object IP : ")
    while True:
        snmp_version=int(input("\nSelect SNMP version to configure...\n\n 2. SNMPv2\n 3. SNMPv3\n [2-3]: "))
        #snmp_version = 2 # disabling v3 for testing
        if snmp_version in [2,3]:
            break
    if snmp_version == 2: #SNMPv2
        community_str=input('Enter SNMPv2 community string : ')
        secConfig=getSNMPv2_config(community_str)
    elif snmp_version == 3:
        username=""
        while not username:
            username = input("Enter SNMPv username: ")
        v3payload = getSNMPv3_payload(username)
    snmp_hostname = ""
    while not snmp_hostname:
        snmp_hostname=input('Enter SNMP host object name : ')
    interface=select_interface(device) # Find the interface to listen on
    while True:
        ready=input("Ready to create objects on %s. Continue (y\\n)" % device.hostname)
        if isinstance(ready, str):
            ready=ready.lower()
        match ready:
            case 'y': # Will need to figure out what version we're configuring here
                if snmp_version==3: # v3 config only
                    dprint ("v3user=create_snmpv3user(device, %s)" % v3payload) 
                    v3user=create_snmpv3user(device, v3payload) 
                    dprint ("secConfig=getSNMPv3_config(%s)" % v3user)
                    secConfig=getSNMPv3_config(v3user)
                # This is for everyone now... 
                dprint("host=create_hostobj(device, %s, %s)" % (name, ip))
                host=create_hostobj(device, name, ip) #version, name, id and type
                dprint("create_snmphost(device, %s, %s, %s, %s)" % (secConfig, host, interface, snmp_hostname))
                create_snmphost(device, secConfig, host, interface, snmp_hostname)
                return
            case 'n':
                return
            case _:
                input("\nInvalid selection, press enter to continue..")

def deleteSNMPconfig_menu(device):
    while True:
        refreshSNMPconfigs(device)
        printSNMPconfigs(device)
        config_count = len(device.SNMPconfigs)
        dprint ("config count = %s" % config_count)
        if config_count == 0 :
            print("\nNo configurations present to edit...")
            return
        while True: 
            try: 
                selection = int(input("\nEnter line to delete, or 0 to exit [0-" + str(config_count) + "]: "))
                if isinstance(selection, int):
                    break
            except: 
                print("\n!! Invalid input")
        if selection == 0:
            return
        else:
            selection -= 1
            dprint ("adjusted selection %s" % selection)
            if selection <= len(device.SNMPconfigs):
                delete_SNMP_config(device, device.SNMPconfigs[selection-1]['managerAddress']['id'],device.SNMPconfigs[selection-1]['id'])
            else:
                print ("\nInvalid selection...\n")

def work_from_file(filename): # a fast way to add SNMPv2 to everything
    import csv
    format = ['HOSTNAME', 'USERNAME', 'PASSWORD' 'SERVER_NAME', 'SERVER_IP', 'NAMEIF', 'HOST_OBJ', 'SNMP_STRING']
    with open(filename, newline='', fieldnames=format) as file:
        csv_file = csv.DictReader(file)

    for line in csv_file:
        hostname=line['HOSTNAME']
        username=line['USERNAME']
        password=line['PASSWORD']
        server_name=line['SERVER_NAME']
        server_ip=line['SERVER_IP']
        nameif=line['NAMEIF']
        host_obj=line['HOST_OBJ']
        snmp_string=line['SNMP_STRING']

        dprint("['HOSTNAME', 'USERNAME', 'PASSWORD' 'SERVER_NAME', 'SERVER_IP', 'NAMEIF', 'HOST_OBJ', 'SNMP_STRING']")
        dprint(format)
        dprint("%s, %s, %s, %s, %s, %s, %s, %s" % (hostname, username, password, server_name, server_ip, nameif, host_obj, snmp_string))

        print("Logging into %s" % hostname)
        device=FDM(hostname)
        if not device.do_auth(username, password):
            print ("\nLogin error %s@%s\n" % (username, hostname))
            continue

        dprint ("host=create_hostobj(device, %s, %s)" % (server_name, server_ip))
        host=create_hostobj(device, server_name, server_ip) #version, name, id and type

        secConfig= {
                                "community": snmp_string,
                                "type": "snmpv2csecurityconfiguration"
                            }

        interface = find_interfaces(device, nameif)
        if not interface['nameif']:
            print("\nUnable to find interface %s on %s\n" % (nameif, hostname))
            continue

        dprint("create_snmphost(device, %s, %s, %s, %s)" % (secConfig, host, interface, host_obj))
        create_snmphost(device, secConfig, host, interface, host_obj)


###################################################################################################################
###################################################################################################################

def main():
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    VERSION = "1.3.0"
    KEYRING="fdm-snmp"
    SAVE_CREDS_TO_KEYRING = True # Do we save all of our creds to the keyring by default?
    AUTO_KEYCHAIN = True # Automagicallu try the keychain if no password supplied


    print (" **********************************************")
    print (" *                                            *")
    print (" * FDM SNMP Configuration Tool                *")
    print (" *   version {:<32} *".format(VERSION))
    print (" *                (c) Tony Mattke 2022-2023   *")
    print (" *                                            *")
    print (" **********************************************\n")
    
    parser = argparse.ArgumentParser(prog="python3 fdm-snmp.py",
                                     description="API Management of FDM SNMP Configurations")
    parser.add_argument("host", help="FDM Managment IP/Hostname", default="", nargs="*")
    parser.add_argument("-u", "--user", dest="user", help="User ID for login (admin is default)", default="admin")
    parser.add_argument("-k", "--keyring", dest="keyring", help="Pull password from local keyring (by hostname)", action="store_true")
    parser.add_argument("-p", "--password", dest="change_password", help="Change keyring password via interactive login", action="store_true")
    parser.add_argument("-d", dest="debug", help=argparse.SUPPRESS, action="store_true")
    args = parser.parse_args()

    username=args.user
    hostname=""
    password=""

    if args.debug:
        global DEBUG 
        DEBUG = True
        print(">Debug ON")
    if args.host:
        hostname = args.host[0]
    while not hostname:
        hostname = input("Enter the FDM Management IP/Hostname: ")
    if "@" in hostname: # for those that username@hostname
        username=args.host.split('@')[0]
        hostname=args.host.split('@')[1]
    while not username: # Should literlaly never need this
        username = getpass.getuser("Username: ")
    if (args.keyring or AUTO_KEYCHAIN) and not args.change_password:
        print("Pulling password from local keyring.")
        password=keyring.get_password(KEYRING, hostname)
        dprint ("password=keyring.get_password(%s, %s) == %s" % (KEYRING, hostname, password))
        if not password:
            print("Password for %s not found in keyring\n" % hostname)
    while not password:
        password = getpass.getpass('Password: ')

    device=FDM(hostname)
    while not device.do_auth(username, password):
        password  = ""
        while not password: 
            password = getpass.getpass('Password: ')

    if SAVE_CREDS_TO_KEYRING:
        keyring.set_password(KEYRING, hostname, password)

    while True:
        refreshSNMPconfigs(device) # Update our list of SNMP Configurations
        printSNMPconfigs(device) # Print the list of SNMP Configurations
        print()
        print(" 1. Add a new SNMP Configuration")
        print(" 2. Delete a current SNMP Configuration")
        print(" 0. Exit")
        choice = input("\n>Enter your choice [0-2]: ")
        match choice:
            case '1':
                newSNMPconfig_menu(device)
                #new_SNMP_config(device)
            case '2':
                deleteSNMPconfig_menu(device)
            case '0':
                sys.exit("\nExiting...")
            case _:
                input("\nInvalid selection, press enter to continue..")

###################################################################################################################
###################################################################################################################

if __name__ == '__main__':
    main()