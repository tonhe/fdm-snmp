#!/usr/bin/env python3
import sys
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
        self.access_token=""
        self.headers=""
        self.interface_counter = 0
        self.valid_interface = []
        self.SNMPconfigs = []

    def do_auth(self, username, password):
        url = f"https://{self.hostname}/api/fdm/latest/fdm/token"
        payload = f'{{ "grant_type": "password","username": "{username}", "password": "{password}" }}'
        self.headers = {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json'
                        }
        response=None
        try:
            response = requests.post(url, headers=self.headers, data=payload, verify=False)
            auth_body=response.json()
            if response.status_code==500:
                print("\n!! Error - Internal Server Error\n")
                return False
            auth_token = auth_body.get('access_token')
            if auth_token == None:
                print("Invalid Password\n")
                return False
            elif response.status_code==200:
                print('Successfully Authenticated')
                self.access_token = auth_token
                self.headers = { 'Authorization': f'Bearer {auth_token}',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                            }
                return True
        except Exception as err:
            print(f"!! Error in do_auth(): {err}")
            sys.exit()

    def get(self, url):
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            if response.status_code==200:
                return response
        except Exception as e:
            print(f"!! ERROR API Get - {e}")
            self.logoout()
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
            print(f"!! ERROR API Post - {e}")
            self.logoout()
            sys.exit()
        return

    def delete(self, url):
        try:
            response = requests.delete(url, headers=self.headers, verify=False)
            if response.status_code != 204:
                print(response.json)
        except Exception as e:
            print(f"!! ERROR in API Delete - {e}")
            self.logout()
            sys.exit()
        return

    def commit_changes(self):
        url=f'https://{self.hostname}/api/fdm/latest/operational/deploy'
        nada = {}
        response=self.post(url, nada)
        if response['state'] == 'QUEUED':
            print("Change Deployement Queued.")

    def logout(self): # Revoke our own access token
        headers = { 'Content-Type': 'application/json',
                    'Accept': 'application/json' }
        payload = f'{{ "grant_type": "revoke_token","access_token": "{self.access_token}","token_to_revoke": "{self.access_token}"}}'
        url = f"https://{self.hostname}/api/fdm/v6/fdm/token"
        try:
            dprint(f"response = requests.post({url}, headers={headers}, data={payload}, verify=False)")
            response = requests.post(url, headers=headers, data=payload, verify=False)
            dprint(f"status code {response.status_code}")
            if response.status_code == 200: 
                print(f"Logged out of {self.hostname}.")
        except Exception as e:
            print(f"!! Logout Error - {e}")

###################################################################################################
###################################################################################################

def dprint(line):
    if DEBUG:
        print(f"(d) {line}")

def nbinput(text, options=""):
    #   choice=nbinput("Choose 1,2,3: ", ['1','2','3'])
    #   password=nbinput("Password: ", True)
    while True:
        try:
            if options == True:
                resp = getpass.getpass(text)
                if resp != "":
                    break
                print("\nPassword cannot be blank.\n")
            else:
                resp = input(text)
                if len(options) > 0 and resp in options:
                        break
                elif resp != "" and len(options) == 0:
                    break
                else:
                    print("\nInvalid input")
        except:
            print("\nInvalid input")
    return resp

def printSNMPconfigs(device):
    device.SNMPconfigs=[]
    url = f"https://{device.hostname}/api/fdm/v6/object/snmphosts?limit=25"
    response = device.get(url)
    if response.status_code==200:
        for line in response.json()['items']:
            if line['name'] is not None:
                device.SNMPconfigs.append(line)
        if len(device.SNMPconfigs) == 0:
            print("\nNo SNMP Configurations Present")
            return
        print(f"\n>>> SNMP Configurations on {device.hostname} >>>")
        #print("{:<5} {:<20} {:<10} {:<15} {:<20} {:<12}".format("#","snmpHost", "nameif", "interface", "networkObject", "ipAddress"))
        print(f"{'#':<5} {'snmpHost':<20} {'nameif':<10} {'interface':<15} {'networkObject':<20} {'ipAddress':<12}")
        line = 0
        for config in device.SNMPconfigs:
            line += 1
            serverIP=get_networkHost_IP(device, config['managerAddress']['id'])
            #print("{:<5} {:<20} {:<10} {:<15} {:<20} {:<12}".format(line,config['name'], config['interface']['name'], config['interface']['hardwareName'], config['managerAddress']['name'], serverIP))
            print(f"{line:<5} {config['name']:<20} {config['interface']['name']:<10} {config['interface']['hardwareName']:<15} {config['managerAddress']['name']:<20} {serverIP:<12}")
 
def create_remotehost_obj(device, name, ip):
    url = f"https://{device.hostname}/api/fdm/latest/object/networks"
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
    url = f"https://{device.hostname}/api/fdm/latest/object/snmpusers"
    response_body = device.post(url, snmpv3_payload)
    return response_body

def print_interface(device, iface):
    if iface['ipv4']['ipAddress'] == None or iface['ipv4']['ipAddress']['ipAddress'] == None:
        ipAddr = "n/a"
    else:
       ipAddr = iface['ipv4']['ipAddress']['ipAddress']
    #print("{:<5} {:<18} {:<20} {:<20} {:<40}".format(device.interface_counter+1, iface['name'], iface['hardwareName'], ipAddr, iface['id']))
    print(f"{device.interface_counter+1:<5} {iface['name']:<18} {iface['hardwareName']:<20} {ipAddr:<20} {iface['id']:<40}")

def find_interfaces (device, nameif=""): # Populates valid interfaces, if nameif is sent, we return a matching interface
    # This is a list of API URLs for the interface types we want to retrieve, True/False = if they can have subinterfaces
    INT_OPS = [
        (f"https://{device.hostname}/api/fdm/latest/devices/default/interfaces", True),
        (f"https://{device.hostname}/api/fdm/latest/devices/default/vlaninterfaces", False),
        (f"https://{device.hostname}/api/fdm/latest/devices/default/etherchannelinterfaces", True)]
    device.interface_counter = 0
    for url, subint in INT_OPS:
        try:
            int_url = f"{url}?limit=25"
            response = device.get(int_url)
            if response.status_code==200:
                for interface in response.json()['items']: # There has to be a better way to iterate through this
                    if interface['name'] is not None and interface['name'] != '':
                        device.valid_interface.append(interface) # Add this to the list of valid interfaces
                        if nameif and (interface['name'] == nameif): # If we're searching for a name and we found it
                            return interface
                        elif not nameif:
                            print_interface(device, device.valid_interface[device.interface_counter])
                        device.interface_counter+=1
                    if subint == True: # if subint is True, lets try to enumerate the subinterfaces
                        sub_responses=[]
                        int_id = interface['id']
                        subint_url = f"{url}/{int_id}/subinterfaces?limit=25"
                        sub_response = device.get(subint_url)
                        if sub_response.status_code==200:
                            for subint in sub_response.json()['items']:
                                if subint['name'] is not None and subint['name'] !='':
                                    device.valid_interface.append(subint)
                                    if nameif and (subint['name'] == nameif):
                                        return subint
                                    elif not nameif:
                                        print_interface(device, device.valid_interface[device.interface_counter])
                                    device.interface_counter+=1
            elif response.status_code==404: # remote device may not support some interface types - bugfix thanks to Saurabh Pawar 10-04-2022
                continue
            else:
                print(f"!! Error: {response}")
        except Exception as err:
            print(f"Error in interface selection {err}")
            device.logout()
            sys.exit()
    
def select_interface(device, nameif=""):
    my_interface = find_interfaces(device, nameif) # This will search for a nameif (if specified) or print a list of interfaces
    if nameif: # if we're searching for a nameif, return that interface
        return my_interface
    num = int(nbinput(f"\nSelect the interface facing your SNMP server [1-{device.interface_counter}]: ", [str(x) for x in range(1,device.interface_counter+1)]))
    return device.valid_interface[num-1] # Because Zero Counting

def create_snmpserver(device, secConfig, host, interface, server_name):
    url = f"https://{device.hostname}/api/fdm/latest/object/snmphosts"
    payload={
                "name": server_name,
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
    url = f"https://{device.hostname}/api/fdm/latest/object/networks/{object_id}"
    get_host = device.get(url)
    if get_host.status_code==200:
        return get_host.json()['value']
    else:
        print(json.loads(get_host.text))
        device.logout()
        sys.exit()

def delete_SNMP_config(device, networkObject_id, snmpHost_id):
    print(f"\nDeleting snmpHost_id - {snmpHost_id}", end='')
    url = f"https://{device.hostname}/api/fdm/v6/object/snmphosts/{snmpHost_id}"
    device.delete(url)
    
    print(f"\nDeleting networkObject_id - {networkObject_id}", end='')
    url=f"https://{device.hostname}/api/fdm/v6/object/networks/{networkObject_id}"
    device.delete(url)
    print()

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
    payload['securityLevel'] = nbinput("Enter Security Level ['AUTH', 'NOAUTH', 'PRIV']: ", ['AUTH', 'NOAUTH', 'PRIV'])
    if payload['securityLevel'] in ['AUTH','PRIV']:
        payload['authenticationAlgorithm'] = nbinput("Enter authentication Algorithm ['SHA', 'SHA256']: ", ['SHA','SHA256'])
        payload['authenticationPassword'] = nbinput("Enter authentication password: ", True)
        if payload['securityLevel'] == "PRIV":
            payload['encryptionAlgorithm'] = nbinput("Enter encryption Algorithm ['AES128', 'AES192', 'AES256', '3DES']: ", ['AES128','AES192','AES256','3DES'])
            payload['encryptionPassword'] = nbinput("Enter encryption password: ", True)
    return payload

def newSNMPconfig_menu(device):
    snmp_version = int(nbinput("\nSelect SNMP version to configure...\n\n 2. SNMPv2\n 3. SNMPv3\n [2-3]: ", ['2','3']))
    #snmp_version=2
    remote_name = nbinput("\nEnter the object name for the remote SNMP Server: ")
    remote_ip = nbinput("Enter the IP for the remote SNMP Server: ")
    if snmp_version == 2: #SNMPv2
        community_str = nbinput("Enter the SNMPv2 community string: ")
        secConfig = getSNMPv2_config(community_str)
    elif snmp_version == 3:
        username = nbinput("Enter the SNMPv3 username: ")
        v3payload = getSNMPv3_payload(username)
    snmp_servername = nbinput('Enter Local SNMP Server object name: ')
    interface=select_interface(device) # Find the interface to listen on
    ready = nbinput(f"Ready to create objects on {device.hostname}. Continue (y\\n): ", ['y', 'n', 'Y', 'N'])
    if isinstance(ready, str):
        ready=ready.lower()
    match ready:
        case 'y': # Will need to figure out what version we're configuring here
            if snmp_version==3: # v3 config only
                dprint(f"v3user=create_snmpv3user(device, {v3payload})") 
                v3user=create_snmpv3user(device, v3payload) 
                dprint(f"secConfig=getSNMPv3_config({v3user})")
                secConfig=getSNMPv3_config(v3user)
            # This is for everyone now... 
            dprint(f"remoteobj = create_remotehost_obj(device, {remote_name}, {remote_ip})")
            remoteobj = create_remotehost_obj(device, remote_name, remote_ip) #version, name, id and type
            dprint(f"create_snmpserver(device, {secConfig}, {remoteobj}, {interface}, {snmp_servername})")
            create_snmpserver(device, secConfig, remoteobj, interface, snmp_servername)
            #device.commit_changes()
            print("\n\n Configuration Complete - Make sure to Commit these changes on main menu!")
            return
        case 'n':
            return

def deleteSNMPconfig_menu(device):
    while True:
        printSNMPconfigs(device)
        config_count = len(device.SNMPconfigs)
        if config_count == 0 :
            print("\nNo configurations present to edit...")
            return
        selection = int(nbinput(f"\nEnter line to delete, or 0 to exit [0-{config_count}]: ", [str(x) for x in range(0,config_count+1)]))
        if selection != 0:
            delete_SNMP_config(device, device.SNMPconfigs[selection-1]['managerAddress']['id'],device.SNMPconfigs[selection-1]['id'])
            #device.commit_changes()
            print("\n\n Configuration Complete - Make sure to Commit these changes on main menu!")
        else:
            return

def work_from_file(filename, KEYRING, SAVE_CREDS_TO_KEYRING): # an Ugly and Fast way to add SNMPv2 to all the things...
    import csv
    fields = ['HOSTNAME', 'USERNAME', 'PASSWORD', 'REMOTESERVER_NAME', 'REMOTESERVER_IP', 'NAMEIF', 'LOCALSERVER_NAME', 'SNMP_STRING']
    with open(filename, newline='') as file:
        csv_file = csv.DictReader(file, fieldnames=fields)
        for line in csv_file:
            hostname=line['HOSTNAME'].strip()
            username=line['USERNAME'].strip()
            password=line['PASSWORD'].strip()
            remoteserver_name=line['REMOTESERVER_NAME'].strip()
            remoteserver_ip=line['REMOTESERVER_IP'].strip()
            nameif=line['NAMEIF'].strip()
            localserver_name=line['LOCALSERVER_NAME'].strip()
            snmp_string=line['SNMP_STRING'].strip()

            dprint(fields)
            dprint(f"{hostname}, {username}, ##########, {remoteserver_name}, {remoteserver_ip}, {nameif}, {localserver_name}, {snmp_string})")
            print(f"\nLogging into {hostname}")
            device=FDM(hostname)

            if not device.do_auth(username, password):
                print(f"\nLogin error {username}@{hostname}\n")
                continue

            if SAVE_CREDS_TO_KEYRING:
                keyring.set_password(KEYRING, hostname, password)

            dprint(f"host=create_remotehost_obj(device, {remoteserver_name}, {remoteserver_ip})")
            print ("Creating Remote SNMP Server Object.")
            remotehost_obj=create_remotehost_obj(device, remoteserver_name, remoteserver_ip) #version, name, id and type

            print ("Locating interface.")
            interface = find_interfaces(device, nameif)
            if not interface['name']:
                print(f"\nUnable to find interface {nameif} on {hostname}\n")
                continue

            secConfig = getSNMPv2_config(snmp_string) 
            dprint(f"create_snmpserver(device, {secConfig}, {remotehost_obj}, {interface}, {localserver_name})")
            print ("Creating SNMP Configuration Object")
            create_snmpserver(device, secConfig, remotehost_obj, interface, localserver_name)
            print(f"Configuration on {hostname} complete.. ")
            device.commit_changes()
            device.logout()
    sys.exit("\nComplete - Exiting")

###################################################################################################################
###################################################################################################################

def main():
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    VERSION = "1.3.2"
    KEYRING="fdm-snmp"
    SAVE_CREDS_TO_KEYRING = True # Do we save all of our creds to the keyring by default?
    AUTO_KEYCHAIN = True # Automagicallu try the keychain if no password supplied

    print(" **********************************************")
    print(" *                                            *")
    print(" * FDM SNMP Configuration Tool                *")
    print(f" *   version {VERSION:<32} *")
    print(" *                (c) Tony Mattke 2022-2023   *")
    print(" *                                            *")
    print(" **********************************************\n")
    
    parser = argparse.ArgumentParser(prog="python3 fdm-snmp.py",
                                     description="API Management of FDM SNMP Configurations")
    parser.add_argument("host", help="FDM Managment IP/Hostname", default="", nargs="*")
    parser.add_argument("-u", "--user", dest="user", help="User ID for login (admin is default)", default="admin")
    parser.add_argument("-k", "--keyring", dest="keyring", help="Pull password from local keyring (by hostname)", action="store_true")
    parser.add_argument("-p", "--password", dest="change_password", help="Change keyring password via interactive login", action="store_true")
    parser.add_argument("-d", dest="debug", help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-c", dest="commit", help=argparse.SUPPRESS, action="store_true") # TESTING
    parser.add_argument("-f", dest="file", help=argparse.SUPPRESS, default="")
    args = parser.parse_args()

    username=args.user
    hostname=""
    password=""


    if args.debug:
        global DEBUG 
        DEBUG = True
        print(">Debug ON")
    if args.file:
        work_from_file(args.file, KEYRING, SAVE_CREDS_TO_KEYRING)
    if args.host:
        hostname = args.host[0]
    while not hostname:
        hostname = nbinput("FDM Management IP or Hostname: ")
    if "@" in hostname: # for those that username@hostname
        username=args.host.split('@')[0]
        hostname=args.host.split('@')[1]
    while not username:
        username = nbinput("Username: ")
    if (args.keyring or AUTO_KEYCHAIN) and not args.change_password:
        print("Pulling password from local keyring.")
        password=keyring.get_password(KEYRING, hostname)
        if not password:
            print(f"Password for {hostname} not found in keyring\n")
            password = nbinput('Password: ', True)
    while not password:
        password = nbinput('Password: ', True)

    device=FDM(hostname)
    while not device.do_auth(username, password):
        password = nbinput('Password: ', True)

    if SAVE_CREDS_TO_KEYRING:
        keyring.set_password(KEYRING, hostname, password)

    if args.commit: #TESTING
        device.commit_changes()
        sys.exit()

    while True:
        printSNMPconfigs(device) # Print the list of SNMP Configurations
        print()
        print(" 1. Add a new SNMP Configuration")
        print(" 2. Delete a current SNMP Configuration")
        print(" 3. Commit changes to device.")
        print(" 0. Exit")
        print()
        choice = nbinput("Enter your choice [0-2]: ", ['0','1','2','3'])

        match choice:
            case '1':
                newSNMPconfig_menu(device)
            case '2':
                deleteSNMPconfig_menu(device)
            case '3':
                device.commit_changes()
            case '0':
                device.logout()
                sys.exit(">Exiting.")

###################################################################################################################
###################################################################################################################

if __name__ == '__main__':
    main()