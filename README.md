# fdm-snmp
SNMP Configuration Script for FDM 6.7+ via API 

NAME

    FDM-SNMP - Cisco FDM SNMP API Configuration Tool

SYNOPSIS

    usage:python3 fdm-snmp.py [-h] [-u USER] [-k] [-p] [host ...]

    API Management of FDM SNMP Configurations

    positional arguments:
    host                  FDM Managment IP/Hostname

    options:
    -h, --help            show this help message and exit
    -u USER, --user USER  User ID for login (admin is default)
    -k, --keyring         Pull password from local keyring (by hostname)
    -p, --password        Change keyring password via interactive login
    -f, --file            Import list of device and configs from file


Feel free to adjust these variables to suit your security needs

    SAVE_CREDS_TO_KEYRING = True # Do we save all of our creds to the keyring by default?
    AUTO_KEYCHAIN = True # Automagicallu try the keychain if no password supplied


CSV File should be formatted as follows

    HOSTNAME, USERNAME, PASSWORD, REMOTESERVER_NAME, REMOTESERVER_IP, NAMEIF, LOCALSERVER_NAME, SNMP_STRING