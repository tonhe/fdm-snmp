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