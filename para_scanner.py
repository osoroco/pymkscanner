#!/usr/bin/python
import ipaddress as ipad
import nmap
import sqlite3
import sys
from multiprocessing import Semaphore, Process, Lock
import urllib,json


#Damian Ruiz
#Paralelized IP range scanning for ports specified 

raw_input("Verify VPN connection is enabled to grab PPPOE dynamic IPs, press enter to continue")
nmsurl="http://196.12.161.10/radius/jonline_users.php"
data=json.loads(urllib.urlopen(nmsurl).read())
raw_input("Data loaded, disconnect VPN and press enter to continue")
dynamic=[]
for i in data['clients']:
    dynamic.append(i.split(','))

static=[]
rstatic=json.load(open('static.json'))
for i in rstatic['clients']:
    static.append(ipad.ip_network(i))

#amount of concurrent scans allowed
semaphore = Semaphore(50)

#first verify if table exists, else create:
conn=sqlite3.connect('scan.db')
c = conn.cursor()
c.execute("select sql from sqlite_master where type='table' and name='scanResults'")
if (len(c.fetchall())==0): 
    c.execute("CREATE TABLE `scanResults` (`id`INTEGER PRIMARY KEY AUTOINCREMENT,`ip` TEXT,`username` TEXT,`ports` BLOB)")
conn.close()



def pscan(ip,username,semaphore):
    nmscanner = nmap.PortScanner()
    nmscanner.scan(hosts=host, arguments='-Pn -p 23,80,53,161 --ttl 10 --max-retries 1')
    #NOTE: This type of scan will never yield 'closed' ports, always 'filtered' or 'open'. 
    #We aren't looking for 'filtered' ports
    p23 = ['open' if nmscanner[host]['tcp'][23]['state']=='open' else 'closed']
    p80 = ['open' if nmscanner[host]['tcp'][80]['state']=='open' else 'closed']
    p53 = ['open' if nmscanner[host]['tcp'][53]['state']=='open' else 'closed']
    p161 = ['open' if nmscanner[host]['tcp'][161]['state']=='open' else 'closed']
    conn=sqlite3.connect('scan.db')
    c=conn.cursor()
    c.execute("INSERT INTO scanResults (`username`,`ip`,`ports`) VALUES ('%s','%s','%s')" % (username,ip,ports))
    conn.commit()
    conn.close()
    semaphore.release()

#for dynamic IP scan:
for ip,username in dynamic:
    semaphore.acquire()
    Process(target=pscan,args=(ip,username,semaphore)).start()

 
#static IP scan:
for i in static:
    ipRange=list(i.hosts())
    for j in ipRange:
        ip=j.exploded
        semaphore.acquire()
        username=None
        Process(target=pscan,args=(ip,username,semaphore)).start()

