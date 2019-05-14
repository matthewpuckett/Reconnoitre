import subprocess
import multiprocessing
import socket
import os
import time 
from multiprocessing import Process, Queue
from file_helper import check_directory


#arp-scan --interface=tap0 10.11.1.1/24
def arp_scan(target_hosts, output_directory, quiet, interface):
    check_directory(output_directory)

    hostnames = 0
    SWEEP = ''
    if(os.path.isfile(target_hosts)):
        if(interface):
            SWEEP = "arp-scan --interface=%s -f %s" % (interface, target_hosts)
        else:
            SWEEP = "arp-scan -f %s" % (target_hosts)
    else:
        if("-" in target_hosts):
            start_ip = target_hosts.split("-")[0]
            end = int(target_hosts.split("-")[1])
            base_ip = start_ip[:start_ip.rfind(".")]
            start = int(start_ip[start_ip.rfind(".")+1:])
            target_hosts = start_ip + '-' + base_ip + '.' + str(end)
        if(interface):
            SWEEP = "arp-scan --interface=%s %s" % (interface, target_hosts)
        else:
            SWEEP = "arp-scan %s" % (target_hosts)
    
    results = ""
    results = subprocess.check_output(SWEEP, shell=True).decode("utf-8")
    lines = results.split("\n")
    with open(output_directory + "/arp_details.txt", 'w') as f, open(output_directory + "/arp_targets.txt", 'w') as t:
        print("[+] Writing hostnames to: %s" % (f.name))
        for line in lines:
            line = line.strip()
            line = line.rstrip()
            
            if('\t' in line):
                #print(line)
                ip_address = line.split("\t")[0]
                mac = line.split("\t")[1]
                make = line.split("\t")[2]
                
                if (hostnames > 0):
                    f.write('\n')
                    t.write('\n')

                print("   [>] Discovered live IP: %s (%s - %s)" % (ip_address, mac, make))
                f.write("%s %s %s" % (ip_address, mac, make))
                t.write("%s" % (ip_address))
                hostnames += 1
                
        print("[*] Found %s IPs that respond to ARP." % (hostnames))
        print("[*] Created ARP lists %s and %s" % (f.name, t.name))