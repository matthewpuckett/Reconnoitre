import subprocess
import multiprocessing
import socket
import os
import time 
from multiprocessing import Process, Queue
from file_helper import check_directory


def hostname_scan(target_hosts, output_directory, quiet, dns_server):
    check_directory(output_directory)
    #f_net = open(output_directory + "/hostnames_netbios.txt", 'w')
    #f_dns = open(output_directory + "/hostnames_dns.txt", 'w')
    #print("[+] Writing hostnames to: %s" % output_file)
    
    hostnames = 0
    SWEEP = ''

    if(os.path.isfile(target_hosts)):
        SWEEP = "nbtscan -q -f %s" % (target_hosts)
    else:
        SWEEP = "nbtscan -q %s" % (target_hosts)
    
    results = ""
    results = subprocess.check_output(SWEEP, shell=True).decode("utf-8")
    lines = results.split("\n")
    with open(output_directory + "/hostnames_netbios.txt", 'w') as f:
        print("[+] Writing hostnames to: %s" % (f.name))
        for line in lines:
            line = line.strip()
            line = line.rstrip()
            
            # Final line is blank which causes list index issues if we don't
            # continue past it.
            if not " " in line:
                continue
            
            while "  " in line: 
                line = line.replace("  ", " ")

            ip_address = line.split(" ")[0]
            host = line.split(" ")[1]
            
            if (hostnames > 0):
                f.write('\n')

            print("   [>] Discovered hostname: %s (%s)" % (host, ip_address))
            f.write("%s - %s" % (host, ip_address))
            hostnames += 1
                
        print("[*] Found %s NETBIOS hostnames." % (hostnames))
        print("[*] Created hostname list %s" % (f.name))

    hostnames = 0
    SWEEP = ''
    results = ""
    ips = list()
    if(os.path.isfile(target_hosts)):
        with open(target_hosts, 'r') as f:
            for line in f:
                ips.append(line.strip())
    else:
        if "-" in target_hosts:
            start_ip = target_hosts.split("-")[0]
            end = int(target_hosts.split("-")[1])
            base_ip = start_ip[:start_ip.rfind(".")]
            start = int(start_ip[start_ip.rfind(".")+1:])
            for i in range(start, end):
                ips.append(base_ip + "." + str(i))
        else:
            ips.append(target_hosts)
    #print(dns_server)
    if(dns_server != False):
        dns_server = dns_server
    elif(os.path.isfile(output_directory + "/dns_servers_targets.txt")):
        with open(output_directory + "/dns_servers_targets.txt",'r') as f:
            dns_server = f.readline().strip()
    else:
        print("[*] dns_servers_targets.txt missing, run with --dns option first, or specify DNS server with --dns-server")
        return

    for ip in ips:
        ip = ip.strip()
        SWEEP = "nslookup %s %s" % (ip, dns_server)
        try:
            results = results + subprocess.check_output(SWEEP, shell=True).decode("utf-8")
        except subprocess.CalledProcessError as e:
            continue #ignore exit codes
    lines = results.split("\n")
    with open(output_directory + "/hostnames_dns.txt", 'w') as f, open(output_directory + "/hostnames_dns_targets.txt", 'w') as t:
        print("[+] Writing hostnames to: %s" % (f.name))
        for line in lines:
            line = line.strip()
            line = line.rstrip()
            if "in-addr.arpa" in line:
                line2 = line.replace(".in-addr.arpa	name = ", " ")
                #print(line2)
                line2 = '.'.join(reversed(line2.split(' ')[0].split('.'))) + ' ' + line2.split(' ')[1][:-1]
                #print(line2)
                print("   [>] Discovered hostname: %s" % (line2))
                f.write("%s" % (line2.strip()))
                t.write("%s" % (line2.strip().split(' ')[0]))
                if (hostnames > 0):
                    f.write('\n')
                    t.write('\n')
                hostnames += 1
                
        print("[*] Found %s DNS hostnames." % (hostnames))
        print("[*] Created hostname list %s" % (f.name))
