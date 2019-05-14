import subprocess
import multiprocessing
import socket
import os
import time 
from multiprocessing import Process, Queue
from file_helper import check_directory

def unicorn_scan(target_hosts, output_directory, quiet, interface, pps):
    check_directory(output_directory)

    hostnames = 0
    SWEEP = ''
    ips = list()
    if(os.path.isfile(target_hosts)):
        with open(target_hosts, 'r') as f:
            for line in f:
                ips.append(line.strip())
        if(interface):
            SWEEP = "unicornscan -R 1 --pps %s --interface=%s" % (pps, interface)
        else:
            SWEEP = "unicornscan -R 1 --pps %s" % (pps)
    else:
        if("-" in target_hosts):
            start_ip = target_hosts.split("-")[0]
            end = int(target_hosts.split("-")[1])
            base_ip = start_ip[:start_ip.rfind(".")]
            start = int(start_ip[start_ip.rfind(".")+1:])
            for i in range(start, end):
                ips.append(base_ip + "." + str(i))
            #print(ips)
        elif('/' in target_hosts): #in case we need to change later
            ips.append(target_hosts)
        else:
            ips.append(target_hosts)
        if(interface):
            SWEEP = "unicornscan -R 1 --pps %s --interface=%s" % (pps, interface)
        else:
            SWEEP = "unicornscan -R 1 --pps %s" % (pps)
        
    


    ports_tcp = set()
    ports_udp = set()

    with open(output_directory + "/unicornscan_details_tcp.txt", 'w') as t, open(output_directory + "/unicornscan_details_udp.txt", 'w') as u:
        print("[+] Writing unicornscan results to: %s and %s" % (t.name, u.name))

        for ip in ips:
            results_tcp = ""
            results_udp = ""

            hostnames_t = 0
            hostnames_u = 0

            SWEEP_t = SWEEP + ' -mT ' + ip + ':a' #scan all TCP ports with SYN
            print(SWEEP_t)
            results_tcp = subprocess.check_output(SWEEP_t, shell=True).decode("utf-8")
            lines_t = results_tcp.split("\n")
            for line in lines_t:
                #TCP open	           epmap[  135]		from 10.11.1.5  ttl 128 
                #TCP open	     netbios-ssn[  139]		from 10.11.1.5  ttl 128 
                #TCP open	    microsoft-ds[  445]		from 10.11.1.5  ttl 128 
                line = line.split('\t')
                #line = line.strip()
                #line = line.rstrip()
                
                #line = line.split('\t')
                if(len(line) is 4):
                    protocol = line[0].strip().rstrip()
                    service = line[1].split('[')[0].strip().rstrip()
                    port = line[1].split('[')[1][:-1].strip().rstrip()
                    ip_address = line[3].split(' ')[1].strip().rstrip()
                    #if (hostnames_t > 0):
                    #    t.write('\n')
                        #tp.write(',')
                    print("   [>] Discovered open port: %s\t%s\t%s\t%s" % (protocol, port, service, ip_address))
                    t.write("%s\t%s\t%s\t%s\n" % (protocol, port, service, ip_address)) #write full details
                    ports_tcp.add(port)
                    hostnames_t += 1
            print("[*] Found %s open TCP ports on %s" % (hostnames_t, ip))

            SWEEP_u = SWEEP + ' -mU ' + ip + ':a' #scan all UDP ports
            print(SWEEP_u)
            results_udp = subprocess.check_output(SWEEP_u, shell=True).decode("utf-8")
            lines_u = results_udp.split("\n")
            for line in lines_u:
                #TCP open	           epmap[  135]		from 10.11.1.5  ttl 128 
                #TCP open	     netbios-ssn[  139]		from 10.11.1.5  ttl 128 
                #TCP open	    microsoft-ds[  445]		from 10.11.1.5  ttl 128 
                line = line.split('\t')
                #line = line.strip()
                #line = line.rstrip()
                
                #line = line.split('\t')
                if(len(line) is 4):
                    protocol = line[0].strip().rstrip()
                    service = line[1].split('[')[0].strip().rstrip()
                    port = line[1].split('[')[1][:-1].strip().rstrip()
                    ip_address = line[3].split(' ')[1].strip().rstrip()
                    #if (hostnames_u > 0):
                    #    u.write('\n')
                    #    up.write(',')
                    print("   [>] Discovered open port: %s\t%s\t%s\t%s" % (protocol, port, service, ip_address))
                    u.write("%s\t%s\t%s\t%s\n" % (protocol, port, service, ip_address))
                    #up.write("%s" % (port)) #write just open port
                    ports_udp.add(port)
                    hostnames_u += 1
            
            print("[*] Found %s open UDP ports on %s" % (hostnames_u, ip))

        print("[*] Created unicornscan lists %s and %s" % (t.name, u.name))
    with open(os.path.join(output_directory, "unicornscan_ports_tcp.txt"), 'w') as tp, open(os.path.join(output_directory, "unicornscan_ports_udp.txt"), 'w') as up:
        print(ports_tcp)
        print('\n')
        ports_tcp = ','.join(ports_tcp)
        print(ports_tcp)
        print(ports_udp)
        ports_udp = ','.join(ports_udp)
        print(ports_udp)
        tp.write(str(ports_tcp))
        up.write(str(ports_udp))