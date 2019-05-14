import subprocess
import multiprocessing
import socket
import os
import time 
from multiprocessing import Process, Queue
from file_helper import check_directory

def enum4linux(output_directory):
    check_directory(output_directory)

    hostnames = 0
    SWEEP = ''
    ips = list()
    print(os.path.join(output_directory, 'unicornscan_details_tcp.txt'))
    if(os.path.isfile(os.path.join(output_directory, 'unicornscan_details_tcp.txt'))):
        with open(os.path.join(output_directory, 'unicornscan_details_tcp.txt'), 'r') as f:
            for line in f:
                #TCP open	139	netbios-ssn	10.11.1.5
                line = line.strip().split('\t')
                print(line)
                if('TCP open' in line[0]) and ('139' in line[1]):
                    ips.append(line[3])
    else:
        return
    print(ips)
    #p=subprocess.Popen(['md5sum',file],stdout=logfile)
    #p.wait()
    for ip in ips:
        with open(os.path.join(output_directory, ip, 'scans', 'enum4linux.txt'), 'w') as f:
            p=subprocess.Popen(['enum4linux','-a',ip],stdout=f)
    p.wait()
    

    '''
    with open(os.path.join(output_directory, ip, 'scans', 'enum4linux.txt'), 'w') as f:
        SWEEP = "enum4linux -a %s" % (ip)
        print("[+] Scanning %s and writing results to: %s" % (ip, f.name))
        results = subprocess.check_output(SWEEP, shell=True).decode("utf-8")
        f.write(results)
    '''
