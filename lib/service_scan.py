import subprocess
import multiprocessing
import socket
import os
import time
from multiprocessing import Process, Queue
from file_helper import check_directory
from file_helper import load_targets
from file_helper import create_dir_structure
from file_helper import write_recommendations


def nmap_scan(ip_address, output_directory, dns_server, quick, no_udp_service_scan, timing, base_directory):
    ip_address = ip_address.strip()
    '''
    print("[+] Starting quick nmap scan for %s" % (ip_address))
    QUICKSCAN = "nmap -sC -sV %s -oA '%s/%s.quick'"  % (ip_address, output_directory, ip_address)
    quickresults = subprocess.check_output(QUICKSCAN, shell=True).decode("utf-8")

    write_recommendations(quickresults, ip_address, output_directory)
    print("[*] TCP quick scans completed for %s" % ip_address)

    if(quick):
        return
    '''
    ports = '-p-' #default to all ports
    tports = '-p-'
    uports = '--top-ports 500'
    tports_file = os.path.join(base_directory, 'unicornscan_ports_tcp.txt')
    uports_file = os.path.join(base_directory, 'unicornscan_ports_udp.txt')
    #print(tports_file)
    #print(uports_file)
    if(os.path.isfile(tports_file)):
        #print('tports exists')
        with open(tports_file, 'r') as tp:
            tports = '-p' + tp.readline().strip()
    if(os.path.isfile(uports_file)):
        with open(uports_file, 'r') as up:
            uports = '-p' + up.readline().strip() 

    #-sV for service detection??? will help for NSE scripts

    if(not dns_server):
        if(os.path.isfile(output_directory + "/dns_servers_targets.txt")):
            with open(output_directory + "/dns_servers_targets.txt",'r') as f:
                dns_server = f.readline().strip()

    if dns_server:
        print("[+] Starting detailed TCP%s nmap scans for %s using DNS Server %s" % (("" if no_udp_service_scan is True else "/UDP"), ip_address, dns_server))
        print("[+] Using DNS server %s" % (dns_server))
        TCPSCAN = "nmap -O -vv -Pn -sS -sV -A -sC %s -T %s -script-args=unsafe=1 --dns-servers %s -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (tports, timing, dns_server, output_directory, ip_address, output_directory, ip_address, ip_address)
        UDPSCAN = "nmap -O -vv -Pn -A -sC -sV -sU %s -T %s --max-retries 0 --dns-servers %s -oN '%s/%sU.nmap' -oX '%s/%sU_nmap_scan_import.xml' %s" % (uports, timing, dns_server, output_directory, ip_address, output_directory, ip_address, ip_address)
    else:
        print("[+] Starting detailed TCP%s nmap scans for %s" % (("" if no_udp_service_scan is True else "/UDP"), ip_address))
        TCPSCAN = "nmap -O -vv -Pn -sS -sV -A -sC %s -T %s -script-args=unsafe=1 -n %s -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (tports, timing, dns_server, output_directory, ip_address, output_directory, ip_address, ip_address)
        UDPSCAN = "nmap -O -sC -sV -sU %s %s -oA '%s/%s-udp'" % (ip_address, uports, output_directory, ip_address)

    print(UDPSCAN)
    udpresults = "" if no_udp_service_scan is True else subprocess.check_output(UDPSCAN, shell=True).decode("utf-8")
    print(TCPSCAN)
    tcpresults = subprocess.check_output(TCPSCAN, shell=True).decode("utf-8")

    write_recommendations(tcpresults + udpresults, ip_address, output_directory)
    print("[*] TCP%s scans completed for %s" % (("" if no_udp_service_scan is True else "/UDP"), ip_address))

    VULSCAN_TCP = "nmap -O -vv -Pn -sSVC -O -A %s -T %s -script-args=unsafe=1 -oA '%s/%s_vulscan_tcp' %s"  % (tports, timing, output_directory, ip_address, ip_address)
    VULSCAN_UDP = "nmap -O -vv -Pn -sSVC -O -A %s -T %s -script-args=unsafe=1 -oA '%s/%s_vulscan_udp' %s"  % (uports, timing, output_directory, ip_address, ip_address)

    tcpvulresults = subprocess.check_output(VULSCAN_TCP, shell=True).decode("utf-8")
    udpvulresults = subprocess.check_output(VULSCAN_UDP, shell=True).decode("utf-8")

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def target_file(target_hosts, output_directory, dns_server, quiet, quick, no_udp_service_scan, timing):
    targets = load_targets(target_hosts, output_directory, quiet)
    target_file = open(targets, 'r')
    try:
        target_file = open(targets, 'r')
        print("[*] Loaded targets from: %s" % targets)
    except:
        print("[!] Unable to load: %s" % targets)

    for ip_address in target_file:
       ip_address = ip_address.strip()
       create_dir_structure(ip_address, output_directory)

       host_directory = output_directory + "/" + ip_address
       nmap_directory = host_directory + "/scans"

       jobs = []
       p = multiprocessing.Process(target=nmap_scan, args=(ip_address, nmap_directory, dns_server, quick, no_udp_service_scan, timing, output_directory))
       jobs.append(p)
       p.start()
    target_file.close()


def target_ip(target_hosts, output_directory, dns_server, quiet, quick, no_udp_service_scan, timing):
    print("[*] Loaded single target: %s" % target_hosts)
    target_hosts = target_hosts.strip()
    create_dir_structure(target_hosts, output_directory)

    host_directory = output_directory + "/" + target_hosts
    nmap_directory = host_directory + "/scans"

    jobs = []
    p = multiprocessing.Process(target=nmap_scan, args=(target_hosts, nmap_directory, dns_server, quick, no_udp_service_scan, timing, output_directory))
    jobs.append(p)
    p.start()


def service_scan(target_hosts, output_directory, dns_server, quiet, quick, no_udp_service_scan, timing):
    check_directory(output_directory)

    if(valid_ip(target_hosts)):
        target_ip(target_hosts, output_directory, dns_server, quiet, quick, no_udp_service_scan, timing)
    else:
        target_file(target_hosts, output_directory, dns_server, quiet, quick, no_udp_service_scan, timing)
