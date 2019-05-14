#!/usr/bin/python


import sys
from argparse import ArgumentParser
from lib.ping_sweeper import ping_sweeper
from lib.find_dns import find_dns
from lib.service_scan import service_scan
from lib.hostname_scan import hostname_scan
from lib.snmp_walk import snmp_walk
from lib.virtual_host_scanner import virtual_host_scanner
from lib.core.input import cli_argument_parser, cli_helper
from lib.unicorn_scan import unicorn_scan
from lib.arp_scan import arp_scan
from lib.enum4linux import enum4linux


def print_banner():
    print("  __")
    print("|\"\"\"\-=  RECONNOITRE")
    print("(____)      An OSCP scanner by @codingo_\n")

def util_checks(util = None):
    if util is None:
        print("[!] Error hit in chktool: None encountered for util.")
        sys.exit(1)

    pyvers = sys.version_info

    if (pyvers[0] >= 3) and (pyvers[1] >= 3): # python3.3+
        import shutil
        if shutil.which(util) is None:
            if util is "nmap":
                print("   [!] nmap was not found on your system. Exiting since we wont be able to scan anything. Please install nmap and try again.")
                sys.exit(1)
            else:
                print("   [-] %s was not found in your system. Scan types using this will fail." % util)
                return "Not Found"
        else:
            return "Found"
    else: # less-than python 3.3
        from distutils import spawn
        if spawn.find_executable(util) is None:
            if util is "nmap":
                print("   [!] nmap was not found on your system. Exiting since we wont be able to scan anything. Please install nmap and try again.")
                sys.exit(1)
            else:
                print("   [-] %s was not found in your system. Scan types using this will fail." % util)
                return "Not Found"
        else:
            return "Found"

def main():
    parser = cli_argument_parser()
    arguments = parser.parse(sys.argv[1:])

    if arguments.output_directory.endswith('/' or '\\'):
        arguments.output_directory = arguments.output_directory[:-1]
    if arguments.target_hosts.endswith('/' or '\\'):
        arguments.target_hosts = arguments.target_hosts[:-1]

    if arguments.quiet is not True:
        print_banner()
        print("[+] Testing for required utilities on your system.")

    utils = ['nmap', 'snmpwalk', 'nbtscan'] # list of utils to check on local system.
    for util in utils:
        util_checks(util)

    if arguments.ping_sweep is True:
        print("[#] Performing ping sweep")
        ping_sweeper(arguments.target_hosts, arguments.output_directory, arguments.quiet)

    if arguments.arp_scan is True:
        print("[#] Performing arp scan")
        arp_scan(arguments.target_hosts, arguments.output_directory, arguments.quiet, arguments.interface)

    if arguments.hostname_scan is True:
        print("[#] Identifying hostnames")
        hostname_scan(arguments.target_hosts, arguments.output_directory, arguments.quiet, arguments.dns_server)

    if arguments.find_dns_servers is True:
        print("[#] Identifying DNS Servers")
        find_dns(arguments.target_hosts, arguments.output_directory, arguments.quiet)

    if arguments.unicorn_scan is True:
        print("[#] Performing unicornscan")
        unicorn_scan(arguments.target_hosts, arguments.output_directory, arguments.quiet, arguments.interface, arguments.pps)

    if arguments.perform_service_scan is True:
        print("[#] Performing service scans")
        if arguments.find_dns_servers is True:
            service_scan(arguments.target_hosts, arguments.output_directory, arguments.find_dns_servers, arguments.quiet, arguments.quick, arguments.no_udp_service_scan, arguments.timing)
        else:
            service_scan(arguments.target_hosts, arguments.output_directory, '', arguments.quiet, arguments.quick, arguments.no_udp_service_scan, arguments.timing)

    if arguments.perform_snmp_walk is True:
        print("[#] Performing SNMP walks")
        snmp_walk(arguments.target_hosts, arguments.output_directory, arguments.quiet)

    if arguments.enum4linux is True:
        print("[#] Running enum4linux")
        enum4linux(arguments.output_directory)

    if arguments.virtualhosts is True:
        print("[#] Performing Virtual host scans")
        if arguments.wordlist is False:
            print("[!] No wordlist was provided, skipping virtual host scanning.")
        else:
            scanner = virtual_host_scanner(arguments.target_hosts, arguments.output_directory, arguments.port, arguments.ignore_http_codes, arguments.ignore_content_length, arguments.wordlist)
            scanner.scan()


if __name__ == "__main__":
    main()
