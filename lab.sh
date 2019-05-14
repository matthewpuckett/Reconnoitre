./reconnoitre.py -t 10.11.1.1-255 -o ~/lab --pps 2000 --interface tap0 --arp-scan --pingsweep #find valid targets
./reconnoitre.py -t ~/lab/arp_targets.txt --pps 2000 -o ~/lab --interface tap0 --dns #find DNS server(s)
./reconnoitre.py -t ~/lab/arp_targets.txt --pps 2000 -o ~/lab --interface tap0 --hostnames --dns-server #this will default DNS server to only first entry in DNS-targets.txt
./reconnoitre.py -t ~/lab/arp_targets.txt --pps 2000 -o ~/lab --interface tap0 --snmp #snmp only
./reconnoitre.py -t ~/lab/arp_targets.txt --pps 2000 -o ~/lab --interface tap0 --unicornscan #scan all ports and write to file
./reconnoitre.py -t ~/lab/arp_targets.txt --pps 2000 -o ~/lab --interface tap0 --services #full service scan using discovered ports only
