import sys
import os
import ipaddress

def setup_iptables():
    os.system('iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
    os.system('iptables -t filter -A INPUT -p icmp -j ACCEPT')
    os.system('iptables -t filter -A INPUT -i lo -j ACCEPT')
    os.system('iptables -t filter -A INPUT -j DROP')

def cleanup_iptables():
    os.system('iptables -t filter -D INPUT -j DROP')
    os.system('iptables -t filter -D INPUT -i lo -j ACCEPT')
    os.system('iptables -t filter -D INPUT -p icmp -j ACCEPT')
    os.system('iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')

if __name__ == '__main__':
    args = " ".join(x for x in sys.argv[1:])
    dest = parse_source_ip(sys.argv[1:])
    
    retransmit = False
    if 'dedup-method none' in args.lower():
        retransmit = True

    if retransmit: 
        setup_iptables()

    os.system(f"zmap {args}")

    if retransmit: 
        cleanup_iptables()

