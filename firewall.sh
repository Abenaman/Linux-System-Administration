#!/bin/bash

#flush old iptables rules
echo "Flushing old firewall rules"
iptables -F
iptables-save > /etc/firewall.conf
#add new rules
echo "adding new firewall rules"
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp -m state --state NEW -m udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 8443 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p udp -m state --state NEW -m udp --dport 2049 -j ACCEPT
iptables -A INPUT -p udp -m state --state NEW -m udp --dport 111 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 2049 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 111 -j ACCEPT
iptables -A INPUT -p udp -m state --state NEW -m udp --dport 138 -j ACCEPT
iptables -A INPUT -p udp -m state --state NEW -m udp --dport 137 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 139 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 445 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 587 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 993 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 143 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 25 -j ACCEPT
iptables -A INPUT -m limit --limit 50/min -j LOG --log-prefix "Firewall denied 50/m:"
iptables -A INPUT -j REJECT --reject-with icmp-port-unreachable
iptables-save > /etc/firewall.conf
echo "new firewall rules added"