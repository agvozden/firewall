#!/bin/bash
#
# http://whatswhat.no/computer/linux/linux-server/537-centos-and-virtualmin-webmin-perfect-iptables-firewall-script
# firewall				Startup script for the iptables based firewall
#
# chkconfig: 345 30 99
# description: Starts and stops iptables based firewall
#
## Specify open ports.
# 22 9722		SSH
# 21 20			FTP
# 49152 65534	PassivePorts proftpd.conf
# 80			HTTP (web)
# 443			HTTPS (web with SSL)
# 25 465 587 	SMTP (mail)
# 110 995		POP3 (mail)
# 143 993		IMAP (mail)
# 3306 			MySQL
# 5432 			PostgreSQL
# 53			DNS (TCP & UDP)
# 10000	 		Webmin
# 20000	 		Usermin
# 8006			Proxmox
# 8088			SAN interface
# 6936			XenServer communucations
# 694 			Ha-cluster UDP
# 5900			VNC 
# 5060			PBX SIP UDP
# 1723          	VPN TCP Ports
# 1701 500 1194     VPN UDP Ports
# 4848          Glassfish
# 6081          Varnish initial
# 137-139 445	SMB/CIFS tcp
# 3478 41641	Tailscale (UDP)
#
INPUT_TCP="9722 80 8080 443 20:21 25 465 587 993 110 143 10000 20000 53 5900 55000:56000"
INPUT_UDP="53 5353 5060 694 55000:56000"
#
IPTABLES=/sbin/iptables
WHITELIST=/usr/local/etc/whitelist.txt
BLACKLIST=/usr/local/etc/blacklist.txt
#
#DO NOT EDIT BELOW THIS LINE
###
RETVAL=0
# To start the firewall
start() {
	echo "Setting up firewall rules..."
	# Block everything by default
	$IPTABLES -P INPUT DROP
	$IPTABLES -P FORWARD DROP
	$IPTABLES -P OUTPUT DROP
	#
	## Unlimited traffic for loopback
	$IPTABLES -A INPUT -i lo -j ACCEPT -m comment --comment "allow loopback"
	$IPTABLES -A OUTPUT -o lo -j ACCEPT -m comment --comment "allow loopback"
	#
	## tun tap
	$IPTABLES -A OUTPUT -o tun+ -j ACCEPT
	$IPTABLES -A OUTPUT -o tap+ -j ACCEPT	
	## Accept packets that are part of an existing connection
	$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	
	#
	## Whitelisted IPs
	#
	$IPTABLES -N whitelist
	$IPTABLES -I INPUT 1 -j whitelist
	for x in `grep -v ^# $WHITELIST | awk '{print $1}'`; do
		case $x in
			\#*|\;*)
			continue
			;;
		esac 
		echo "Permitting $x"
		$IPTABLES -A whitelist -t filter -s $x -j ACCEPT
	done
	
	#
	## Blacklisted IPs
	#
	$IPTABLES -N blacklist
	$IPTABLES -I INPUT 2 -j blacklist
	#cmnttxt=""
	for x in `grep -v ^# $BLACKLIST | awk '{print $1}'`; do
		case $x in
			\#*|\;*)
			#cmnttxt=$x
			continue
			;;
		esac 
		echo "Denying $x"
		$IPTABLES -A blacklist -t filter -s $x -j DROP
		#-m comment --comment cmnttxt
	done
	
	# Drop all invalid packets - disable on VPN
	$IPTABLES -A INPUT -m state --state INVALID -j DROP
	$IPTABLES -A FORWARD -m state --state INVALID -j DROP
	$IPTABLES -A OUTPUT -m state --state INVALID -j DROP
	# Drop excessive RST packets to avoid smurf attacks
	$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
	# Attempt to block portscans
	$IPTABLES -N portscan
	# Anyone who tried to portscan us is locked out for an entire day.
	$IPTABLES -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
	$IPTABLES -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
	# Once the day has passed, remove them from the portscan list
	$IPTABLES -A INPUT   -m recent --name portscan --remove
	$IPTABLES -A FORWARD -m recent --name portscan --remove
	# These rules add scanners to the portscan list, and log the attempt.
	$IPTABLES -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
	$IPTABLES -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
	$IPTABLES -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
	$IPTABLES -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP	
	
	#
	## ddos
	$IPTABLES -N ddos_attack
	$IPTABLES -A INPUT -p udp -m state --state NEW -m recent --set --name ddos_attack --rsource 
	$IPTABLES -A INPUT -p udp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 --name ddos_attack --rsource -j DROP
	
	#
	## ssh brute force jail
	$IPTABLES -N ssh_attack
	$IPTABLES -A INPUT -p tcp --dport 22 -m state --state NEW -j ssh_attack
	$IPTABLES -A INPUT -p tcp --dport 9722 -m state --state NEW -j ssh_attack
	$IPTABLES -A ssh_attack -m recent --set --name ssh_attack
	$IPTABLES -A ssh_attack -m recent --update --seconds 60 --hitcount 5 --name ssh_attack -j DROP

	# ICMP packets should fit in a Layer 2 frame, thus they should
	# never be fragmented.  Fragmented ICMP packets are a typical sign
	# of a denial of service attack.
	$IPTABLES -N icmp_packets
	$IPTABLES -A icmp_packets --fragment -p ICMP -j LOG --log-prefix "ICMP Fragment: "
	$IPTABLES -A icmp_packets --fragment -p ICMP -j DROP
	
	#
	## Permitted Ports
	#	
	for port in $INPUT_TCP; do
		echo "Accepting port TCP $port"
		$IPTABLES -A INPUT -t filter -p tcp --dport $port -j ACCEPT
		$IPTABLES -A OUTPUT -t filter -p tcp --sport $port -j ACCEPT
	done
	for port in $INPUT_UDP; do
		echo "Accepting port UDP $port"
		$IPTABLES -A INPUT -t filter -p udp --dport $port -j ACCEPT
	done

	echo "Accepting Samba ports on 192.168.0.0/18 network"
	$IPTABLES -A INPUT -s 192.168.0.0/18 -m state --state NEW -p udp --dport 137 -j ACCEPT
	$IPTABLES -A INPUT -s 192.168.0.0/18 -m state --state NEW -p udp --dport 138 -j ACCEPT
	$IPTABLES -A INPUT -s 192.168.0.0/18 -m state --state NEW -p tcp --dport 139 -j ACCEPT
	$IPTABLES -A INPUT -s 192.168.0.0/18 -m state --state NEW -p tcp --dport 445 -j ACCEPT	
	
	#
	## Permitted Services (gre)
	#	
	$IPTABLES -A INPUT -p 47 -j ACCEPT
	$IPTABLES -A OUTPUT -p 47 -j ACCEPT
	
	#
	## Drop and log the rest
	$IPTABLES -A INPUT -j LOG --log-prefix "INPUT DROP: " -m limit --limit 10/minute --limit-burst 10
	$IPTABLES -A INPUT -j DROP
	#
	## Output accept everything but 'invalid' packets
	$IPTABLES -A OUTPUT -m state --state NEW -j ACCEPT
	$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPTABLES -A OUTPUT -j LOG --log-prefix "OUTPUT DROP: "
	$IPTABLES -A OUTPUT -j DROP
	echo "--------------------------------------------------"
	echo "Firewall Loaded"
	echo "--------------------------------------------------"
	#$IPTABLES -L -nvx
	#$IPTABLES -t nat -L
	RETVAL=0

}
# To stop the firewall
stop() {
	echo "--------------------------------------------------"
	echo "Firewall Stopped"
	echo "--------------------------------------------------"
	$IPTABLES -L -nvx
	$IPTABLES -t nat -L
	RETVAL=0
}
clear() {
	$IPTABLES -F
	$IPTABLES -X
	$IPTABLES -t nat -F
	$IPTABLES -t nat -X
	$IPTABLES -t mangle -F
	$IPTABLES -t mangle -X
	$IPTABLES -P INPUT ACCEPT
	$IPTABLES -P FORWARD ACCEPT
	$IPTABLES -P OUTPUT ACCEPT
	RETVAL=0
}
case $1 in
	start)
	clear
	start
	;;
stop)
	clear
	stop
	;;
restart)
	clear
	start
	;;
status)
	$IPTABLES -L -nvx
	$IPTABLES -t nat -L
	RETVAL=0
	;;
mod)
	# enable ftp pasive mode
	modprobe ip_conntrack_ftp
	;;
openvpn)
	$IPTABLES -A INPUT -i eth0 -m state --state NEW -p udp --dport 1194 -j ACCEPT
	$IPTABLES -A INPUT -i tun+ -j ACCEPT
	$IPTABLES -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
	$IPTABLES -A FORWARD -i tun+ -j ACCEPT
	$IPTABLES -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
	$IPTABLES -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
	$IPTABLES -A OUTPUT -o tun+ -j ACCEPT
	;;	
*)
	echo "Usage: firewall {start|stop|restart|status|mod|openvpn}"
	RETVAL=1
esac
exit $RETVAL
