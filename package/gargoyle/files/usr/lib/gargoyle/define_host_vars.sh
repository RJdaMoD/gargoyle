#!/bin/sh

# This program is copyright © 2008-2010 Eric Bishop and is distributed under the terms of the GNU GPL 
# version 2.0 with a special clarification/exception that permits adapting the program to 
# configure proprietary "back end" software provided that all modifications to the web interface
# itself remain covered by the GPL. 
# See http://gargoyle-router.com/faq.html#qfoss for more information

echo "dhcpLeaseLines = new Array();"
if [ -e /tmp/dhcp.leases ] ; then
	cat /tmp/dhcp.leases | awk '{print "dhcpLeaseLines.push(\""$0"\");"}'
fi

echo "dhcp6LeaseLines = new Array();"
if [ -e /tmp/hosts/odhcpd ] ; then
	cat /tmp/hosts/odhcpd | grep "^#" | awk '{print "dhcp6LeaseLines.push(\""$0"\");"}'
fi


echo "hostsLines = new Array();"
if [ -e /etc/hosts ]; then
	cat /etc/hosts | awk '/^[0-9a-fA-F:]/{print "hostsLines.push(\""$1" "$2"\");"}'
fi


echo "wlanLines = new Array();"
echo "wifiLines = new Array();"
echo "wifiClientLines = new Array();"

for host in $(echo $HOSTNAME; uci -q get network.globals.managed_aps); do
	prefix=
	if [ $host != $HOSTNAME ]; then
		prefix="openssh-ssh -o ControlMaster=auto -o ControlPath=/tmp/ssh-control-%C -o ControlPersist=30 $host"
	fi
	fileName=/tmp/wifiStatus.${host#@}
	cat <<EOF | { if flock -xn 3; then cat /dev/null >$fileName; $prefix sh -s >&3; else flock -x 3; fi } 3>>$fileName &
iwinfo | awk -v HOSTNAME=\$HOSTNAME '/^wlan/ { printf "wlanLines.push(\""\$1"@"HOSTNAME" "} /ESSID:/ {gsub(/"/,"",\$3); printf ""\$3" "} /Access Point:/ {printf ""\$3" "} /Mode: .* Channel: / { print ""\$4"\");" }'
if [ -e /lib/wifi/broadcom.sh ] ; then
	wl assoclist | awk '{print "wifiLines.push(\""\$0"\");"}'
elif [ -e /lib/wifi/mac80211.sh ] && [ -e "/sys/class/ieee80211/phy0" ] ; then
	aps=\$( iwinfo | grep ESSID | awk ' { print \$1 } ' )
	if [ -n "\$aps" ] ; then
		for ap in \$aps ; do
			cli=\$( iwinfo \$ap i | grep Client )
			if [ -n "\$cli" ] ; then arrayname="wifiClientLines" ; else arrayname="wifiLines" ; fi
			iw \$ap station dump | awk -v ap=\$ap -v HOSTNAME=\$HOSTNAME '/^Station/ { printf "'\$arrayname'.push(\""\$2" " ;} /\tsignal:/ {printf ""\$2" "} /tx bitrate:/ {printf ""\$3" "} /rx bitrate:/ {printf ""\$3" "} /autho/ {print ap"@"HOSTNAME"\");"}'
		done
	fi
fi
EOF
done
wait
cat /tmp/wifiStatus.*


echo "conntrackLines = new Array();"
cat /proc/net/nf_conntrack | awk '{print "conntrackLines.push(\""substr($0,index($0,$3))"\");"}'

echo "arpLines = new Array();"
ip neigh | grep -v "FAILED" | awk '{print "arpLines.push(\""$0"\");"}'

current_time=$(date +%s)
echo "currentTime=$current_time;"
