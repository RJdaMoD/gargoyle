#!/bin/sh
apContainerVar="$1"
shift
if [ -z "$apContainerVar" ]; then
	apContainerVar="originalManagedAPs"
fi
hosts_to_query="$@"
if [ -z "$hosts_to_query" ]; then
	hosts_to_query="$(echo -n $HOSTNAME ''; uci -q get ap_management_gargoyle.ap_management.managed_aps)"
fi
cmd="$(cat <<- EOC
firstRadio=true
echo "["
for radio in \$(uci show wireless | grep wifi-device | sed -E 's/^wireless\.(.*)=wifi-device\$/\1/'); do
	radioPath=\$(uci get wireless.\$radio.path)
	if [ \$(echo \$radioPath | grep "pci0000:00" | wc -l) = '1' ]; then
		phy=\$(ls -1 /sys/bus/pci/devices/\$(echo \$radioPath | sed -E 's|^.*pci0000:00/(.*)\$|\1|')/ieee80211)
	elif [ \$(echo \$radioPath | grep "^platform/" | wc -l) = '1' ]; then
		phy=\$(ls -1 /sys/bus/platform/devices/\$(echo \$radioPath | sed -E 's|^platform/(.*)\$|\1|')/ieee80211)
	else
		continue
	fi
	if \$firstRadio; then
		firstRadio=false
	else
		echo ","
	fi
	echo "	{\"radio\":\"\$radio\", \"phy\":\"\$phy\", \"bands\":["
	iw phy \$phy channels | awk '
		function printChannel(lastChannel) {
			if(channel) {
				printf "\t\t\t\t\t{\"channel\":%d, \"frequency\":%de6, \"enabled\":%s, \"maxTxPower\":%s, \"radarDetection\":%s,\n",\
					channel, frequencyMHz, enabled, maxTxPower, radarDetection?"true":"false"
				print "\t\t\t\t\t\t\"channelWidths\":"channelWidths dfs"}"(lastChannel?"":",")
				radarDetection=""
				dfs=""
			}
		}
		function printBandEnd(lastBand) {
			printChannel(1);
			if(band) {
				print "\t\t\t\t]\n\t\t\t}"(lastBand?"\n\t\t]":",")
			}
		}
		/^Band / {
			printBandEnd(0);
			band=gensub(/:/,"","",\$2);
			print "\t\t\t{\"band\":"band", \"channels\":["
		}
		/^[ \t]+\* \d+ MHz \[\d+\]/ {
			printChannel(0);
			frequencyMHz=\$2;
			channel=gensub(/\[|\]/,"","g",\$4);
			enabled=(\$5!="(disabled)") ? "true" : "false";
		}
		/^[ \t]+Maximum TX power: / {	maxTxPower=\$4	}
		/^[ \t]+Channel widths: / {
			channelWidths="["
			for(i=3;i<=NF;i++) { channelWidths=channelWidths"\""gensub(/20MHz/,"HT20","",\$i)"\""(i<NF?",":"]") }
		}
		/^[ \t]+Radar detection/ {
			radarDetection=1
		}
		/^[ \t]+DFS state: / {
			dfs=dfs", \"dfs_state\":\""\$3"\""
			if(\$5) { dfs=dfs", \"dfs_time\":"\$5 }
		}
		/^[ \t]+DFS CAC time: \d+ ms/ {
			dfs=dfs", \"dfs_cac\":"(\$4/1000)
		}
		END { printBandEnd(1) }';
	echo -n -e "\t}"
done
\$firstRadio || echo
echo "]"
EOC
)"
source /usr/lib/ap_management/runCommandOnAccessPoints.sh "$cmd" wifiCapabilities $hosts_to_query
wait
for hostWithUser in $hosts_to_query; do
	host=${host#*@}
	fileName=/tmp/wifiCapabilities.$host
	if [ -e $fileName ]; then
			echo "$apContainerVar.find(ap => ap.name == \"$hostWithUser\").radios = $(cat $fileName);"
	fi
done
