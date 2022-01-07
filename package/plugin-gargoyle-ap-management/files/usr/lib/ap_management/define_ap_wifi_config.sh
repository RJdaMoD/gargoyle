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
source /usr/lib/ap_management/runCommandOnAccessPoints.sh "uci show network; uci show wireless" wifiConfig $hosts_to_query
cat <<EOF
function addUCIlineToContainer(key,value,container)
{
	var keys = key.split(".");
	while(keys.length<3) keys.push("");
	if(value.match(/^'.*'$/))
	{
		value = value.substr(1, value.length - 2)
		if(value.match(/^.*(' '.*)+$/)) value = value.split("' '");
	}
	container.set(keys[0], keys[1], keys[2], value);
}
EOF
wait
for hostWithUser in $hosts_to_query; do
	host=${hostWithUser#*@}
	fileName=/tmp/wifiConfig.$host
	ip=$(nslookup $host | awk '/Address 1:/ { print $3 }')
	echo "hostWithUser: $hostWithUser, host: $host, fileName: $fileName, ip: $ip" 1>&2
	echo "tempUciContainer = new UCIContainer();"
	if [ -e $fileName ]; then
			awk -v FS='=' '{print "addUCIlineToContainer(\"" $1 "\",\"" $2 "\",tempUciContainer);"}' \
				$fileName
	else
		echo "$fileName does not exist!"
	fi
	echo "$apContainerVar.push({name:'$hostWithUser', hostName:'$host', ip:'$ip', config:tempUciContainer});"
done
cat <<EOF
tempUciContainer = undefined;
addUCIlineToContainer = undefined;
$apContainerVar.sort((x,y) => x.name == y.name ? 0 : x.name < y.name ? -1 : 1);
$apContainerVar.forEach(ap => {
				ap.bridges = ap.config.getAllSectionsOfType('network', 'interface')
            .filter(iface => ap.config.get('network', iface, 'type') === 'bridge');
        ap.lanVlan = 1;
        var vlanPattern = '\\.' + ap.lanVlan + '$';
				ap.lanBridge = ap.bridges.find(iface => ap.config.get('network', iface, 'ifname').split(' ')
								.find(ifname => ifname.match(vlanPattern)));
				ap.lanInterface = ap.lanBridge ?
						ap.config.get('network', ap.lanBridge, 'ifname').split(' ')
								.find(ifname => ifname.match(vlanPattern)).match('^(.*)' + vlanPattern)[1]
						: undefined;
		});
EOF