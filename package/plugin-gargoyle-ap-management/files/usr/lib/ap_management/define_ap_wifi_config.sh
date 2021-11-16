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
connectionKeepAliveTime=$(uci -q get ap_management_gargoyle.ap_management.connection_keep_alive)
[ -z $connectionKeepAliveTime ] && connectionKeepAliveTime=30
for host in $hosts_to_query; do
	ip=$(nslookup $host | awk '/Address 1:/ { print $3 }')
	if [ -n $ip ]; then
		prefix=
		if [ $host != $HOSTNAME ]; then
			prefix="openssh-ssh -o ControlMaster=auto -o ControlPath=/tmp/ssh-control-%C \
				-o ControlPersist=$connectionKeepAliveTime $host"
		fi
		fileName=/tmp/wifiConfig.${host#@}
		echo "uci show wireless" | \
		{
				if flock -xn 3; then
					cat /dev/null >$fileName;
					$prefix sh -s >&3;
				else
					flock -x 3;
				fi
		} 3>>$fileName &
	fi
done
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
for host in $hosts_to_query; do
	fileName=/tmp/wifiConfig.${host#@}
	ip=$(nslookup $host | awk '/Address 1:/ { print $3 }')
	echo "tempUciContainer = new UCIContainer();"
	if [ -e $fileName ]; then
			awk -v FS='=' '{print "addUCIlineToContainer(\"" $1 "\",\"" $2 "\",tempUciContainer);"}' \
				$fileName
	fi
	echo "$apContainerVar.push({name:'$host', hostName:'${host#@}', ip:'$ip', config:tempUciContainer});"
done
echo "tempUciContainer = undefined;"
echo "addUCIlineToContainer = undefined;"
echo "$apContainerVar.sort((x,y) => x.name == y.name ? 0 : x.name < y.name ? -1 : 1);"
