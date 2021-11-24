#!/bin/sh
cmd="$1"
shift
if [ -z "$cmd" ]; then
	$cmd="echo 1"
fi
fileNamePrefix="$1"
shift
hosts_to_query="$@"
if [ -z "$hosts_to_query" ]; then
	hosts_to_query="$(echo -n $HOSTNAME ''; uci -q get ap_management_gargoyle.ap_management.managed_aps)"
fi
connectionKeepAliveTime=$(uci -q get ap_management_gargoyle.ap_management.connection_keep_alive)
[ -z $connectionKeepAliveTime ] && connectionKeepAliveTime=30
for hostWithUser in $hosts_to_query; do
	host=${hostWithUser#*@}
	ip=$(nslookup $host | awk '/Address 1:/ { print $3 }')
	if [ -n $ip ]; then
		prefix=
		if [ $hostWithUser != $HOSTNAME ]; then
			prefix="openssh-ssh -o ControlMaster=auto -o ControlPath=/tmp/ssh-control-%C \
				-o ControlPersist=$connectionKeepAliveTime $hostWithUser"
		fi
		if [ -z "$fileNamePrefix" ]; then
			echo "$cmd" | $prefix sh -s >/dev/null &
		else
			fileName="/tmp/$fileNamePrefix.$host"
			echo "$cmd" | \
			{
					if flock -xn 3; then
						cat /dev/null >$fileName
						$prefix sh -s >&3
					else
						flock -x 3
					fi
			} 3>>$fileName &
		fi
	fi
done
