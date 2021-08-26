# Copyright Eric Bishop, 2008-2010
# This is free software licensed under the terms of the GNU GPL v2.0
#
. /lib/functions.sh
. /lib/functions/network.sh
include /lib/network

ra_mask="0x0080"
ra_mark="$ra_mask/$ra_mask"

death_mask=0x8000
death_mark="$death_mask"

wan_if=""

apply_xtables_rule()
{
	rule="$1"
	family="${2:-ipv4}"

	if [ "$family" = "ipv4" ] || [ "$family" = "any" ] ; then
		iptables ${rule}
	fi
	if [ "$family" = "ipv6" ] || [ "$family" = "any" ] ; then
		ip6tables ${rule}
	fi
}

ip_family()
{
	ip="$1"
	ip4=$(echo "$ip" | grep -E "^\d+\.\d+\.\d+\.\d+$")
	[ -n "$ip4" ] && echo "ipv4"
	ip6=$(echo "$ip" | grep -E "^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$")
	[ -n "$ip6" ] && echo "ipv6"
}

mask_to_cidr()
{
	mask="$1"
	bits=0;
	mask_parts=$(echo $mask | sed 's/\./ /g')
	for p in $mask_parts ; do
		case $p in
			255)
				bits=$(($bits + 8)) ;;
			254)
				bits=$(($bits + 7)) ;;
			252)
				bits=$(($bits + 6)) ;;
			248)
				bits=$(($bits + 5)) ;;
			240)
				bits=$(($bits + 4)) ;;
			224)
				bits=$(($bits + 3)) ;;
			192)
				bits=$(($bits + 2)) ;;
			128)
				bits=$(($bits + 1)) ;;
		esac
	done
	echo $bits
}

define_wan_if()
{
	if  [ -z "$wan_if" ] ;  then
		#Wait for up to 15 seconds for the wan interface to indicate it is up.
		wait_sec=15
		while ! network_is_up wan && [ "$wait_sec" -gt 0 ] ; do
			sleep 1
			wait_sec=$(($wait_sec - 1))
		done

		#The interface name will depend on if pppoe is used or not.  If pppoe is used then
		#the name we are looking for is in network.wan.l3_device.  If there is nothing there
		#use the device named by network.wan.device

		network_get_device wan_if wan
		if [ -z "$wan_if" ] ; then
			network_get_physdev wan_if wan
		fi
	fi
}

# parse remote_accept sections in firewall config and add necessary rules
insert_remote_accept_rules()
{
	local config_name="firewall"
	local section_type="remote_accept"

	ssh_max_attempts=$(uci get dropbear.@dropbear[0].max_remote_attempts 2>/dev/null)
	ssh_port=$(uci get dropbear.@dropbear[0].Port)
	if [ -z "$ssh_max_attempts" ] || [ "$ssh_max_attempts" = "unlimited" ] ; then
		ssh_max_attempts=""
	else
		ssh_max_attempts=$(( $ssh_max_attempts + 1 ))
	fi

	#add rules for remote_accepts
	parse_remote_accept_config()
	{
		vars="local_port remote_port start_port end_port proto zone family"
		proto="tcp udp"
		zone="wan"
		family="ipv4"
		for var in $vars ; do
			config_get $var $1 $var
		done
		if [ "$proto" = "tcpudp" ] || [ -z "$proto" ] ; then
			proto="tcp udp"
		fi
		if [ "$family" = "any" ] ; then
			family="ipv4 ipv6"
		fi
		if [ -z "$family" ] ; then
			family="ipv4"
		fi 

		for fam in $family ; do
			for prot in $proto ; do
				if [ -n "$local_port" ] ; then
					if [ -z "$remote_port"  ] ; then
						remote_port="$local_port"
					fi

					#Discourage brute force attacks on ssh from the WAN by limiting failed conneciton attempts.
					#Each attempt gets a maximum of 10 password tries by dropbear.
					if   [ -n "$ssh_max_attempts"  ] && [ "$local_port" = "$ssh_port" ] && [ "$prot" = "tcp" ] ; then
						apply_xtables_rule "-t filter -A "input_${zone}_rule" -p "$prot" --dport $ssh_port -m recent --set --name SSH_CHECK" "$fam"
						apply_xtables_rule "-t filter -A "input_${zone}_rule" -m recent --update --seconds 300 --hitcount $ssh_max_attempts --name SSH_CHECK -j DROP" "$fam"
					fi

					if [ "$remote_port" != "$local_port" ] ; then
						if [ "$fam" = "ipv4" ] ; then
							#since we're inserting with -I, insert redirect rule first which will then be hit second, after setting connmark
							apply_xtables_rule "-t nat -I "zone_${zone}_prerouting" -p "$prot" --dport "$remote_port" -j REDIRECT --to-ports "$local_port"" "$fam"
							apply_xtables_rule "-t nat -I "zone_${zone}_prerouting" -p "$prot" --dport "$remote_port" -j CONNMARK --set-mark "$ra_mark"" "$fam"
							apply_xtables_rule "-t filter -A "input_${zone}_rule" -p $prot --dport "$local_port" -m connmark --mark "$ra_mark" -j ACCEPT" "$fam"
						else
							logger -t "gargoyle_firewall_util" "Port Redirect not supported for IPv6"
						fi
					else
						if [ "$fam" = "ipv4" ] ; then
							apply_xtables_rule "-t nat -I "zone_${zone}_prerouting" -p "$prot" --dport "$remote_port" -j REDIRECT --to-ports "$local_port"" "$fam"
						fi
						apply_xtables_rule "-t filter -A "input_${zone}_rule" -p "$prot" --dport "$local_port" -j ACCEPT" "$fam"
					fi
				elif [ -n "$start_port" ] && [ -n "$end_port" ] ; then
					if [ "$fam" = "ipv4" ] ; then
						apply_xtables_rule "-t nat -I "zone_${zone}_prerouting" -p "$prot" --dport "$start_port:$end_port" -j REDIRECT" "$fam"
					fi
					apply_xtables_rule "-t filter -A "input_${zone}_rule" -p "$prot" --dport "$start_port:$end_port" -j ACCEPT" "$fam"
				fi
			done
		done
	}
	config_load "$config_name"
	config_foreach parse_remote_accept_config "$section_type"
}

# creates a chain that sets third byte of connmark to a value that denotes what l7 proto
# is associated with connection. This only sets the connmark, it does not save it to mark
create_l7marker_chain()
{
	# eliminate chain if it exists
	delete_chain_from_table "mangle" "l7marker"

	app_proto_num=1
	app_proto_shift=16
	app_proto_mask="0xFF0000"

	all_prots=$(ls /etc/l7-protocols/* | sed 's/^.*\///' | sed 's/\.pat$//' )
	qos_active=$(ls /etc/rc.d/*qos_gargoyle* 2>/dev/null)
	if [ -n "$qos_active" ] ; then
		qos_l7=$(uci show qos_gargoyle | sed '/layer7=/!d; s/^.*=//g')
	fi
	fw_l7=$(uci show firewall | sed '/app_proto/!d; s/^.*=//g')
	all_used="$fw_l7 $qos_l7"

	if [ "$all_used" != " " ] ; then
		iptables -t mangle -N l7marker
		iptables -t mangle -I PREROUTING  -m connbytes --connbytes 0:20 --connbytes-dir both --connbytes-mode packets -m connmark --mark 0x0/$app_proto_mask -j l7marker
		iptables -t mangle -I POSTROUTING -m connbytes --connbytes 0:20 --connbytes-dir both --connbytes-mode packets -m connmark --mark 0x0/$app_proto_mask -j l7marker

		for proto in $all_prots ; do
			proto_is_used=$(echo "$all_used" | grep "$proto")
			if [ -n "$proto_is_used" ] ; then
				app_proto_mark=$(printf "0x%X" $(($app_proto_num << $app_proto_shift)) )
				iptables -t mangle -A l7marker -m connmark --mark 0x0/$app_proto_mask -m layer7 --l7proto $proto -j CONNMARK --set-mark $app_proto_mark/$app_proto_mask
				echo "$proto	$app_proto_mark	$app_proto_mask" >> /tmp/l7marker.marks.tmp
				app_proto_num=$((app_proto_num + 1))
			fi
		done

		copy_file="y"
		if [ -e /etc/md5/layer7.md5 ] ; then
			old_md5=$(cat /etc/md5/layer7.md5)
			current_md5=$(md5sum /tmp/l7marker.marks.tmp | awk ' { print $1 ; } ' )
			if [ "$current_md5" = "$old_md5" ] ; then
				copy_file="n"
			fi
		fi

		if [ "$copy_file" = "y" ] ; then
			mv /tmp/l7marker.marks.tmp /etc/l7marker.marks
			mkdir -p /etc/md5
			md5sum /etc/l7marker.marks | awk ' { print $1 ; }' > /etc/md5/layer7.md5
		else
			rm /tmp/l7marker.marks.tmp
		fi
	fi
}

insert_pf_loopback_rules()
{
	config_name="firewall"
	section_type="redirect"

	#Need to always delete the old chains first.
	delete_chain_from_table "nat"    "pf_loopback_A"
	delete_chain_from_table "filter" "pf_loopback_B"
	delete_chain_from_table "nat"    "pf_loopback_C"

	define_wan_if
	if [ -z "$wan_if" ]  ; then return ; fi
	network_get_ipaddr wan_ip wan
	network_get_subnet lan_mask lan

	if [ -n "$wan_ip" ] && [ -n "$lan_mask" ] ; then

		iptables -t nat    -N "pf_loopback_A"
		iptables -t filter -N "pf_loopback_B"
		iptables -t nat    -N "pf_loopback_C"

		iptables -t nat    -I zone_lan_prerouting -d $wan_ip -j pf_loopback_A
		iptables -t filter -I zone_lan_forward               -j pf_loopback_B
		iptables -t nat    -I postrouting_rule -o br-lan     -j pf_loopback_C

		add_pf_loopback()
		{
			local vars="src dest proto src_dport dest_ip dest_port"
			local all_defined="1"
			for var in $vars ; do
				config_get $var $1 $var
				loaded=$(eval echo "\$$var")
				#echo $var =  $loaded
				if [ -z "$loaded" ] && [ ! "$var" = "$src_dport" ] ; then
					all_defined="0"
				fi
			done

			if [ -z "$src_dport" ] ; then
				src_dport=$dest_port
			fi

			sdp_dash=$src_dport
			sdp_colon=$(echo $sdp_dash | sed 's/\-/:/g')
			dp_dash=$dest_port
			dp_colon=$(echo $dp_dash | sed 's/\-/:/g')

			if [ "$all_defined" = "1" ] && [ "$src" = "wan" ] && [ "$dest" = "lan" ]  ; then
				iptables -t nat    -A pf_loopback_A -p $proto --dport $sdp_colon -j DNAT --to-destination $dest_ip:$dp_dash
				iptables -t filter -A pf_loopback_B -p $proto --dport $dp_colon -d $dest_ip -j ACCEPT
				iptables -t nat    -A pf_loopback_C -p $proto --dport $dp_colon -d $dest_ip -s $lan_mask -j MASQUERADE
			fi
		}

		config_load "$config_name"
		config_foreach add_pf_loopback "$section_type"
	fi
}

insert_dmz_rule()
{
	local config_name="firewall"
	local section_type="dmz"

	#add rules for remote_accepts
	parse_dmz_config()
	{
		vars="to_ip from"
		for var in $vars ; do
			config_get $var $1 $var
		done
		if [ -n "$from" ] ; then
			network_get_device from_if "$from" || \
				from_if=$(uci -q get network.$from.ifname)
		fi
		# echo "from_if = $from_if"
		if [ -n "$to_ip" ] && [ -n "$from"  ] && [ -n "$from_if" ] ; then
			iptables -t nat -A "zone_"$from"_prerouting" -i $from_if -j DNAT --to-destination $to_ip
			# echo "iptables -t nat -A "prerouting_"$from -i $from_if -j DNAT --to-destination $to_ip"
			iptables -t filter -I "zone_"$from"_forward" -d $to_ip -j ACCEPT
		fi
	}
	config_load "$config_name"
	config_foreach parse_dmz_config "$section_type"
}

insert_restriction_rules()
{
	define_wan_if
	if [ -z "$wan_if" ]  ; then return ; fi

	if [ -e /tmp/restriction_init.lock ] ; then return ; fi
	touch /tmp/restriction_init.lock

	egress_exists=$(iptables -t filter -L egress_restrictions 2>/dev/null)
	ingress_exists=$(iptables -t filter -L ingress_restrictions 2>/dev/null)
	egress_exists=${egress_exists}$(ip6tables -t filter -L egress_restrictions 2>/dev/null)
	ingress_exists=${ingress_exists}$(ip6tables -t filter -L ingress_restrictions 2>/dev/null)

	if [ -n "$egress_exists" ] ; then
		delete_chain_from_table filter egress_whitelist
		delete_chain_from_table filter egress_restrictions
	fi
	if [ -n "$ingress_exists" ] ; then
		delete_chain_from_table filter ingress_whitelist
		delete_chain_from_table filter ingress_restrictions
	fi

	apply_xtables_rule "-t filter -N egress_restrictions" "any"
	apply_xtables_rule "-t filter -N ingress_restrictions" "any"
	apply_xtables_rule "-t filter -N egress_whitelist" "any"
	apply_xtables_rule "-t filter -N ingress_whitelist" "any"

	apply_xtables_rule "-t filter -I FORWARD -o $wan_if -j egress_restrictions" "any"
	apply_xtables_rule "-t filter -I FORWARD -i $wan_if -j ingress_restrictions" "any"

	apply_xtables_rule "-t filter -I egress_restrictions  -j egress_whitelist" "any"
	apply_xtables_rule "-t filter -I ingress_restrictions -j ingress_whitelist" "any"

	package_name="firewall"
	parse_rule_config()
	{
		section=$1
		section_type=$(uci get "$package_name"."$section")

		config_get "enabled" "$section" "enabled"
		if [ -z "$enabled" ] ; then enabled="1" ; fi
		if [ "$enabled" = "1" ] && ( [ "$section_type"  = "restriction_rule" ] || [ "$section_type" = "whitelist_rule" ] ) ; then
			#convert app_proto && not_app_proto to connmark here
			config_get "app_proto" "$section" "app_proto"
			config_get "not_app_proto" "$section" "not_app_proto"

			if [ -n "$app_proto" ] ; then
				app_proto_connmark=$(cat /etc/l7marker.marks 2>/dev/null | grep $app_proto | awk '{ print $2 ; }' )
				app_proto_mask=$(cat /etc/l7marker.marks 2>/dev/null | grep $app_proto | awk '{ print $3 ;  }' )
				uci set "$package_name"."$section".connmark="$app_proto_connmark/$app_proto_mask"
			fi
			if [ -n "$not_app_proto" ] ; then
				not_app_proto_connmark=$(cat /etc/l7marker.marks 2>/dev/null | grep "$not_app_proto" | awk '{ print $2 }')
				not_app_proto_mask=$(cat /etc/l7marker.marks 2>/dev/null | grep "$not_app_proto" | awk '{ print $3 }')
				uci set "$package_name"."$section".not_connmark="$not_app_proto_connmark/$not_app_proto_mask"
			fi

			table="filter"
			chain="egress_restrictions"
			ingress=""
			target="REJECT"

			config_get "is_ingress" "$section" "is_ingress"
			if [ "$is_ingress" = "1" ] ; then
				ingress=" -i "
				if [ "$section_type" = "restriction_rule"  ] ; then
					chain="ingress_restrictions"
				else
					chain="ingress_whitelist"
				fi
			else
				if [ "$section_type" = "restriction_rule"  ] ; then
					chain="egress_restrictions"
				else
					chain="egress_whitelist"
				fi
			fi

			if [ "$section_type" = "whitelist_rule" ] ; then
				target="ACCEPT"
			fi

			config_get "family" "$section" "family"
			[ -z "$family" ] && family="ipv4"

			make_iptables_rules -p "$package_name" -s "$section" -t "$table" -c "$chain" -g "$target" -f "$family" $ingress
			make_iptables_rules -p "$package_name" -s "$section" -t "$table" -c "$chain" -g "$target" -f "$family" $ingress -r

			uci del "$package_name"."$section".connmark 2>/dev/null
			uci del "$package_name"."$section".not_connmark	 2>/dev/null
		fi
	}

	config_load "$package_name"
	config_foreach parse_rule_config "whitelist_rule"
	config_foreach parse_rule_config "restriction_rule"

	rm -rf /tmp/restriction_init.lock
}

initialize_quotas()
{
	define_wan_if
	if [ -z "$wan_if" ] ; then return ; fi

	if [  -e /tmp/quota_init.lock ] ; then return ; fi
	touch /tmp/quota_init.lock

	network_get_subnet lan_mask lan
	network_get_subnet6 lan_ipmask6 lan
	[ -z "$lan_ipmask6" ] && lan_ipmask6="2001:db8::/32"
	full_qos_enabled=$(ls /etc/rc.d/*qos_gargoyle 2>/dev/null)

	if [ -n "$full_qos_enabled" ] ; then
		full_up=$(uci get qos_gargoyle.upload.total_bandwidth 2>/dev/null)
		full_down=$(uci get qos_gargoyle.download.total_bandwidth 2>/dev/null)
		if [ -z "$full_up" ] && [ -z "$full_down" ] ; then
			full_qos_enabled=""
		fi
	fi


	# restore_quotas does the hard work of building quota chains & rebuilding crontab file to do backups
	#
	# this initializes qos functions ONLY if we have quotas that
	# have up and down speeds defined for when quota is exceeded
	# and full qos is not enabled
	if [ -z "$full_qos_enabled" ] ; then
		restore_quotas    -w $wan_if -d $death_mark -m $death_mask -s "$lan_mask" -t $lan_ipmask6 -c "0 0,4,8,12,16,20 * * * /usr/bin/backup_quotas >/dev/null 2>&1"
		initialize_quota_qos
	else
		restore_quotas -q -w $wan_if -d $death_mark -m $death_mask -s "$lan_mask" -t $lan_ipmask6 -c "0 0,4,8,12,16,20 * * * /usr/bin/backup_quotas >/dev/null 2>&1"
		cleanup_old_quota_qos
	fi

	#enable cron, but only restart cron if it is currently running
	#since we initialize this before cron, this will
	#make sure we don't start cron twice at boot
	/etc/init.d/cron enable
	cron_active=$(ps | grep "crond" | grep -v "grep" )
	if [ -n "$cron_active" ] ; then
		/etc/init.d/cron restart
	fi

	rm -rf /tmp/quota_init.lock
}

load_all_config_sections()
{
	local config_name="$1"
	local section_type="$2"

	all_config_sections=""
	section_order=""
	config_cb()
	{
		if [ -n "$2" ] || [ -n "$1" ] ; then
			if [ -n "$section_type" ] ; then
				if [ "$1" = "$section_type" ] ; then
					all_config_sections="$all_config_sections $2"
				fi
			else
				all_config_sections="$all_config_sections $2"
			fi
		fi
	}

	config_load "$config_name"
	echo "$all_config_sections"
}

cleanup_old_quota_qos()
{
	for iface in $(tc qdisc show | awk '{print $5}' | sort -u ); do
		tc qdisc del dev "$iface" root >/dev/null 2>&1
	done
}

initialize_quota_qos()
{
	cleanup_old_quota_qos

	#speeds should be in kbyte/sec, units should NOT be present in config file (unit processing should be done by front-end)
	quota_sections=$(load_all_config_sections "firewall" "quota")
	upload_speeds=""
	download_speeds=""
	config_load "firewall"
	for q in $quota_sections ; do
		config_get "exceeded_up_speed" $q "exceeded_up_speed"
		config_get "exceeded_down_speed" $q "exceeded_down_speed"
		if [ -n "$exceeded_up_speed" ] && [ -n "$exceeded_down_speed" ] ; then
			if [ $exceeded_up_speed -gt 0 ] && [ $exceeded_down_speed -gt 0 ] ; then
				upload_speeds="$exceeded_up_speed $upload_speeds"
				download_speeds="$exceeded_down_speed $download_speeds"
			fi
		fi
	done

	#echo "upload_speeds = $upload_speeds"

	unique_up=$( printf "%d\n" $upload_speeds 2>/dev/null | sort -u -n)
	unique_down=$( printf "%d\n" $download_speeds 2>/dev/null | sort -u -n)

	#echo "unique_up = $unique_up"

	num_up_bands=1
	num_down_bands=1
	if [ -n "$upload_speeds" ] ; then
		num_up_bands=$((1 + $(printf "%d\n" $upload_speeds 2>/dev/null | sort -u -n |  wc -l) ))
	fi
	if [ -n "$download_speeds" ] ; then
		num_down_bands=$((1 + $(printf "%d\n" $download_speeds 2>/dev/null | sort -u -n |  wc -l) ))
	fi

	#echo "num_up_bands=$num_up_bands"
	#echo "num_down_bands=$num_down_bands"

	if [ -n "$wan_if" ] && [ $num_up_bands -gt 1 ] && [ $num_down_bands -gt 1 ] ; then
		insmod sch_prio  >/dev/null 2>&1
		insmod sch_tbf   >/dev/null 2>&1
		insmod cls_fw    >/dev/null 2>&1

		ifconfig imq0 down  >/dev/null 2>&1
		ifconfig imq1 down  >/dev/null 2>&1
		rmmod  imq          >/dev/null 2>&1
		# Allow IMQ to fail to load 3 times (15 seconds) before we bail out
		# No particularly graceful way to get out of this one. Quotas will be active but speed limits won't be enforced.
		insmod imq numdevs=1 hook_chains="INPUT,FORWARD" hook_tables="mangle,mangle" >/dev/null 2>&1
		cnt=0
		while [ "$(ls -d /proc/sys/net/ipv4/conf/imq* 2>&- | wc -l)" -eq "0" ]
			do
				logger -t "gargoyle_firewall_util" "insmod imq failed. Waiting and trying again..."
				sleep 5
				cnt=`expr $cnt + 1`
				if [ $cnt -ge 3 ] ; then
					logger -t "gargoyle_firewall_util" "Could not insmod imq, too many retries. Stopping."
					cleanup_old_quota_qos
					return
				fi
				insmod imq numdevs=1 hook_chains="INPUT,FORWARD" hook_tables="mangle,mangle" >/dev/null 2>&1
			done
		ip link set imq0 up

		#egress/upload
		tc qdisc del dev $wan_if root >/dev/null 2>&1
		tc qdisc add dev $wan_if handle 1:0 root prio bands $num_up_bands priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
		cur_band=2
		upload_shift=0
		for rate_kb in $unique_up ; do
			kbit=$(echo $((rate_kb*8))kbit)
			mark=$(($cur_band << $upload_shift ))
			tc filter add dev $wan_if parent 1:0 prio $cur_band protocol ip  handle $mark fw flowid 1:$cur_band
			tc qdisc  add dev $wan_if parent 1:$cur_band handle $cur_band: tbf rate $kbit burst $kbit limit $kbit
			cur_band=$(($cur_band+1))
		done

		#ingress/download
		tc qdisc del dev imq0 root >/dev/null 2>&1
		tc qdisc add dev imq0 handle 1:0 root prio bands $num_down_bands priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
		cur_band=2
		download_shift=8
		for rate_kb in $unique_down ; do
			kbit=$(echo $((rate_kb*8))kbit)
			mark=$(($cur_band << $download_shift ))
			tc filter add dev imq0 parent 1:0 prio $cur_band protocol ip  handle $mark fw flowid 1:$cur_band
			tc qdisc  add dev imq0 parent 1:$cur_band handle $cur_band: tbf rate $kbit burst $kbit limit $kbit
			cur_band=$(($cur_band+1))
		done

		iptables -t mangle -I ingress_quotas -i $wan_if -j IMQ --todev 0

		#tc -s qdisc show dev $wan_if
		#tc -s qdisc show dev imq0
	fi
}

enforce_dhcp_assignments()
{
	enforce_assignments=$(uci get firewall.@defaults[0].enforce_dhcp_assignments 2> /dev/null)
	delete_chain_from_table "filter" "lease_mismatch_check"

	local pairs1
	local pairs2
	local pairs
	pairs1=""
	pairs2=""
	if [ -e /tmp/dhcp.leases ] ; then
		pairs1=$(cat /tmp/dhcp.leases | sed '/^[ \t]*$/d' | awk ' { print $2"^"$3"\n" ; } ' )
	fi
	if [ -e /etc/ethers ] ; then
		pairs2=$(cat /etc/ethers | sed '/^[ \t]*$/d' | awk ' { print $1"^"$2"\n" ; } ' )
	fi
	pairs=$( printf "$pairs1\n$pairs2\n" | sort | uniq )


	if [ "$enforce_assignments" = "1" ] && [ -n "$pairs" ] ; then
		iptables -t filter -N lease_mismatch_check
		local p
		for p in $pairs ; do
			local mac
			local ip
			mac=$(echo $p | sed 's/\^.*$//g')
			ip=$(echo $p | sed 's/^.*\^//g')
			if [ -n "$ip" ] && [ -n "$mac" ] ; then
				iptables -t filter -A lease_mismatch_check  ! -s  "$ip"  -m mac --mac-source  "$mac"  -j REJECT
				iptables -t filter -A lease_mismatch_check  -s  "$ip"  -m mac ! --mac-source  "$mac"  -j REJECT
			fi
		done
		iptables -t filter -I delegate_forward -j lease_mismatch_check
	fi
}

force_router_dns()
{
	force_router_dns=$(uci get firewall.@defaults[0].force_router_dns 2> /dev/null)
	if [ "$force_router_dns" = "1" ] ; then
		iptables -t nat -I zone_lan_prerouting -p tcp --dport 53 -j REDIRECT
		iptables -t nat -I zone_lan_prerouting -p udp --dport 53 -j REDIRECT
	fi
}

add_adsl_modem_routes()
{
	wan_proto=$(uci -q get network.wan.proto)
	if [ "$wan_proto" = "pppoe" ] ; then
		wan_dev=$(uci -q get network.wan.ifname) #not really the interface, but the device
		iptables -A postrouting_rule -t nat -o $wan_dev -j MASQUERADE
		iptables -A forwarding_rule -o $wan_dev -j ACCEPT
		/etc/ppp/ip-up.d/modemaccess.sh firewall $wan_dev
	fi
}

initialize_firewall()
{
	iptables -I zone_lan_forward -i br-lan -o br-lan -j ACCEPT
	insert_remote_accept_rules
	insert_dmz_rule
	create_l7marker_chain
	enforce_dhcp_assignments
	force_router_dns
	add_adsl_modem_routes
  isolate_guest_and_local_networks
}


guest_mac_from_uci() {
	local is_guest_network
	local macaddr
	config_get is_guest_network "$1" is_guest_network
	if [ "$is_guest_network" = "1" ]; then
		config_get macaddr "$1" macaddr
		echo "$macaddr"
	fi
}

get_guest_macs() {
	config_foreach guest_mac_from_uci "wifi-iface"
}

local_mac_from_uci() {
	local is_local_network
	local macaddr
	config_get is_local_network "$1" is_local_network
	if [ "$is_local_network" = "1" ]; then
		config_get macaddr "$1" macaddr
		echo "$macaddr"
	fi
}

get_local_macs() {
	config_foreach local_mac_from_uci "wifi-iface"
}

censored_mac_from_uci() {
	local is_censored_network
	local macaddr
	config_get is_censored_network "$1" is_censored_network
	if [ "$is_censored_network" = "1" ]; then
		config_get macaddr "$1" macaddr
		echo "$macaddr"
	fi
}

get_censored_macs() {
	config_foreach censored_mac_from_uci "wifi-iface"
}

wifi_iface_for_mac_from_uci() {
	local wifi_iface="$1"
	local mac_addr_to_seek="$2"
	local mac_addr_of_iface
	config_get mac_addr_of_iface $wifi_iface macaddr
	if [ "$mac_addr_of_iface" = "$mac_addr_to_seek" ]; then
		echo "$wifi_iface"
	fi
}

get_wifi_iface_for_mac()
{
	local mac_addr_to_seek="$1"
	local wifi_ifaces=$(config_foreach wifi_iface_for_mac_from_uci "wifi-iface" $mac_addr_to_seek)
	for wifi_iface in $wifi_ifaces ; do
		echo $wifi_iface
		break
	done
}

ip_to_number() {
	local ip=$(echo "$1" | sed "s|^\([^/]*\)/.*$|\1|") # strip off netmask if present
	local ip_n=0
	for oktet in $(echo $ip | sed 'y/./ /'); do
		ip_n=$(($ip_n*256+$oktet))
	done
	echo $ip_n
}

ip_in_subnet() {
	local ip=$(ip_to_number "$1")
	local subnet_ip=$(ip_to_number "$2")
	local subnet_mask=$(ip_to_number "$3")
	[ $(($ip&$subnet_mask)) = $(($subnet_ip&$subnet_mask)) ]
}

isolate_guest_and_local_networks() {
	ebtables -t filter -F FORWARD
	ebtables -t filter -F INPUT
	ebtables -t filter -F OUTPUT
	ebtables -t filter -N logAndDrop
	ebtables -t filter -F logAndDrop
	ebtables -t filter -P logAndDrop DROP
	ebtables -t filter -A logAndDrop --log-level warning \
		--log-prefix "ebtables-drop" --log-ip --log-arp --log-ip6 -j DROP
	local router_ip=$(uci -q -p /tmp/state get network.lan.gateway) # get ip of router if we are an access point
	local ap_ip=$(uci -p /tmp/state get network.lan.ipaddr)
	local is_router="0"
	if [ -z "$router_ip" ]; then
		 router_ip="$ap_ip" # we are the router
		 is_router="1"
	fi
	local lan_netmask=$(uci -p /tmp/state get network.lan.netmask)

	config_load "wireless"
	local guest_macs=$( get_guest_macs )
	local local_macs=$( get_local_macs )
	local censored_macs=$( get_censored_macs )
	if [ -n "$guest_macs" ] || [ -n "$local_macs" ] || [ -n "$censored_macs" ]; then
		local lanifs=`brctl show br-lan 2>/dev/null | awk ' $NF !~ /interfaces/ { print $NF } '`
		local lif
		for lif in $lanifs ; do
			for gmac in $guest_macs ; do
				local is_guest=$(ifconfig "$lif"	2>/dev/null | grep -i "$gmac")
				if [ -n "$is_guest" ]; then
					local wifi_iface=$(get_wifi_iface_for_mac "$gmac")
					local allowed_ips
					local forbidden_ips
					local allowed_servers
					local logDrops
					local dropTarget=DROP
					config_get allowed_ips "$wifi_iface" allowed_ips
					config_get forbidden_ips "$wifi_iface" forbidden_ips
					config_get allowed_servers "$wifi_iface" allowed_servers
					config_get logDrops "$wifi_iface" logDrops
					[ "$logDrops" = 1 ] && dropTarget=logAndDrop
					echo "$lif with mac $gmac is wireless guest named $wifi_iface$(
							if [ -n "$allowed_ips" ]; then
								echo -n " but has these local ips allowed: $allowed_ips"
								if [ -n "$forbidden_ips" ]; then
									echo " except $forbidden_ips"
								else
									echo
								fi
							fi)"
					if [ -n "$allowed_servers" ]; then
						echo "$lif is allowed to host these servers: $allowed_servers"
					fi
					#Allow access to WAN but not other LAN hosts for anyone on guest network - does not work for access points, better drop all traffic to local ips, see below
					#ebtables -t filter -A FORWARD -i "$lif" --logical-out br-lan -j DROP
					restrict_guest_interface "$lif" $router_ip $lan_netmask $is_router \
						"$allowed_ips" "$forbidden_ips" "$allowed_servers" $dropTarget
				fi
			done
			for lmac in $local_macs ; do
				local is_local=$(ifconfig "$lif" 2>/dev/null | grep -i "$lmac")
				if [ -n "$is_local" ]; then
					#Only allow access to LAN for anyone on local network
					local wifi_iface=$(get_wifi_iface_for_mac "$lmac")
					local allowed_ips
					local forbidden_ips
					local allowed_servers
					local logDrops
					local dropTarget=DROP
					config_get allowed_ips "$wifi_iface" allowed_ips
					config_get forbidden_ips "$wifi_iface" forbidden_ips
					config_get allowed_servers "$wifi_iface" allowed_servers
					config_get logDrops "$wifi_iface" logDrops
					[ "$logDrops" = 1 ] && dropTarget=logAndDrop
					echo "$lif with mac $lmac is local wifi named $wifi_iface$(
							if [ -n "$allowed_ips" ]; then
								echo -n " and has these ips allowed: $allowed_ips"
								if [ -n "$forbidden_ips" ]; then
									echo " except $forbidden_ips"
								else
									echo
								fi
							fi)"
					if [ -n "$allowed_servers" ]; then
						echo "$lif is allowed to host these servers: $allowed_servers"
					fi
					restrict_local_interface "$lif" $router_ip $lan_netmask $is_router \
						"$allowed_ips" "$forbidden_ips" "$allowed_servers" $dropTarget
				fi
			done
			for cmac in $censored_macs ; do
				local is_censored=$(ifconfig "$lif" 2>/dev/null | grep -i "$cmac")
				if [ -n "$is_censored" ]; then
					#censor access to given ips for anyone on censored network
					local wifi_iface=$(get_wifi_iface_for_mac "$cmac")
					local allowed_ips
					local forbidden_ips
					local logDrops
					local dropTarget=DROP
					config_get allowed_ips "$wifi_iface" allowed_ips
					config_get forbidden_ips "$wifi_iface" forbidden_ips
					config_get logDrops "$wifi_iface" logDrops
					[ "$logDrops" = 1 ] && dropTarget=logAndDrop
					echo "$lif with mac $lmac is censored wifi named $wifi_iface$(
							if [ -n "$forbidden_ips" ]; then
								echo -n " and has these ips forbidden: $forbidden_ips"
								if [ -n "$allowed_ips" ]; then
									echo " except $allowed_ips"
								else
									echo
								fi
							fi)"
					restrict_censored_interface "$lif" $router_ip $lan_netmask $is_router \
						"$allowed_ips" "$forbidden_ips" $dropTarget
				fi
			done
		done
	fi
	
	config_load "network"
	config_foreach check_guest_or_local_or_censored_network "interface" $router_ip \
		$lan_netmask $is_router
		
	#clean duplicate rules
	clean_duplicate_ebtables_rules filter INPUT
	clean_duplicate_ebtables_rules filter FORWARD
	clean_duplicate_ebtables_rules filter OUTPUT
}

clean_duplicate_ebtables_rules() {
	local table="$1"
	local chain="$2"
	local duplicate_rules=$(ebtables -t $table -L $chain | sort | uniq -c \
		| sed '/^ *1 /d;s/^ *[0-9]* //')
	local oldIFS=$IFS
	IFS=$'\n'
	local duplicate_rule_ids_to_delete=$(
		for duplicate_rule in $duplicate_rules ; do
			ebtables -t $table -L $chain --Ln | grep -e "$duplicate_rule" \
				| tail -n +2 | sed -E 's/^( *[0-9]*)\..*/\1/'
		done | sort -r)
	IFS="$oldIFS"
	for duplicate_rule_id_to_delete in $duplicate_rule_ids_to_delete ; do
		ebtables -t $table -D $chain \
			$duplicate_rule_id_to_delete:$duplicate_rule_id_to_delete
	done
}

decompose_ip_and_port() {
	local ip_and_port="$(echo $1 | sed -E 's/^[ \t]*([^ \t]*)[ \t]$/\1/')"
	local ip_type_var=$2
	local ip_var=$3
	local mask_var=$4
	local port_var=$5
	local ip4pattern="[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
	local ip6pattern="(:|([0-9A-Fa-f]{1,4}:)*)([0-9A-Fa-f]{1,4})?(:|(:[0-9A-Fa-f]{1,4})*)"
	local portPattern="[0-9]{1,5}(-[0-9]{1,5})?"
	if [ $(echo $ip_and_port | grep -E "^$ip4pattern(/[0-9]{1,2}|/$ip4pattern)?(:$portPattern)?$" | wc -l) -eq 1 ]; then
		eval "$ip_type_var=IPV4"
		eval "$ip_var=$(echo $ip_and_port | sed 's|/.*$||;s/:.*$//')"
		eval "$mask_var=$(echo $ip_and_port | sed '/^[^/]*$/d;s|^.*/||;s/:.*$//')"
		eval "$port_var=$(echo $ip_and_port | sed '/^[^:]*$/d;s/^.*://;s/-/:/')"
	elif [ $(echo $ip_and_port | grep -E "^$ip6pattern(/[0-9]{1,3}|/$ip6pattern)?(\.$portPattern)?$" | wc -l) -eq 1 ]; then
		eval "$ip_type_var=IPV6"
		eval "$ip_var=$(echo $ip_and_port | sed 's|/.*$||;s/\..*$//')"
		eval "$mask_var=$(echo $ip_and_port | sed '/^[^/]*$/d;s|^.*/||;s/\..*$//')" 
		eval "$port_var=$(echo $ip_and_port | sed '/^[^.]*$/d;s/^.*\.//;s/-/:/')"
	elif [ $(echo $ip_and_port | grep -E "^\[$ip6pattern(/[0-9]{1,3}|/$ip6pattern)?\](:$portPattern)?$" | wc -l) -eq 1 ]; then
		eval "$ip_type_var=IPV6"
		eval "$ip_var=$(echo $ip_and_port | sed -E 's|^\[([^/]*)(/.*)?\].*$|\1|')"
		eval "$mask_var=$(echo $ip_and_port | sed '/^[^/]*$/d;s|^\[.*/||;s/\].*$//')"
		eval "$port_var=$(echo $ip_and_port | sed '/^\[.*\]$/d;s/^\[.*\]://;s/-/:/')"
	else
		return 1
	fi
	return 0
}

lookup_host_addresses() {
	nslookup "$1" | sed -E '/^Address +[0-9]+:/!d;s/^Address +[0-9]+: +//'
}

decompose_host_address_and_call_proc() {
	local address="$1"
	shift
	local proc="$1"
	shift
	local rc=0
	if [ $(echo $address | grep -E "^/.*\.sh$" | wc -l) -eq 1 ]; then
		echo "Executing $address..."
		sh $address "$@"
		return 0
	elif [ $(echo $address | grep -E "^/" | wc -l) -eq 1 ]; then
	if [ $(echo $address | grep -E "^/" | wc -l) -eq 1 ]; then
		for host in $(cat $address | grep -E "^ *(0\.0\.0\.0 |:: )? *[^ ]+ *$" \
				| sed -E 's/^ *(0\.0\.0\.0 |:: )? *([^ ]+) *$/\2/' | sort | uniq); do
			decompose_host_address_and_call_proc "$host" $proc "$@" || rc=$?
		done
		return $rc
	elif [ $(echo $address \
			| grep -E "^([^ .:;/]*\.)*[^ .:;/]*(:[0-9]+)?$" | wc -l) -eq 1 ]; then
		local host=$(echo $address | sed 's/:.*$//')
		local port=$(echo $address | sed '/^[^:]*$/d;s/^.*://')
		for ip in $(lookup_host_addresses "$host"); do
			eval "$proc $ip $@" || rc=$?
		done
		return $rc
	else
		echo "Invalid host address: $address"
		return 0
	fi
}

allow_ip_for_interface() {
	local allowed_ip_and_port="$1"
	local lif="$2"
	local router_ip="$3"
	local lan_netmask="$4"
	local allowed_ip_type
	local allowed_ip
	local allowed_mask
	local allowed_port
	if ! decompose_ip_and_port "$allowed_ip_and_port" allowed_ip_type allowed_ip \
			allowed_mask allowed_port; then
		decompose_host_address_and_call_proc "$allowed_ip_and_port" allow_ip_for_interface \
            $lif $router_ip $lan_netmask
		return $?
	fi
#	echo "$lif: allow ip $allowed_ip_and_port: $allowed_ip_type , $allowed_ip , $allowed_mask , $allowed_port"
	if [ -n "$allowed_mask" ]; then
		allowed_ip=$allowed_ip/$allowed_mask
	fi
	local needs_routing="0"
	local ipp
	if [ "$allowed_ip_type" = "IPV4" ]; then
		if ip_in_subnet "$allowed_ip" "$router_ip" "$lan_netmask"; then
			ebtables -t filter -A INPUT -i "$lif" -p ARP \
				--arp-ip-dst "$allowed_ip" -j ACCEPT
			ebtables -t filter -A OUTPUT -o "$lif" -p ARP \
				--arp-ip-src "$allowed_ip" -j ACCEPT
			ebtables -t filter -A FORWARD -i "$lif" -p ARP \
				--arp-ip-dst "$allowed_ip" -j ACCEPT
			ebtables -t filter -A FORWARD -o "$lif" -p ARP \
				--arp-ip-src "$allowed_ip" -j ACCEPT
		else
			needs_routing="1"
		fi
		ipp="ip"
	elif [ "$allowed_ip_type" = "IPV6" ]; then
		ipp="ip6"
	fi
	if [ -n "$allowed_port" ]; then
		ebtables -t filter -A INPUT -i "$lif" -p $allowed_ip_type \
			--$ipp-dst "$allowed_ip" --$ipp-proto tcp --$ipp-dport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p $allowed_ip_type \
			--$ipp-src "$allowed_ip" --$ipp-proto tcp --$ipp-sport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p $allowed_ip_type \
			--$ipp-dst "$allowed_ip" --$ipp-proto tcp --$ipp-dport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p $allowed_ip_type \
			--$ipp-src "$allowed_ip" --$ipp-proto tcp --$ipp-sport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p $allowed_ip_type \
			--$ipp-dst "$allowed_ip" --$ipp-proto udp --$ipp-dport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p $allowed_ip_type \
			--$ipp-src "$allowed_ip" --$ipp-proto udp --$ipp-sport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p $allowed_ip_type \
			--$ipp-dst "$allowed_ip" --$ipp-proto udp --$ipp-dport "$allowed_port" \
			-j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p $allowed_ip_type \
			--$ipp-src "$allowed_ip" --$ipp-proto udp --$ipp-sport "$allowed_port" \
			-j ACCEPT
	else
		ebtables -t filter -A INPUT -i "$lif" -p $allowed_ip_type \
			--$ipp-dst "$allowed_ip" -j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p $allowed_ip_type \
			--$ipp-src "$allowed_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p $allowed_ip_type \
			--$ipp-dst "$allowed_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p $allowed_ip_type \
			--$ipp-src "$allowed_ip" -j ACCEPT
	fi
	[ "$needs_routing" = "1" ] && return 1	
}

forbid_ip_for_interface() {
	local forbidden_ip_and_port="$1"
	local lif="$2"
	local router_ip="$3"
	local lan_netmask="$4"
	local dropTarget="$5"
	[ -z $dropTarget ] && dropTarget=DROP
	local forbidden_ip_type
	local forbidden_ip
	local forbidden_mask
	local forbidden_port
	local ipp=""
	if ! decompose_ip_and_port "$forbidden_ip_and_port" forbidden_ip_type \
			forbidden_ip forbidden_mask forbidden_port; then
		decompose_host_address_and_call_proc "$forbidden_ip_and_port" forbid_ip_for_interface \
			$lif $router_ip $lan_netmask $dropTarget			
		return $?
	fi
	if [ -n "$forbidden_mask" ]; then
		forbidden_ip=$forbidden_ip/$forbidden_mask
	fi
	if [ "$forbidden_ip_type" = "IPV4" ]; then
		if ip_in_subnet "$forbidden_ip" "$router_ip" "$lan_netmask"; then
			ebtables -t filter -A INPUT -i "$lif" -p ARP \
				--arp-ip-dst "$forbidden_ip" -j $dropTarget
			ebtables -t filter -A OUTPUT -o "$lif" -p ARP \
				--arp-ip-src "$forbidden_ip" -j $dropTarget
			ebtables -t filter -A FORWARD -i "$lif" -p ARP \
				--arp-ip-dst "$forbidden_ip" -j $dropTarget
			ebtables -t filter -A FORWARD -o "$lif" -p ARP \
				--arp-ip-src "$forbidden_ip" -j $dropTarget
		fi
		ipp="ip"
	elif [ "$forbidden_ip_type" = "IPV6" ]; then
		ipp="ip6"
	fi
	if [ -n $ipp ]; then
		if [ -n "$forbidden_port" ]; then
			ebtables -t filter -A INPUT -i "$lif" -p $forbidden_ip_type \
				--$ipp-dst "$forbidden_ip" --$ipp-proto tcp \
				--$ipp-dport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A OUTPUT -o "$lif" -p $forbidden_ip_type \
				--$ipp-src "$forbidden_ip" --$ipp-proto tcp \
				--$ipp-sport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A FORWARD -i "$lif" -p $forbidden_ip_type \
				--$ipp-dst "$forbidden_ip" --$ipp-proto tcp \
				--$ipp-dport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A FORWARD -o "$lif" -p $forbidden_ip_type \
				--$ipp-src "$forbidden_ip" --$ipp-proto tcp \
				--$ipp-sport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A INPUT -i "$lif" -p $forbidden_ip_type \
				--$ipp-dst "$forbidden_ip" --$ipp-proto udp \
				--$ipp-dport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A OUTPUT -o "$lif" -p $forbidden_ip_type \
				--$ipp-src "$forbidden_ip" --$ipp-proto udp \
				--$ipp-sport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A FORWARD -i "$lif" -p $forbidden_ip_type \
				--$ipp-dst "$forbidden_ip" --$ipp-proto udp \
				--$ipp-dport "$forbidden_port" -j $dropTarget
			ebtables -t filter -A FORWARD -o "$lif" -p $forbidden_ip_type \
				--$ipp-src "$forbidden_ip" --$ipp-proto udp \
				--$ipp-sport "$forbidden_port" -j $dropTarget
		else
			ebtables -t filter -A INPUT -i "$lif" -p $forbidden_ip_type \
				--$ipp-dst "$forbidden_ip" -j $dropTarget
			ebtables -t filter -A OUTPUT -o "$lif" -p $forbidden_ip_type \
				--$ipp-src "$forbidden_ip" -j $dropTarget
			ebtables -t filter -A FORWARD -i "$lif" -p $forbidden_ip_type \
				--$ipp-dst "$forbidden_ip" -j $dropTarget
			ebtables -t filter -A FORWARD -o "$lif" -p $forbidden_ip_type \
				--$ipp-src "$forbidden_ip" -j $dropTarget
		fi
	fi
}

allow_server_for_interface() {
	local allowed_server="$1"
	local lif="$2"
	local router_ip="$3"
	local lan_netmask="$4"
	local allowed_server_ip_type
	local allowed_server_ip
	local allowed_server_mask
	local allowed_server_port
	local ipp
	if ! decompose_ip_and_port "$allowed_server" allowed_server_ip_type \
			allowed_server_ip allowed_server_mask allowed_server_port; then
		decompose_host_address_and_call_proc "$allowed_server" allow_server_for_interface \
			$lif $router_ip $lan_netmask
		return $?
	fi
	if [ -n "$allowed_server_mask" ]; then
		allowed_server_ip=$allowed_server_ip/$allowed_server_mask
	fi
	if [ "$allowed_server_ip_type" = "IPV4" ]; then
		ebtables -t filter -A INPUT -i "$lif" -p ARP \
			--arp-ip-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p ARP \
			--arp-ip-dst "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p ARP \
			--arp-ip-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p ARP \
			--arp-ip-dst "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p IPV4 \
			--ip-proto icmp --ip-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p IPV4 \
			--ip-proto icmp --ip-dst "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p IPV4 \
			--ip-proto icmp --ip-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p IPV4 \
			--ip-proto icmp --ip-dst "$allowed_server_ip" -j ACCEPT
		ipp="ip"
	elif [ "$allowed_server_ip_type" = "IPV6" ]; then
		ebtables -t filter -A FORWARD -o "$lif" -p IPV6 \
			--ip6-proto ipv6-icmp --ip6-dst "ff02::/ffff::" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p IPV6 \
			--ip6-proto ipv6-icmp --ip6-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p IPV6 \
			--ip6-proto ipv6-icmp --ip6-dst "$allowed_server_ip" -j ACCEPT
		ipp="ip6"
	fi
	if [ -n "$allowed_server_port" ]; then
		ebtables -t filter -A INPUT -i "$lif" -p $allowed_server_ip_type \
			--$ipp-src "$allowed_server_ip" --$ipp-proto tcp \
			--$ipp-sport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p $allowed_server_ip_type \
			--$ipp-dst "$allowed_server_ip" --$ipp-proto tcp \
			--$ipp-dport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p $allowed_server_ip_type \
			--$ipp-src "$allowed_server_ip" --$ipp-proto tcp \
			--$ipp-sport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p $allowed_server_ip_type \
			--$ipp-dst "$allowed_server_ip" --$ipp-proto tcp \
			--$ipp-dport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p $allowed_server_ip_type \
			--$ipp-src "$allowed_server_ip" --$ipp-proto udp \
			--$ipp-sport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p $allowed_server_ip_type \
			--$ipp-dst "$allowed_server_ip" --$ipp-proto udp \
			--$ipp-dport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p $allowed_server_ip_type \
			--$ipp-src "$allowed_server_ip" --$ipp-proto udp \
			--$ipp-sport "$allowed_server_port" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p $allowed_server_ip_type \
			--$ipp-dst "$allowed_server_ip" --$ipp-proto udp \
			--$ipp-dport "$allowed_server_port" -j ACCEPT
	else
		ebtables -t filter -A FORWARD -i "$lif" -p $allowed_server_ip_type \
			--$ipp-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p $allowed_server_ip_type \
			--$ipp-dst "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p $allowed_server_ip_type \
			--$ipp-src "$allowed_server_ip" -j ACCEPT
		ebtables -t filter -A OUTPUT -o "$lif" -p $allowed_server_ip_type \
			--$ipp-dst "$allowed_server_ip" -j ACCEPT
	fi
}


restrict_guest_interface() {
	local lif="$1"
	local router_ip="$2"
	local lan_netmask="$3"
	local is_router="$4"
	local allowed_ips="$5"
	local forbidden_ips="$6"
	local allowed_servers="$7"
	local dropTarget="$8"
	[ -z $dropTarget ] && dropTarget=DROP
	if [ -n "$allowed_ips" ]; then
		if [ -n "$forbidden_ips" ]; then
			for forbidden_ip in $forbidden_ips ; do
				forbid_ip_for_interface $forbidden_ip "$lif" $router_ip $lan_netmask $dropTarget
			done
		fi
		for allowed_ip in $allowed_ips ; do
			allow_ip_for_interface $allowed_ip "$lif" $router_ip $lan_netmask
		done
	fi
	if [ -n "$allowed_servers" ]; then
		for allowed_server in $allowed_servers ; do
			allow_server_for_interface $allowed_server "$lif" $router_ip $lan_netmask
		done
	fi
	if [ "$is_router" = "1" ]; then
		ebtables -t filter -A INPUT -i "$lif" -p ARP --arp-ip-dst "$router_ip" \
			-j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p IPV4 --ip-proto udp \
			--ip-dport 67 -j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p IPV4 \
			--ip-dst $router_ip --ip-proto udp --ip-dport 53 \
			-j ACCEPT
	else
		ebtables -t filter -A FORWARD -i "$lif" -p ARP --arp-ip-dst "$router_ip" \
			-j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p ARP --arp-ip-src "$router_ip" \
			-j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p IPV4 \
			--ip-dst $router_ip --ip-proto udp --ip-dport 53 \
			-j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p IPV4 \
			--ip-src $router_ip --ip-proto udp --ip-sport 53 \
			-j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p IPV4 --ip-proto udp \
			--ip-dport 67 -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p IPV4 --ip-proto udp \
			--ip-sport 67 -j ACCEPT
	fi
	ebtables -t filter -A INPUT -i "$lif" -p ARP \
		--arp-ip-dst "$router_ip/$lan_netmask" -j $dropTarget
	ebtables -t filter -A FORWARD -i "$lif" -p ARP \
		--arp-ip-dst "$router_ip/$lan_netmask" -j $dropTarget
	ebtables -t filter -A FORWARD -o "$lif" -p ARP \
		--arp-ip-src "$router_ip/$lan_netmask" -j $dropTarget
	ebtables -t filter -A INPUT -i "$lif" -p IPV4 \
		--ip-dst "$router_ip/$lan_netmask" -j $dropTarget
	ebtables -t filter -A FORWARD -i "$lif" -p IPV4 \
		--ip-dst "$router_ip/$lan_netmask" -j $dropTarget
	ebtables -t filter -A FORWARD -o "$lif" -p IPV4 \
		--ip-src "$router_ip/$lan_netmask" -j $dropTarget
	#no IPv6 in guest network unless we are router since we would have to check ip6 addresses otherwise
	if [ "$is_router" = "1" ]; then
		ebtables -t filter -A FORWARD -i "$lif" --logical-out pppoe-wan -p IPV6 \
			-j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" --logical-in pppoe-wan -p IPV6 \
			-j ACCEPT
		ebtables -t filter -A INPUT -i "$lif" -p IPV6 -j ACCEPT
	else
		ebtables -t filter -A INPUT -i "$lif" -p IPV6 -j $dropTarget
	fi
	ebtables -t filter -A FORWARD -i "$lif" -p IPV6 -j $dropTarget
	ebtables -t filter -A FORWARD -o "$lif" -p IPV6 -j $dropTarget
}

restrict_local_interface() {
	local lif="$1"
	local router_ip="$2"
	local lan_netmask="$3"
	local is_router="$4"
	local allowed_ips="$5"
	local forbidden_ips="$6"
	local allowed_servers="$7"
	local dropTarget="$8"
	[ -z $dropTarget ] && dropTarget=DROP
	if [ -n "$allowed_ips" ]; then
		local needs_routing="0"
		if [ -n "$forbidden_ips" ]; then
			for forbidden_ip in $forbidden_ips ; do
				forbid_ip_for_interface $forbidden_ip "$lif" $router_ip $lan_netmask $dropTarget
			done
		fi
		for allowed_ip in $allowed_ips ; do
			allow_ip_for_interface $allowed_ip "$lif" $router_ip $lan_netmask \
				|| needs_routing="1"
		done
		if [ "$needs_routing" = "1" ]; then
			echo "$lif needs routing because of non-local allowed ip, thus allowing arp to $router_ip"
			if [ "$is_router" != "0" ]; then
				ebtables -t filter -A INPUT -i "$lif" -p ARP --arp-ip-dst $router_ip \
					-j ACCEPT
			else
				ebtables -t filter -A FORWARD -i "$lif" -p ARP \
					--arp-ip-dst "$router_ip" -j ACCEPT
				ebtables -t filter -A FORWARD -o "$lif" -p ARP \
					--arp-ip-src "$router_ip" -j ACCEPT
			fi
		fi
	else
		ebtables -t filter -A INPUT -i "$lif" -p ARP \
			--arp-ip-dst "$router_ip/$lan_netmask" -j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p ARP \
			--arp-ip-dst "$router_ip/$lan_netmask" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p ARP \
			--arp-ip-src "$router_ip/$lan_netmask"-j ACCEPT
		ebtables -t filter -A FORWARD -i "$lif" -p IPV4 \
			--ip-dst "$router_ip/$lan_netmask" -j ACCEPT
		ebtables -t filter -A FORWARD -o "$lif" -p IPV4 \
			--ip-src "$router_ip/$lan_netmask" -j ACCEPT 
	fi
	if [ -n "$allowed_servers" ]; then
		for allowed_server in $allowed_servers ; do
			allow_server_for_interface $allowed_server "$lif" $router_ip $lan_netmask
		done
	fi
	#Allow broadcast and directed arp
	#ebtables -t filter -A INPUT -i "$lif" -p ARP -j ACCEPT
	#ebtables -t filter -A FORWARD -i "$lif" -p ARP -j ACCEPT
	#Allow DHCP broadcast and directed
	ebtables -t filter -A INPUT -i "$lif" -p IPV4 --ip-proto udp \
		--ip-dport 67 -j ACCEPT
	ebtables -t filter -A FORWARD -i "$lif" -p IPV4 --ip-proto udp \
		--ip-dport 67 -j ACCEPT
	ebtables -t filter -A FORWARD -o "$lif" -p IPV4 --ip-proto udp \
		--ip-sport 67 -j ACCEPT
	#Allow EAPOL for wifi authentication
	ebtables -A INPUT -i "$lif" -p 0x888e -j ACCEPT
	#Drop anything else
	ebtables -t filter -A FORWARD -i "$lif" -j $dropTarget
	ebtables -t filter -A FORWARD -o "$lif" -j $dropTarget
	ebtables -t filter -A INPUT -i "$lif" -j $dropTarget
}

restrict_censored_interface() {
	local lif="$1"
	local router_ip="$2"
	local lan_netmask="$3"
	local is_router="$4"
	local allowed_ips="$5"
	local forbidden_ips="$6"
	local dropTarget="$7"
	[ -z $dropTarget ] && dropTarget=DROP
	if [ -n "$forbidden_ips" ]; then
		if [ -n "$allowed_ips" ]; then
			for allowed_ip in $allowed_ips ; do
				allow_ip_for_interface $allowed_ip "$lif" $router_ip $lan_netmask
			done
		fi
		for forbidden_ip in $forbidden_ips ; do
			forbid_ip_for_interface $forbidden_ip "$lif" $router_ip $lan_netmask $dropTarget
		done
	fi
}

check_guest_or_local_or_censored_network() { # network, not wifi!
	local iface="$1"
	local router_ip="$2"
	local lan_netmask="$3"
	local is_router="$4"
	local ifname
	local is_guest_network
	local is_local_network
	local is_local_network
	local is_censored_network
	local allowed_ips
	local forbidden_ips
	local allowed_servers
	local logDrops
	local dropTarget=DROP
	config_get ifname "$iface" ifname
	config_get is_guest_network "$iface" is_guest_network
	config_get is_local_network "$iface" is_local_network
	config_get is_censored_network "$iface" is_censored_network
	config_get allowed_ips "$iface" allowed_ips
	config_get forbidden_ips "$iface" forbidden_ips
	config_get allowed_servers "$iface" allowed_servers
	config_get logDrops "$iface" logDrops
	[ "$logDrops" = 1 ] && dropTarget=logAndDrop
	if [ "$is_guest_network" = "1" ]; then
		echo "$ifname is guest network named $iface$(
			if [ -n "$allowed_ips" ]; then
				echo -n " but has these local ips allowed: $allowed_ips"
				if [ -n "$forbidden_ips" ]; then
					echo " except $forbidden_ips"
				else
					echo
				fi
			fi)"
		if [ -n "$allowed_servers" ]; then
			echo "$ifname is allowed to host these servers: $allowed_servers"
		fi
		restrict_guest_interface "$ifname" $router_ip $lan_netmask $is_router \
			"$allowed_ips" "$forbidden_ips" "$allowed_servers" $dropTarget
	fi		
	if [ "$is_local_network" = "1" ]; then
		echo "$ifname is local network named $iface$(
			if [ -n "$allowed_ips" ]; then
				echo -n " with these ips allowed: $allowed_ips"
				if [ -n "$forbidden_ips" ]; then
					echo " except $forbidden_ips"
				else
					echo
				fi
			fi)"
		if [ -n "$allowed_servers" ]; then
			echo "$ifname is allowed to host these servers: $allowed_servers"
		fi
		restrict_local_interface "$ifname" $router_ip $lan_netmask $is_router \
			"$allowed_ips" "$forbidden_ips" "$allowed_servers" $dropTarget
	fi
	if [ "$is_censored_network" = "1" ]; then
		echo "$ifname is censored network named $iface$(
			if [ -n "$forbidden_ips" ]; then
				echo -n " with these ips forbidden: $forbidden_ips"
				if [ -n "$allowed_ips" ]; then
					echo " except $allowed_ips"
				else
					echo
				fi
			fi)"
		restrict_censored_interface "$ifname" $router_ip $lan_netmask $is_router \
			"$allowed_ips" "$forbidden_ips" $dropTarget
	fi
}

ifup_firewall()
{
	insert_restriction_rules
	initialize_quotas
	insert_pf_loopback_rules
}
