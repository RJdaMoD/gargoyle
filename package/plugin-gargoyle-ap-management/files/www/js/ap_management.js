/*
 * This program is copyright © 2021 Roger John and is distributed under the terms of
 *  the GNU GPL
 * version 2.0 with a special clarification/exception that permits adapting the program to
 * configure proprietary "back end" software provided that all modifications to the web interface
 * itself remain covered by the GPL.
 * See http://gargoyle-router.com/faq.html#qfoss for more information
 */
var apmS   = {}; //part of i18n
var basicS = {}; //part of i18n

var pkg = 'ap_management';
var sec = 'config';
var channelBandMap = {'11b': '2.4GHz (b)', '11g': '2.4GHz', '11a': '5GHz'};
var channelBandIndex = {'11b': 1, '11g': 1, '11a': 2};
var allowedChannelBandsForIndex = {1: ['11b', '11g'], 2: ['11a']};
var channelBandReverseMap = {};
Object.keys(channelBandMap).forEach(k => { channelBandReverseMap[channelBandMap[k]] = k; });
var htModeMap = {};
['NOHT', 'HT20', 'HT40', 'HT40-', 'HT40+', 'VHT20', 'VHT40', 'VHT80', 'VHT160'].forEach(x => { htModeMap[x] = x; } );
var encryptionMap;
var encryptionCiphers = {'ccmp': 'CCMP', 'tkip': 'TKIP', 'tkip+ccmp': 'CCMP & TKIP', 'gcmp': 'GCMP'};

var managedAPs = [];

function keyFunctionToCompareFunction(k) { return (x, y) => k(x) === k(y) ? 0 : k(x) < k(y) ? -1 : 1; }

function diffArrays(a, b, keyOrCmp, left, equal, right)
{
	left = left || (() => {});
	equal = equal || (() => {});
	right = right || (() => {});
	keyOrCmp = keyOrCmp || (x => x);
	var cmp  = keyOrCmp.length > 1 ? keyOrCmp : keyFunctionToCompareFunction(keyOrCmp);
	a.sort(cmp);
	b.sort(cmp);
	var i = 0, j = 0;
	while(i < a.length && j < b.length)
	{
		var c = cmp(a[i], b[j]);
		if(c < 0) { left(a[i++]); }
		else if(c > 0) { right(b[j++]); }
		else { equal(a[i++], b[j++]); }
	}
	while(i < a.length) { left(a[i++]); }
	while(j < b.length) { right(b[j++]); }
}

function union(...arrays)
{
	var r = [];
	arrays.forEach(a => { a.forEach(x => { if(!r.find(y => y === x)) { r.push(x); }})});
	r.sort();
	return r;
}

function flatten(a, d= 1)
{
	while(d-- > 0) { a = Array.prototype.concat.apply([], a); }
	return a;
}

function pushTo(a) { return x => { a.push(x); }; }

function leftComplementIntersectionRightComplement(a, b, keyOrCmp)
{
	var l = [], i = [], r = [];
	keyOrCmp = keyOrCmp || (x => x);
	diffArrays(a, b, keyOrCmp, pushTo(l), pushTo(i), pushTo(r));
	return [l, i, r];
}

function intersection(a, b, keyCmp) { return leftComplementIntersectionRightComplement(a, b, keyCmp)[1]; }

function complement(a, b, keyOrCmp) { return leftComplementIntersectionRightComplement(a, b, keyOrCmp)[0]; }

function randomHexString(length)
{
	return [...Array(length).keys()].map(() => Math.floor(16 * Math.random()))
		.map(x => x > 9 ? String.fromCharCode(x - 10 + 'A'.charCodeAt(0)) : x + '').join('');
}

function saveChanges()
{
	var mainCommands = [];
	var packageAndSection = 'ap_management_gargoyle.ap_management';
	function addManagedAP(ap)
	{
		if(ap.name !== currentHostName)
		{
			mainCommands.push('uci -q add_list ' + packageAndSection + '.managed_aps=' + ap.name);
		}
	}
	function deleteManagedAP(ap)
	{
		if(ap.name !== currentHostName)
		{
			mainCommands.push('uci -q del_list ' + packageAndSection + '.managed_aps=' + ap.name);
			mainCommands.push('rm -f /tmp/wifiConfig.' + ap.name);
			mainCommands.push('rm -f /tmp/wifiStatus.' + ap.name);
		}
	}

	diffArrays(managedAPs, originalManagedAPs, ap => ap.name, addManagedAP, undefined, deleteManagedAP);

	if(mainCommands.length > 0) { mainCommands.push('uci -q commit'); }

	var uciKeyValue = function(key, value) { return key + "='" + value.replaceAll("'", "'\"'\"'") + "'"; }
	var diffUciOption = function(c1, c2, pkg, section, option)
	{
		var oldValue = c1.get(pkg, section, option);
		var newValue = c2.get(pkg, section, option);
		var key = pkg + "." + section + "." + option;
		if(oldValue === newValue) { return []; }
		else if(newValue && isArray(newValue))
		{
			var cmds = [];
			if(oldValue && isArray(oldValue))
			{
				diffArrays(newValue, oldValue, x => x, v => cmds.push('uci -q add_list ' + uciKeyValue(key, v)),
					undefined, v => cmds.push('uci -q del_list ' + uciKeyValue(key, v)));
			}
			else
			{
				cmds.push('uci -q delete ' + key);
				cmds.push(...newValue.map(v => 'uci -q add_list ' + uciKeyValue(key, v)));
			}
			return cmds;
		}
		else if(newValue) {	return ['uci -q set ' + uciKeyValue(key, newValue)]; }
		else if(oldValue) {	return ['uci -q delete ' + key]; }
		else { return []; }
	};
	var diffUciSection = function(c1, c2, pkg, section)
	{
		var oldType = c1.get(pkg, section, '');
		var newType = c2.get(pkg, section, '');
		var key = pkg + '.' + section;
		var cmds = [];
		if(newType && oldType !== newType) {	cmds.push('uci -q set ' + uciKeyValue(key, newType)); }
		diffArrays(c1.getAllOptionsInSection(pkg, section + '\\.', true),
			c2.getAllOptionsInSection(pkg, section + '\\.', true), opt => opt,
			opt => { cmds.push('uci -q delete ' + key + '.' + opt); },
			(opt1, opt2) => { cmds.push(...diffUciOption(c1, c2, pkg, section, opt1)); },
			opt => {
				var value = c2.get(pkg, section, opt);
				if(isArray(value)) { cmds.push(...value.map(v => 'uci -q add_list ' + uciKeyValue(key + '.'+opt, v))); }
				else { cmds.push('uci -q set ' + uciKeyValue(key + '.'+opt, value)); }
			});
		if(oldType && !newType) { cmds.push('uci -q delete ' + key); }
		return cmds;
	};
	var diffUciSections = function(c1, c2, pkg, sections)
	{
		return sections.map(section => diffUciSection(c1, c2, pkg, section)).reduce((x,y) => x.concat(y), []);
	};
	var diffUciPackage = function(c1, c2, pkg)
	{
		return diffUciSections(c1, c2, pkg, union(c1.getAllSections(pkg), c2.getAllSections(pkg)));
	};
	var apCommands = [];
	managedAPs.forEach(ap => {
		var origAp = originalManagedAPs.find(origAp => origAp.name === ap.name);
		if(origAp)
		{
			var cmds = diffUciPackage(origAp.config, ap.config, 'wireless')
			if(cmds.length > 0)
			{
				cmds.push('uci commit', 'wifi');
				apCommands.push("source /usr/lib/ap_management/runCommandOnAccessPoints.sh '"
					+ cmds.join('\n').replaceAll("'","'\"'\"'") + "' "
					+ "'' " + ap.name);
			}
		}
	});
	if(apCommands.length > 0) {	mainCommands = mainCommands.concat(apCommands, ["wait"]); }
	if(mainCommands.length > 0)
	{
		mainCommands.push("/usr/lib/ap_management/define_ap_wifi_config.sh originalManagedAPs");
		mainCommands.push("/usr/lib/ap_management/define_ap_wifi_capabilities.sh originalManagedAPs");
		var callback = function(response)
		{
			if(successfulResponse(response))
			{
				originalManagedAPs = [];
				eval(stripSuccessFromResponse(response));
				resetData();
			}
		}
		//runCommandsWithCallback(mainCommands, callback);
		alert(mainCommands);
	}
	else { disableSaveButton(); }
}

function cloneAP(ap)
{
	var clonedAP = {};
	Object.keys(ap).forEach(key => {
		if(['number', 'string'].find(t => t === typeof ap[key])) {clonedAP[key] = ap[key]; }
	});
	clonedAP.config = ap.config.clone();
	clonedAP.radios = ap.radios.map(radio => clonePlainFlatObject(radio));
	clonedAP.bridges = ap.bridges.slice();
	clonedAP.wifiInfo = ap.wifiInfo;
	return clonedAP;
}

function resetData()
{
	disableSaveButton();
	managedAPs = originalManagedAPs.map(cloneAP);
	buildTables();
}

function buildTables()
{
	buildAccessPointTable();
	buildRadioTable();
	buildSSIDtable();
}

function buildAccessPointTable() {
	var apTable = managedAPs.map(ap => [ap.name, ap.ip,
		"" + ap.config.getAllSectionsOfType("wireless","wifi-device").length,
		"" + ap.config.getAllSectionsOfType("wireless","wifi-iface").length]);
	apTable = createTable([apmS.ap, 'IP', apmS.numRadios, apmS.numSSIDs], apTable, "access_points_table", true, false, removeAPfromTable);
	var apTableRows = apTable.getElementsByTagName('tr'); // remove "Remove"-button for router
	for(var i=0; i<apTableRows.length; i++)
	{
		var cells = apTableRows[i].getElementsByTagName('td');
		if(cells.length > 0 && cells[0].innerText === currentHostName)
		{
			cells[cells.length - 1].innerHTML = "<span/>";
			break;
		}
	}
	var tableContainer = document.getElementById('access_points_table_container');
	if(tableContainer.firstChild != null) {	tableContainer.removeChild(tableContainer.firstChild); }
	tableContainer.appendChild(apTable);
	TSort_Data = ['access_points_table', 's', 'p', 'i', 'i'];
	tsRegister();
	tsSetTable('access_points_table');
	tsInit();
	checkAccessPointToBeAdded();
}

function buildRadioTable() {
	var radioTable = flatten(
		managedAPs.map(ap => ap.config.getAllSectionsOfType("wireless","wifi-device")
			.map(radio => {
				var opts = ["hwmode", "channel", "hwmode", "htmode", "txpower", "country"]
					.map(opt => ap.config.get("wireless", radio, opt));
				opts[0] = channelBandMap[opts[0]];
				var chan = ap.radios.find(x => x.radio === radio).bands.find(x => x.band === channelBandIndex[opts[2]])
					.channels.find(x => x.channel == opts[1]);
				opts[2] = chan ? chan.frequency/1e6 + "" : "?";
				return [ap.hostName, radio].concat(opts).concat(
					originalManagedAPs.find(origAp => origAp.name === ap.name) ?
						createEditButton(editRadioModal) : "");
			})));
	radioTable = createTable(
		["AP", apmS.radio, apmS.channelBand, apmS.channel, apmS.frequency + " (MHz)", apmS.channelMode,
			apmS.txPower + " (dBm)", apmS.country],
		radioTable, "radio_table", false, false);
	var tableContainer = document.getElementById('radio_table_container');
	if(tableContainer.firstChild != null) { tableContainer.removeChild(tableContainer.firstChild); }
	tableContainer.appendChild(radioTable);
	TSort_Data = ['radio_table', 's', 's', 's', 'i', 'i', 's', 'i', 's'];
	tsRegister();
	tsSetTable('radio_table');
	tsInit();
}

function getWifiSecurityRelevantUciOptionsFor(x)
{
	if(typeof(x) === "string")
	{
		if (x.match(/^psk|^sae/)) {	return ['encryption', 'key'];	}
		else if (x.match(/^wep/)) {	return ['encryption', 'key', 'key1', 'key2', 'key3', 'key4']; }
		else if (serviceSet.security.type.match(/^wpa/)) { return ['encryption', 'server', 'port', 'key']; }
		else { return ['encryption']; }
	}
	else if(typeof(x) === "object")
	{
		return clonePlainFlatObject(x, getWifiSecurityRelevantUciOptionsFor(x.encryption));
	}
}

function clonePlainFlatObject(obj, keys, defaults)
{
	if(obj === undefined) { return obj; }
	keys = keys || Object.keys(obj);
	var r = {};
	if(!defaults) { defaults = {}; }
	keys.forEach(key => { r[key] = obj[key] || defaults[key]; });
	return r;
}

function enrichWithDefaults(obj, defaults)
{
	Object.keys(defaults).forEach(k => { if(!obj[k]) { obj[k] = defaults[k]; } })
	return obj;
}

function enrichWithUciDefaultsForWifiIface(obj)
{
	return enrichWithDefaults(obj, uciDefaults.wireless['wifi-iface']);
}

function getCommonVlansOfServiceSets(serviceSets)
{
	return serviceSets.map(serviceSet => serviceSet.vlan).reduce((y,z) => intersection(y, z)).sort();
}

function getCommonVlanOfServiceSets(serviceSets)
{
	return getCommonVlansOfServiceSets(serviceSets)[0];
}

function gatherServiceSets(aps) {
	var gatheredServiceSets = [];
	aps.forEach(ap => {
		ap.config.getAllSectionsOfType("wireless", "wifi-iface")
			.filter(iface => ap.config.get("wireless", iface, "mode") === 'ap')
			.forEach(iface => {
				var serviceSet = {'ap': ap.hostName, 'iface': iface};
				ap.config.getAllOptionsInSection('wireless', iface + '\\.', true)
					.forEach(opt => serviceSet[opt] = ap.config.get('wireless', iface, opt));
				var network = serviceSet.network || uciDefaults.wireless['wifi-iface'].network;
				serviceSet.vlan = ap.config.get('network', network) === 'interface' ?
					ap.config.get('network', network, 'ifname').split(' ').map(dev => dev.split('.')[1] || '0') : [];
				var existingServiceSet = gatheredServiceSets.find(
					x => [x[0], serviceSet]
						.map(y => clonePlainFlatObject(y,
							['ssid', 'disabled', 'hidden', 'isolate', 'ieee80211r']
								.concat(getWifiSecurityRelevantUciOptionsFor(y.encryption)),
							uciDefaults.wireless['wifi-iface']))
						.map(JSON.stringify).reduce((y,z) => y === z)
						&& intersection(getCommonVlansOfServiceSets(x), serviceSet.vlan).length > 0
				);
				if (existingServiceSet) {
					existingServiceSet.push(serviceSet);
				} else {
					gatheredServiceSets.push([serviceSet]);
				}
			});
	});
	return gatheredServiceSets;
}

function getWifiEncryptionMap()
{
	if(!encryptionMap)
	{
		encryptionMap = {
			'none': basicS.None, 'sae-mixed': 'WPA3/WPA2 SAE/PSK', 'sae': 'WPA3 SAE', 'psk2': 'WPA2 PSK',
			'psk': 'WPA PSK', 'wep': 'WEP', 'owe': 'OWE', 'wpa': 'WPA RADIUS', 'wpa2': 'WPA2 RADIUS',
			'wpa-mixed': 'WPA/WPA2 RADIUS', 'wpa3': 'WPA3 RADIUS', 'wpa3-mixed': 'WPA3/WPA2 RADIUS'
		};
	}
	return encryptionMap;
}

function getWifiEncryptionName(enc)
{
	var encryptionMap = getWifiEncryptionMap();
	var x = enc.split('+');
	var r = encryptionMap[x[0]];
	if(r)
	{
		var cipher = x.slice(1).join('+').replace(/aes/,'ccmp');
		cipher = encryptionCiphers[cipher] || cipher;
		return cipher ? r + ' (' + cipher + ')' : r;
	}
	else { return enc; }
}

function buildSSIDtable()
{
	var gatheredServiceSets = gatherServiceSets(managedAPs);
	var ssidTable = gatheredServiceSets.map(x =>
		[x[0].ssid, getWifiEncryptionName(x[0].encryption),
			getApWithRadioListFromServiceSets(x).sort().join(', '),
			getCommonVlanOfServiceSets(x),
			createCheckbox(x[0].disabled !== '1',
					o => changeValueOfBooleanSSIDproperty(x, 'disabled', !o.target.checked)),
			createCheckbox(x[0].hidden === '1',
					o => changeValueOfBooleanSSIDproperty(x, 'hidden', o.target.checked)),
			createCheckbox(x[0].isolate === '1',
					o => changeValueOfBooleanSSIDproperty(x, 'isolate', o.target.checked)),
			createCheckbox(x[0].ieee80211r === '1' && x[0].encryption.match(/^(psk|sae|wpa)/),
					o => changeValueOfBooleanSSIDproperty(x, 'ieee80211r', o.target.checked),
					x[0].encryption.match(/^(psk|sae|wpa)/)),
			createEditButton(editSSIDmodal)]);
	ssidTable = createTable(
		[apmS.SSID, apmS.security, apmS.aps, 'VLAN', apmS.enabled, apmS.hidden, apmS.isolate,
			apmS.fastRoaming],
		ssidTable, "ssid_table", true, false, removeSSIDfromTable);
	var tableContainer = document.getElementById('ssid_table_container');
	if(tableContainer.firstChild != null) { tableContainer.removeChild(tableContainer.firstChild); }
	tableContainer.appendChild(ssidTable);
	TSort_Data = ['ssid_table', 's', 's', 's', 'i'];
	tsRegister();
	tsSetTable('ssid_table');
	tsInit();
}

function addAccessPoint()
{
	var ap = { "name" : document.getElementById("add_ap_name").value };
	// TODO: prevent addition of existent aps
	ap.hostName = ap.name.replace(/^.*@/, ""); // extract host name from constructs like user@host
	var callback = function(response)
	{
		if(successfulResponse(response))
		{
			var ip = stripSuccessFromResponse(response);
			if(ip.match(/[0-9]{1,3}(\.[0-9]{1,3}){3}/))
			{
				ap.ip = ip;
				addAccessPointAfterIPlookup(ap);
			}
			else { addAccessPointButFirstAddIpAddress(ap); }
		}
		else { alert("Error resolving "+ap.hostName+" to an address: "+response); }
	}
	return runCommandsWithCallback("nslookup " + ap.hostName + " | awk '/Address 1:/ { print $3 }'", callback);
}

function addAccessPointButFirstAddIpAddress(ap) {
	var callback = function()
	{
		var ipContainer = document.getElementById("access_point_ip_address");
		if(ipContainer.validity.patternMismatch) { alert(replaceAP(apmS.invalidIpAddress, ap)); }
		else
		{
			ap.ip = ipContainer.value;
			closeModalWindow("access_point_supply_ip_address_modal");
			var callback = function (response) {
				if (successfulResponse(response)) {
					var ip = stripSuccessFromResponse(response);
					if (ip === ap.ip)
					{
						alert("Successfully saved ip address " + ap.ip + " for " + ap.hostName + ".");
						addAccessPointAfterIPlookup(ap);
					}
					else { alert("Setting the ip address " + ap.ip + " for " + ap.hostName + " did not work: " + ip); }
				}
			}
			return runCommandsWithCallback([
					"uci -q add_list dhcp.@dnsmasq[0].address=/" + ap.hostName + "/" + ap.ip,
					"uci commit",
					"/etc/init.d/dnsmasq restart",
					"nslookup " + ap.hostName + " | awk '/Address 1:/ { print $3 }'"],
				callback);
		}
	}
	var modalElements = [
		{ "id" : "access_point_supply_ip_address_modal_title",
			"innertext": replaceAP(apmS.supplyIpAddress, ap) },
		{ "id" : "access_point_supply_ip_address_header_text",
			"innertext" : replaceAP(apmS.supplyIpAddressOfAccessPoint, ap) },
		{ "id" : "access_point_pass" }
	];
	var modalButtons = [
		{"title" : apmS.save, "classes" : "btn btn-primary", "function" : callback},
		"defaultDismiss"
	];
	modalPrepare('access_point_supply_ip_address_modal', replaceAP(apmS.supplyIpAddress, ap),
		modalElements, modalButtons);
	openModalWindow('access_point_supply_ip_address_modal');
}

function addAccessPointAfterIPlookup(ap)
{
	// test ssh connectivity
	var callback = function(response)
	{
		if(successfulResponse(response))
		{
			var sshResult = stripSuccessFromResponse(response);
			if(sshResult === "1") { addAccessPointAfterConnectivityTest(ap);	}
			else if(sshResult.match(/host key.*failed/i)) {	addAccessPointButFirstCheckAndAddHostKey(ap); }
			else if(sshResult.match(/permission denied/i)) { addAccessPointButFirstAddSshKey(ap); }
			else { alert("Ssh-ing "+ap.name+" gave unknown result: "+sshResult); }
		}
		else { alert("Error resolving "+ap.hostName+" to an address: "+response); }
	}
	return runCommandsWithCallback("openssh-ssh -o BatchMode=yes "+ap.name+" echo 1 2>&1", callback);
}

function addAccessPointButFirstCheckAndAddHostKey(ap)
{
	var confirmationCallback = function() { addAccessPointButFirstAddHostKey(ap); }
	var callback = function(response)
	{
		if(successfulResponse(response))
		{
			var hostKeys = stripSuccessFromResponse(response);
			var modalElements = [
				{ "id" : "access_point_confirm_host_key_modal_title",
					"innertext" : replaceAP(apmS.confirmAPhostKey, ap) },
				{ "id" : "access_point_confim_host_key_header_text",
					"innertext" : replaceAP(apmS.canYouConfirmHostKey, ap) },
				{ "id" : "access_point_confim_host_key_container", "innertext" : hostKeys }
			];
			var modalButtons = [
				{"title" : apmS.confirm, "classes" : "btn btn-primary", "function" : confirmationCallback},
				"defaultDismiss"
			];
			modalPrepare('access_point_confirm_host_key_modal', apmS.confirmAPhostKey,
				modalElements, modalButtons);
			openModalWindow('access_point_confirm_host_key_modal');
		}
		else alert("Error resolving "+ap.hostName+" to an address: "+response);
	}
	return runCommandsWithCallback("ssh-keyscan "+ap.hostName+" 2>/dev/null | ssh-keygen -l -f -", callback);
}

function addAccessPointButFirstAddHostKey(ap)
{
	var callback = function(response)
	{
		if(successfulResponse(response))
		{
			var sshResult = stripSuccessFromResponse(response);
			var knownHostsMatch = sshResult.match(/^.*known hosts[^\n]*/);
			if(knownHostsMatch.length > 0)
			{
				sshResult = sshResult.substr(knownHostsMatch[0].length).trim();
				alert(knownHostsMatch[0]);
				closeModalWindow('access_point_confirm_host_key_modal');
			}
			if(sshResult === "1") { addAccessPointAfterConnectivityTest(ap);	}
			else if(sshResult.match(/permission denied/i)) { addAccessPointButFirstAddSshKey(ap); }
			else { alert("Ssh-ing "+ap.name+" gave unknown result: "+sshResult); }
		}
	}
	return runCommandsWithCallback(
		"openssh-ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "+ap.name+" echo 1 2>&1",
		callback);
}

function addAccessPointButFirstAddSshKey(ap)
{
	var transferCallback = function()
	{
		var pass = document.getElementById("access_point_pass").value;
		closeModalWindow("access_point_enter_password_modal");
		var callback = function(response)
		{
			if(successfulResponse(response))
			{
				var sshResult = stripSuccessFromResponse(response);
				if(sshResult.match(/^[0-9]+$/))
				{
					if(sshResult === "0")
					{
						alert("Successfully transferd ssh key to "+ap.name+".");
						addAccessPointAfterConnectivityTest(ap);
					}
					else { alert("Ssh-ing "+ap.name+" gave error "+sshResult+"."); }
				}
				else { alert("Ssh-ing "+ap.name+" gave unknown result: "+sshResult); }
			}
		}
		return runCommandsWithCallback(
			"sshpass -p '"+pass.replaceAll("'","'\"'\"'")+"'openssh-ssh "+ap.name
				+" \"echo $(cat /root/.ssh/id_rsa.pub) >> /etc/dropbear/authorized_keys; echo \\$?\" 2>&1",
			callback);
	}
	var modalElements = [
		{ "id" : "access_point_enter_password_modal_title",
			"innertext" : replaceAP(apmS.enterPasswordForSshKeyTransferDetail, ap) },
		{ "id" : "access_point_enter_password_header_text",
			"innertext" : replaceAP(apmS.enterPasswordForSshKeyTransferDetail, ap) },
		{ "id" : "access_point_pass" }
	];
	var modalButtons = [
		{"title" : apmS.transfer, "classes" : "btn btn-primary", "function" : transferCallback},
		"defaultDismiss"
	];
	modalPrepare('access_point_enter_password_modal', replaceAP(apmS.enterPasswordForSshKeyTransfer, ap),
		modalElements, modalButtons);
	openModalWindow('access_point_enter_password_modal');
}

function addAccessPointAfterConnectivityTest(ap)
{
	var callback = function(response)
	{
		if(successfulResponse(response))
		{
			document.getElementById("add_ap_name").value = "";
			eval(stripSuccessFromResponse(response));
			enableSaveButton();
			checkAccessPointToBeAdded();
			buildTables();
		}
	}
	return runCommandsWithCallback(
		["/usr/lib/ap_management/define_ap_wifi_config.sh managedAPs " + ap.hostName,
			"/usr/lib/ap_management/define_ap_wifi_capabilities.sh managedAPs " + ap.hostName],
		callback);
}

function successfulResponse(response)
{
	return response != null && response.match(/Success\n$/);
}

function stripSuccessFromResponse(response)
{
	return response.replace(/Success\n$/,"").trim();
}

function runCommandsWithCallback(cmd, callback, disableControlsBeforeRequest = true, reenableControlsAfterResponse = true)
{
	var commands = isArray(cmd) ? cmd.join("\n") : cmd;
	var param = getParameterDefinition("commands", commands) + "&"
		+ getParameterDefinition("hash",
			document.cookie.split(/;/)
				.filter(s=>s.split(/=/)[0].trim()==="hash")
				.reduce((r,s)=>s)
				.split(/=/)[1])
	if(disableControlsBeforeRequest)
	{
		setControlsEnabled(false, true, UI.Wait);
	}
	var stateChangeFunction = function(req)
	{
		if(req.readyState === 4)
		{
			if(reenableControlsAfterResponse) setControlsEnabled(true);
			callback(req.responseText);
		}
	}
	return runAjax("POST", "utility/run_commands.sh", param, stateChangeFunction);
}

function removeAPfromTable(table, row)
{
	var removedAPname = row.childNodes[0].firstChild.data;
	managedAPs = managedAPs.filter(ap => ap.name !== removedAPname);
	buildRadioTable();
	enableSaveButton();
}

function checkAccessPointToBeAdded()
{
	var apNameField = document.getElementById("add_ap_name");
	var button = document.getElementById("add_ap_button");
	if(apNameField.validity.patternMismatch || managedAPs.find(ap => ap.name === apNameField.value))
	{
		button.setAttribute("disabled","disabled");
	}
	else { button.removeAttribute("disabled"); }
}

function togglePass(name)
{
	password_field = document.getElementById(name);
	password_field.type = password_field.type === 'password' ? 'text' : 'password';
}

function replaceAP(str, ap) { return str.replaceAll("$AP", ap.hostName); }

function enableSaveButton(enable = true)
{
	var saveButton = document.getElementById("save_button");
	if(enable) { saveButton.removeAttribute("disabled"); }
	else { saveButton.setAttribute("disabled", "disabled"); }
}

function disableSaveButton(disable=true) { enableSaveButton(!disable); }

function createEditButton(callback)
{
	var editButton = createInput("button");
	editButton.textContent = UI.Edit;
	editButton.className = "btn btn-default btn-edit";
	editButton.onclick = callback;
	return editButton;
}

function convertArrayToOptionsMap(a, valueFn)
{
		valueFn = valueFn || (x => x);
		var obj = {};
		a.forEach(x => { obj[x] = valueFn(x) }) ;
		return obj;
}

function editRadioModal()
{
	var editRow = this.parentNode.parentNode;
	var modalButtons = [
		{"title" : UI.CApplyChanges, "classes" : "btn btn-primary", "function" : function() { editRadio(editRow); } },
		"defaultDiscard"
	];
	var editValues = function(i) { return editRow.childNodes[i].firstChild.data; };
	var apHostName = editValues(0);
	var ap = managedAPs.find(ap => ap.hostName === apHostName);
	var apRadio = editValues(1);
	var radio = ap.radios.find(radio => radio.radio === apRadio);
	var allowedChannelBandsForRadio = convertArrayToOptionsMap(
		union(...radio.bands.map(band => allowedChannelBandsForIndex[band.band])),
			channelBand => channelBandMap[channelBand]);
	var apRadioBand = channelBandReverseMap[editValues(2)];
	var band = radio.bands.find(band => band.band === channelBandIndex[apRadioBand]);
	var apChannel = editValues(3);
	var allowedChannels = band ? convertArrayToOptionsMap(band.channels.map(channel => channel.channel)) : {};
	var channel = band ? band.channels.find(channel => channel.channel == apChannel) : undefined;
	var allowedChannelModes = channel ? convertArrayToOptionsMap(channel.channelWidths): {};
	var modalElements = [
		{'id': 'edit_radio_ap', 'value': apHostName},
		{'id': 'edit_radio_radio', 'value': apRadio},
		{'id': 'edit_radio_original_radio', 'value': apRadio},
		{'id': 'edit_radio_channel_band', 'value': apRadioBand, 'options': allowedChannelBandsForRadio},
		{'id': 'edit_radio_channel', 'value': apChannel, 'options': allowedChannels},
		{'id': 'edit_radio_frequency', 'value': editValues(4)},
		{'id': 'edit_radio_channel_mode', 'value': editValues(5), 'options': allowedChannelModes},
		{'id': 'edit_radio_tx_power', 'value': editValues(6)},
		{'id': 'edit_radio_country', 'value': editValues(7)}
	];
	modalPrepare('access_point_edit_radio_modal', apmS.editRadio, modalElements, modalButtons);
	checkAllowedOptionsInRadioEditModal();
	openModalWindow('access_point_edit_radio_modal');
}

function createOption(key, value) {
	var option = document.createElement('option');
	option.value = key;
	option.innerHTML = value;
	return option;
}

function checkAllowedOptionsInRadioEditModal(element)
{
	var truncId = element ? element.id.replace(/^edit_radio_/,"") : "channel_band";
	var apHostName = document.getElementById("edit_radio_ap").value;
	var ap = managedAPs.find(ap => ap.hostName === apHostName);
	var apRadio = document.getElementById("edit_radio_original_radio").value;
	var radio = ap.radios.find(radio => radio.radio === apRadio);
	var apRadioBand = document.getElementById("edit_radio_channel_band").value;
	var band = radio.bands.find(band => band.band === channelBandIndex[apRadioBand]);
	var channelSelect = document.getElementById("edit_radio_channel");
	if(truncId === "channel_band")
	{
		var selectedChannel = channelSelect.value;
		removeAllOptionsFromSelectElement(channelSelect);
		band.channels.forEach(channel => { channelSelect.options.add(createOption(channel.channel, channel.channel))});
		channelSelect.value = band.channels.find(channel => channel.channel == selectedChannel)?.channel;
	}
	if(truncId === "channel_band" || truncId === "channel")
	{
		var selectedChannel = channelSelect.value;
		var channel = band.channels.find(channel => channel.channel == selectedChannel);
		document.getElementById('edit_radio_frequency').value =
			selectedChannel ? channel.frequency/1e6 + "" : "";
		document.getElementById('edit_radio_tx_power_max').innerText =
			selectedChannel ? "(0-"+Math.floor(channel.maxTxPower)+")" : "";
		var txPowerInput = document.getElementById('edit_radio_tx_power');
		if(selectedChannel && txPowerInput.value && txPowerInput.value > channel.maxTxPower)
		{
			txPowerInput.value = channel.maxTxPower;
		}
		document.getElementById('edit_radio_tx_power').max = channel.maxTxPower;
		var channelModeSelect = document.getElementById('edit_radio_channel_mode');
		var selectedChannelMode = channelModeSelect.value;
		removeAllOptionsFromSelectElement(channelModeSelect);
		if(selectedChannel)
		{
			channel.channelWidths.forEach(
				channelWidth => { channelModeSelect.options.add(createOption(channelWidth, channelWidth)) });
			channelModeSelect.value = channel.channelWidths.find(channelWidth => channelWidth === selectedChannelMode);
		}
	}
}

function markInvalidField(field, invalid)
{
	if(invalid && typeof invalid === 'function') { invalid = invalid(field); }
	if(invalid) { field.style.border = 'solid red'; }
	else { field.style.border = ''; }
	return invalid;
}

function editRadio(editRow)
{
	var changed = false;
	var editValues = function(i) { return editRow.childNodes[i].firstChild.data; };
	var radioField = document.getElementById('edit_radio_radio');
	var apHostName = editValues(0);
	var apRadio = editValues(1);
	var newRadio = radioField.value;
	if(markInvalidField(document.getElementById('edit_radio_tx_power'),
			field => field.value && (field.value < field.min || field.max < field.value))
		| markInvalidField(radioField,
			!newRadio || managedAPs.find(ap => ap.hostName === apHostName)
					.config.getAllSectionsOfType('wireless','wifi-device')
					.filter(radio => radio !== apRadio).find(radio => radio === newRadio))
		| markInvalidField(document.getElementById('edit_radio_channel_mode'), field => !field.value)
		| markInvalidField(document.getElementById('edit_radio_channel'), field => !field.value))
	{
		return;
	}
	var ap = managedAPs.find(ap => ap.hostName === apHostName);
	if(apRadio !== newRadio)
	{
		ap.config.set('wireless', newRadio, '', 'wifi-device');
		ap.config.getAllOptionsInSection('wireless', apRadio + '\\.', true)
			.forEach(opt => {
				var value = ap.config.get('wireless', apRadio, opt);
				if(isArray(value)) { ap.config.createListOption('wireless', newRadio, opt); }
				ap.config.set('wireless', newRadio, opt, value);
			});
		ap.config.getAllSectionsOfType('wireless', 'wifi-iface')
			.filter(iface => ap.config.get('wireless', iface, 'device') === apRadio)
			.forEach(iface => { ap.config.set('wireless', iface, 'device', newRadio); });
		ap.config.removeSection('wireless', apRadio);
		ap.radios.find(radio => radio.radio === apRadio).radio = newRadio;
		apRadio = newRadio;
		changed = true;
		buildSSIDtable();
	}
	var checkAndSetUciValueFromId = function(opt, id)
	{
			return checkAndSetUciValue(ap, apRadio, opt, document.getElementById(id).value);
	};
	changed |= checkAndSetUciValueFromId('hwmode', 'edit_radio_channel_band');
	changed |= checkAndSetUciValueFromId('channel', 'edit_radio_channel');
	changed |= checkAndSetUciValueFromId('htmode', 'edit_radio_channel_mode');
	changed |= checkAndSetUciValueFromId('txpower', 'edit_radio_tx_power');
	changed |= checkAndSetUciValueFromId('country', 'edit_radio_country');
	if(changed)
	{
		buildRadioTable();
		enableSaveButton();
	}
	closeModalWindow('access_point_edit_radio_modal');
}

function createCheckbox(checked, callback, enabled)
{
	var checkbox = document.createElement('input');
	checkbox.type = 'checkbox';
	if(enabled === false) { checkbox.setAttribute("disabled", "disabled"); }
	checkbox.checked = checked;
	checkbox.onclick = callback;
	return checkbox;
}

function removeSSIDfromTable(table, row)
{
	var SSIDtoRemove = row.childNodes[0].firstChild.data;
	row.childNodes[2].firstChild.data.split(', ')
		.map(apAndRadio => apAndRadio.match(/^(.*)\.([^.]*)/))
		.map(m => ({'ap': m[1], 'radio': m[2]}))
		.forEach(apr => {
			var ap = managedAPs.find(ap => ap.hostName === apr.ap);
			ap.config.getAllSectionsOfType('wireless', 'wifi-iface')
				.filter(iface => ap.config.get('wireless', iface, 'ssid') === SSIDtoRemove
					&& ap.config.get('wireless', iface, 'device') === apr.radio)
				.forEach(iface => { ap.config.removeSection('wireless', iface)});
		});
	buildSSIDtable();
	enableSaveButton();
}

function changeValueOfBooleanSSIDproperty(serviceSets, option, checked)
{
	var newValue = checked ? '1' : '0';
	var changed = false;
	serviceSets.forEach(serviceSet => {
		changed |= checkAndSetUciValue(managedAPs.find(ap => ap.hostName === serviceSet.ap),
			serviceSet.iface, option, newValue);
	});
	if(option === 'ieee80211r' && checked && changed)
	{
		var fastRoamingMode = serviceSets[0].encryption.match(/^(psk|sae)/) ?
			'local' :
			allServiceSetsHaveMacAddresses(serviceSets) ?
				'static' :
				'auto';
		configureFastRoaming(serviceSets, newValue, fastRoamingMode);
	}
	if(changed) { enableSaveButton(); }
}

function getApWithRadioFromServiceSet(serviceSet) { return serviceSet.ap + '.' + serviceSet.device; }

function getApWithRadioListFromServiceSets(serviceSets)
{
	return serviceSets.map(getApWithRadioFromServiceSet);
}

function getMacAddressesOfServiceSets(serviceSets)
{
	return serviceSets.map(
		serviceSet => {
			var ap =managedAPs.find(ap=>ap.hostName === serviceSet.ap);
			var r = { 'ap': serviceSet.ap, 'radio': serviceSet.device, 'iface': serviceSet.iface };
			r.device = Object.keys(ap.wifiInfo).find(devName=>{
				var dev = ap.wifiInfo[devName];
				return dev['ESSID']===serviceSet.ssid &&
					ap.radios.find(radio=>radio.phy===dev['PHY name']).radio===serviceSet.device;
			});
			r.macAddr = r.device && ap.wifiInfo[r.device]['Access Point'];
			return r;
		});
}

function allServiceSetsHaveMacAddresses(serviceSets)
{
	return !getMacAddressesOfServiceSets(serviceSets).find(x => !x.macAddr);
}

function getServiceSetsFor(ssid, apAndRadioList)
{
	return gatherServiceSets(managedAPs).find(
		serviceSets => serviceSets[0].ssid === ssid
			&& apAndRadioList.includes(getApWithRadioFromServiceSet(serviceSets[0])));
}

function editSSIDmodal()
{
	var editRow = this.parentNode.parentNode;
	var modalButtons = [
		{"title" : UI.CApplyChanges, "classes" : "btn btn-primary", "function" : function() { editSSID(editRow); } },
		"defaultDiscard"
	];
	var editValues = function(i) { return editRow.childNodes[i].firstChild.data; };
	var ssid = editValues(0);
	var selectedRadios = editValues(2).split(/, /);
	var selectedAps = union(selectedRadios.map(apAndRadio => apAndRadio.split('.')[0]));
	var availableVlansMap = convertArrayToOptionsMap(getAvailableVlansOnAPs(selectedAps));
	var serviceSets = gatherServiceSets(managedAPs).find(
		serviceSets => serviceSets[0].ssid === ssid
			&& selectedRadios.indexOf(serviceSets[0].ap + '.' + serviceSets[0].device) >= 0);
	var allRadios = convertArrayToOptionsMap(
		flatten(managedAPs.map(ap => ap.radios.map(radio => ap.hostName + '.' + radio.radio))));
	var getOption = function(opt) { return serviceSets[0][opt] || uciDefaults.wireless['wifi-iface'][opt]; };
	var encryption = getOption('encryption').split('+');
	if(encryption.length > 1)
	{
		encryption = [encryption[0], encryption.slice(1).join('+').replace(/aes/, 'ccmp')];
	}
	else { encryption.push('ccmp'); }
	var fastRoamingModes = { 'auto' : apmS.autoDiscovery, 'static': apmS.staticConfiguration,
		'local': apmS.localKeyGeneration};
	if(!encryption[0].match(/^psk|^sae/)) { delete fastRoamingModes.local; }
	if(!allServiceSetsHaveMacAddresses(serviceSets)) { delete fastRoamingModes.static; }
	var modalElements = [
		{'id': 'edit_ssid_ssid', 'value': ssid},
		{'id': 'edit_ssid_aps', 'values': selectedRadios, 'options': allRadios},
		{'id': 'edit_ssid_vlan', 'value': getCommonVlanOfServiceSets(serviceSets), 'options': availableVlansMap},
		{'id': 'edit_ssid_encryption', 'value': encryption[0], 'options': getWifiEncryptionMap()},
		{'id': 'edit_ssid_encryption_cipher', 'value': encryption[0] !== 'wep' ? encryption[1] : 'ccmp',
			'options': encryptionCiphers},
		{'id': 'edit_ssid_encryption_key', 'value': serviceSets[0].key},
		{'id': 'edit_ssid_radius_server', 'value': serviceSets[0].server},
		{'id': 'edit_ssid_radius_port', 'value': getOption('port')},
		{'id': 'edit_ssid_wep_mode', 'value': encryption[0] === 'wep' && encryption[1] ? encryption[1] : 'open'},
		{'id': 'edit_ssid_wep_key', 'value': serviceSets[0].key},
		{'id': 'edit_ssid_wep_key1', 'value': serviceSets[0].key1},
		{'id': 'edit_ssid_wep_key2', 'value': serviceSets[0].key2},
		{'id': 'edit_ssid_wep_key3', 'value': serviceSets[0].key3},
		{'id': 'edit_ssid_wep_key4', 'value': serviceSets[0].key4},
		{'id': 'edit_ssid_mobility_domain', 'value': getOption('mobility_domain')},
		{'id': 'edit_ssid_fast_roaming_mode', 'options' : fastRoamingModes,	'value': getFastRoamingMode(getOption)}
	];
	modalPrepare('access_points_edit_ssid_modal', apmS.editSSID, modalElements, modalButtons);
	[{'id': 'edit_ssid_enabled', 'value': getOption('disabled') === '0'},
		{'id': 'edit_ssid_hidden', 'value': getOption('hidden') === '1'},
		{'id': 'edit_ssid_isolate', 'value': getOption('isolate') === '1'},
		{'id': 'edit_ssid_ieee80211r', 'value': getOption('ieee80211r') === '1'},
		{'id': 'edit_ssid_pmk_r1_push', 'value': getOption('pmk_r1_push') === '1'},
		{'id': 'edit_ssid_ft_over_ds', 'value': getOption('ft_over_ds') === '1'},
		{'id': 'edit_ssid_disassoc_low_ack', 'value': getOption('disassoc_low_ack') === '1'}
	].forEach(x => { document.getElementById(x.id).checked = x.value; });
	showCorrespondingFieldsInSsidEditModal();
	openModalWindow('access_points_edit_ssid_modal');
}


function changeVisibilityOfEditSsidField(subid, show) {
	document.getElementById('edit_ssid_' + subid + '_container').style.display = show ? 'block' : 'none';
}

function getOptionValueIndex(selectElement, value)
{
	selectElement = typeof selectElement === 'string' ? document.getElementById(selectElement) : selectElement;
	for(var i=0; i < selectElement.options.length; i++)
	{
		if(selectElement.options.item(i).value === value) {	return i; }
	}
	return -1;
}

function showCorrespondingFieldsInSsidEditModal()
{
	var wepRowIds = ['wep_mode', 'wep_key', 'wep_key1', 'wep_key2', 'wep_key3', 'wep_key4'];
	var pskRowIds = ['encryption_key', 'encryption_cipher', 'ieee80211r', 'mobility_domain', 'fast_roaming_mode',
		'pmk_r1_push', 'ft_over_ds'];
	var wpaRowIds = [...pskRowIds, 'radius_server', 'radius_port'];
	var allRowIds = union(wepRowIds, pskRowIds, wpaRowIds);
	var showOnly = function(ids) {
		complement(allRowIds, ids).forEach(id => changeVisibilityOfEditSsidField(id, false));
		ids.forEach(id => changeVisibilityOfEditSsidField(id, true));
	};
	var selectedSecurity = document.getElementById('edit_ssid_encryption').value;
	if(selectedSecurity.match(/^wep/)) { showOnly(wepRowIds); }
	else if(selectedSecurity.match(/^psk|^sae/)) { showOnly(pskRowIds); }
	else if(selectedSecurity.match(/^wpa/)) { showOnly(wpaRowIds); }
	else { showOnly([]); }
	var fastRoamingEnabled = document.getElementById('edit_ssid_ieee80211r').checked;
	['mobility_domain', 'fast_roaming_mode', 'pmk_r1_push', 'ft_over_ds']
		.forEach(id => changeVisibilityOfEditSsidField(id, fastRoamingEnabled));
	var fastRoamingModeSelect = document.getElementById('edit_ssid_fast_roaming_mode');
	var selectedFastRoamingMode = fastRoamingModeSelect.value;
	var fastRoamingModeSelectLocalIndex = getOptionValueIndex(fastRoamingModeSelect, 'local');
	if(selectedSecurity.match(/^psk|^sae/) && fastRoamingModeSelectLocalIndex < 0)
	{
		fastRoamingModeSelect.options.add(createOption('local', apmS.localKeyGeneration))
	}
	else if(!selectedSecurity.match(/^psk|^sae/) && fastRoamingModeSelectLocalIndex >= 0)
	{
		if(selectedFastRoamingMode === 'local') { selectedFastRoamingMode = undefined; }
		fastRoamingModeSelect.options.remove(fastRoamingModeSelectLocalIndex);
	}
	fastRoamingModeSelect.value = selectedFastRoamingMode;
	changeVisibilityOfEditSsidField('pmk_r1_push',
		selectedSecurity.match(/^psk|^sae|^wpa/) && fastRoamingEnabled
			&& fastRoamingModeSelect.value !== 'local');
}

function ajdustAvailableVlansInSsidEditModal()
{
	var vlanSelect = document.getElementById('edit_ssid_vlan');
	var selectedVlan = vlanSelect.value;
	removeAllOptionsFromSelectElement(vlanSelect);
	var availableVlans = getAvailableVlansOnAPs(
		union(getSelectedOptionValues('edit_ssid_aps').map(apAndRadio => apAndRadio.split('.')[0])));
	availableVlans.forEach(vlan => { vlanSelect.options.add(createOption(vlan, vlan))});
	vlanSelect.value = availableVlans.find(vlan => vlan == selectedVlan);
}

function getVlanBridge(ap, vlan)
{
	return ap.bridges.find(iface =>
		ap.config.get('network', iface, 'ifname').split(' ').find(ifname => ifname.match('\\.' + vlan + '$')));
}

function getAvailableVlansOnAPs(apsToSearch)
{
	return (apsToSearch ? managedAPs.filter(ap => apsToSearch.find(apName => ap.hostName === apName)) : managedAPs)
		.map(ap => ap.config.getAllSectionsOfType('network', 'switch_vlan')
				.map(switchVlanSection => ap.config.get('network', switchVlanSection, 'vlan'))
				.filter(vlan => getVlanBridge(ap, vlan)))
		.reduce((x, y) => intersection(x,y));
}

function getSelectedOptionValues(id)
{
	var selectOptions = document.getElementById(id).options;
	var selectedValues = [];
	for(var i = 0; i < selectOptions.length; i++)
	{
		if(selectOptions.item(i).selected) { selectedValues.push(selectOptions.item(i).value); }
	}
	return selectedValues;
}

function editSSID(editRow)
{
	var changed = false;
	var getField = function(id) { return document.getElementById('edit_ssid_' + id); };
	var newSsidField = getField('ssid');
	var newEncryption = getField('encryption').value;
	var newEncryptionCipher = getField('encryption_cipher').value;
	var newWEPmode = getField('wep_mode').value;
	var newVlanField = getField('vlan');
	var fastRoamingEnabled = newEncryption.match(/^(psk|sae|wpa)/) && getField('ieee80211r').checked;
	var mobilityDomainField = getField('mobility_domain');
	var fastRoamingModeField = getField('fast_roaming_mode');
	if (markInvalidField(newSsidField, !(newSsidField.validity.valid && newSsidField.value))
		| markInvalidField(newVlanField, !newVlanField.value)
		| (fastRoamingEnabled && markInvalidField(mobilityDomainField,
			!(mobilityDomainField.validity.valid && mobilityDomainField.value)))
		| (fastRoamingEnabled && (
			markInvalidField(fastRoamingModeField, !fastRoamingModeField.value)
			| markInvalidField(mobilityDomainField,
				!(mobilityDomainField.validity.valid && mobilityDomainField.value))))) {
		return;
	}
	var editValues = function(i)
	{
		var cell = editRow.childNodes[i].firstChild;
		return cell.type === 'checkbox' ? cell.checked : cell.data;
	};
	var oldSsid = editValues(0);
	var oldRadios = editValues(2).split(/, /);
	var serviceSets = getServiceSetsFor(oldSsid, oldRadios);
	var newEnabled = getField('enabled').checked;
	var selectedAps = getSelectedOptionValues('edit_ssid_aps');
	var removedRadios = [], keptRadios = [], addedRadios = [];
	diffArrays(oldRadios, selectedAps, null, pushTo(removedRadios), pushTo(keptRadios), pushTo(addedRadios));
	removedRadios.forEach(processAPifaceForServiceSet(oldSsid, (ap, radio, iface) => {
		if(newEnabled)	{ ap.config.set('wireless', iface, 'disabled', '1'); }
		else { ap.config.removeSection('wireless', iface); }
		changed = true;
	}));
	serviceSets = serviceSets.filter(serviceSet => !removedRadios.includes(getApWithRadioFromServiceSet(serviceSet)));
	addedRadios.forEach(processAPifaceForServiceSet(oldSsid, (ap, radio, iface) => {
		if(!iface)
		{
			iface = getRandomSectionName(ap.config,'wireless','ap_managed_');
			ap.config.set('wireless', iface, '', 'wifi-iface');
			ap.config.set('wireless', iface, 'ssid', oldSsid);
			ap.config.set('wireless', iface, 'device', radio);
			serviceSets.push({'ap': ap.hostName, 'iface': iface, 'device': radio, 'ssid': oldSsid});
			changed = true;
		}
	}));
	var modifiedAps = addedRadios.concat(keptRadios);
	modifiedAps.forEach(processAPifaceForServiceSet(oldSsid, (ap, radio, iface) => {
		changed |= checkAndSetUciValue(ap, iface, 'disabled', newEnabled ? '0' : '1');
		['hidden', 'isolate', 'disassoc_low_ack'].concat(fastRoamingEnabled ? ['ft_over_ds', 'pmk_r1_push'] : [])
			.forEach(id => {
				changed |= checkAndSetUciValue(ap, iface, id, getField(id).checked ? '1' : '0')
			});
		var newVlan = newVlanField.value;
		var newVlanBr = getVlanBridge(ap, newVlan);
		changed |= checkAndSetUciValue(ap, iface, 'network', newVlanBr);
		if(newEncryption === 'wep')
		{
			changed |= checkAndSetUciValue(ap, iface, 'encryption',
				newWEPmode === 'open' ? 'wep' : 'wep+' + newWEPmode);
			['key', 'key1', 'key2', 'key3', 'key4']
				.forEach(id => { changed |= checkAndSetUciValue(ap, iface, id, getField(id).value) });
		}
		else if(newEncryption.match(/^(psk|sae|wpa)/))
		{
			changed |= checkAndSetUciValue(ap, iface, 'encryption',
				newEncryptionCipher === 'ccmp' ? newEncryption : newEncryption + '+' + newEncryptionCipher);
			changed |= checkAndSetUciValue(ap, iface, 'key', getField('encryption_key').value);
			if(newEncryption.match(/^wpa/))
			{
				['server', 'port'].forEach(opt => {
					changed |= checkAndSetUciValue(ap, iface, opt, getField('radius_'  +opt).value)
				});
			}
		}
		else { changed |= checkAndSetUciValue(ap, iface, 'encryption', newEncryption); }
		if(fastRoamingEnabled)
		{
			changed |= checkAndSetUciValue(ap, iface, 'mobility_domain', mobilityDomainField.value);
		}
		changed |= checkAndSetUciValue(ap, iface, 'ssid', newSsidField.value);
	}));

	changed |= configureFastRoaming(serviceSets, fastRoamingEnabled, fastRoamingModeField.value);

	if(changed)
	{
		buildSSIDtable();
		enableSaveButton();
	}
	closeModalWindow('access_points_edit_ssid_modal');
}

function processAPifaceForServiceSet(ssid, f) {
	return x => {
		var [apHost, apRadio] = x.split('.');
		var ap = managedAPs.find(ap => ap.hostName === apHost);
		var iface = ap.config.getAllSectionsOfType('wireless', 'wifi-iface')
			.find(iface => ap.config.get('wireless', iface, 'ssid') === ssid
				&& ap.config.get('wireless', iface, 'device') === apRadio);
		f(ap, apRadio, iface);
	};
}

function checkAndSetUciValue(ap, section, opt, value)
{
	var oldValue = ap.config.get('wireless', section, opt);
	var changed = false;
	if(oldValue && isArray(oldValue))
	{
		if(value)
		{
				changed = !isArray(value) ||
					value.length !== oldValue.length ||
					intersection(value, oldValue).length !== value.length;
		}
		else {
			value = [];
			changed = true;
		}
	}
	else if(value && isArray(value))
	{
		ap.config.createListOption('wireless', section, opt);
		changed = true;
	}
	else { changed = oldValue !== value; }
	if(changed) { ap.config.set('wireless', section, opt, value); }
	return changed;
}

function getFastRoamingMode(getOption)
{
	var encryptionIsPsk = getOption('encryption').match(/^(psk|sae)/);
	var r0kh = getOption('r0kh'), r1kh = getOption('r1kh');
	return encryptionIsPsk && getOption('ft_psk_generate_local') === '1' ?
		'local' :
		r0kh && isArray(r0kh) && r1kh && isArray(r1kh)?
			r0kh.length === 1 && r0kh[0].match(/^ff(:ff){5},\*,/) &&
			r1kh.length === 1 && r1kh[0].match(/^00(:00){5},00(:00){5},/) ?
				'auto' :
				'static' :
			encryptionIsPsk ? 'local' : 'auto';
}

function configureFastRoaming(serviceSets, fastRoamingEnabled, fastRoamingMode)
{
	var changed = false;
	var ssid = serviceSets[0].ssid;
	var r0kh = [], r1kh = [];
	if(fastRoamingEnabled && ['auto', 'static'].includes(fastRoamingMode)) {
		var oldR0kh = managedAPs.find(ap => ap.hostName === serviceSets[0].ap)
			.config.get('wireless', serviceSets[0].iface, 'r0kh');
		var password = oldR0kh && isArray(oldR0kh) && oldR0kh.split(',').at(-1);
		if (!password || password.length < 32) {
			password = randomHexString(32);
		}
		if (fastRoamingMode === 'auto') {
			r0kh.push('ff:ff:ff:ff:ff:ff,*,' + password);
			r1kh.push('00:00:00:00:00:00,00:00:00:00:00:00,' + password);
		} else {
			getMacAddressesOfServiceSets(serviceSets).map(r => r.macAddr).forEach(bssid => {
				var nasid = bssid.replaceAll(':', '');
				r0kh.push(`${bssid},${nasid},${password}`);
				r1kh.push(`${bssid},${bssid},${password}`);
			});
		}
	}
	getApWithRadioListFromServiceSets(serviceSets).forEach(
		processAPifaceForServiceSet(ssid,
			(ap, radio, iface) => {
				if(fastRoamingEnabled)
				{
					if(['auto', 'static'].includes(fastRoamingMode))
					{
						changed |= checkAndSetUciValue(ap, iface, 'r0kh', r0kh);
						changed |= checkAndSetUciValue(ap, iface, 'r1kh', r1kh);
						changed |= checkAndSetUciValue(ap, iface, 'ft_psk_generate_local', '0');
						changed |= checkAndSetUciValue(ap, iface, 'ieee80211r', '1');
					}
					else if(fastRoamingMode === 'local')
					{
						changed |= checkAndSetUciValue(ap, iface, 'ft_psk_generate_local', '1');
						changed |= checkAndSetUciValue(ap, iface, 'ieee80211r', '1');
					}
				}
				else changed |= checkAndSetUciValue(ap, iface, 'ieee80211r', '0');
			})
	);
	return changed;
}

function getRandomSectionName(config, section, prefix)
{
	var newSectionName = prefix + randomHexString(4);
	while(config.get(pkg, newSectionName))
	{
		newSectionName = prefix + randomHexString(4);
	}
	return newSectionName;
}

/*
			var switchSection = ap.config.getAllSectionsOfType('network', 'switch')[0];
			var switchName = ap.config.get('network', switchSection , 'name');
			if(!ap.config.getAllSectionsOfType('network', 'switch_vlan').find(
				switchVlanSection =>
					ap.config.get('network', switchVlanSection, 'device') === switchName &&
						ap.config.get('network', switchVlanSection, 'vlan') === newVlan))
			{
				var taggedSwitchPorts = ap.config.getAllSectionsOfType('network', 'switch_vlan')
					.filter(switchVlanSection =>
						ap.config.get('network', switchVlanSection, 'device') === switchName &&
						ap.config.get('network', switchVlanSection, 'vlan') === '1')
					.map(switchVlanSection =>
						ap.config.get('network', switchVlanSection, 'ports')
							.replaceAll('t', '').split(' ')
							.map(port => port + 't').join(' '))[0];
				var newSwitchVlanSection =
					getRandomSectionName(ap.config, 'network', 'ap_managed_switch_vlan_');
				ap.config.set('network', newSwitchVlanSection, '', 'switch_vlan');
				ap.config.set('network', newSwitchVlanSection, 'device', switchName);
				ap.config.set('network', newSwitchVlanSection, 'vlan', newVlan);
				ap.config.set('network', newSwitchVlanSection, 'ports', taggedSwitchPorts);
			}

		if(!newVlanBr)
		{
			newVlanBr = getRandomSectionName(ap.config,'network','ap_managed_br_');
			ap.config.set('network', newVlanBr, '', 'interface');
			ap.config.set('network', newVlanBr, 'type', 'bridge');
			ap.config.set('network', newVlanBr, 'ifname', lanIf + '.' + newVlan);
		}

function checkAndAlertMissingVlanConfiguration(vlan, apsToSearch)
{
	var apsWithMissingVlan = managedAPs
		.filter(ap =>
			(!apsToSearch || apsToSearch.find(apHostName => apHostName === ap.hostName))
			&& (!ap.config.getAllSectionsOfType('network', 'switch_vlan')
					.find(sw_vlan => ap.config.get('network', sw_vlan, 'vlan') === vlan)
				|| !getVlanBridge(ap, vlan)))
		.map(ap => ap.hostName);
	if(apsWithMissingVlan.length > 0)
	{
		alert(apmS.missingVlanOnAps.replace('$VLAN', vlan + '') + apsWithMissingVlan.join(', '));
		return false;
	}
	return true;
}

 */

function addSSID()
{

}
