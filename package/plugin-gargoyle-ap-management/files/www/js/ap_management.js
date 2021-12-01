/*
 * This program is copyright © 2021 Roger John and is distributed under the terms of
 *  the GNU GPL
 * version 2.0 with a special clarification/exception that permits adapting the program to
 * configure proprietary "back end" software provided that all modifications to the web interface
 * itself remain covered by the GPL.
 * See http://gargoyle-router.com/faq.html#qfoss for more information
 */
var apmS   = new Object(); //part of i18n
var basicS = new Object(); //part of i18n

var pkg = "ap_management";
var sec = "config";
var channelBandMap = {"11b": "2.4GHz (b)", "11g": "2.4GHz", "11a": "5GHz"};
var channelBandIndex = {"11b": 1, "11g": 1, "11a": 2};
var allowedChannelBandsForIndex = {1: ["11b", "11g"], 2: ["11a"]};
var channelBandReverseMap = {};
Object.keys(channelBandMap).forEach(k => { channelBandReverseMap[channelBandMap[k]] = k; });
var htModeMap = {};
["NOHT", "HT20", "HT40", "HT40-", "HT40+", "VHT20", "VHT40", "VHT80", "VHT160"].forEach(x => { htModeMap[x] = x; } );
var encryptionMap;
var encryptionCiphers = {'ccmp': 'CCMP', 'tkip': 'TKIP', 'tkip+ccmp': 'CCMP & TKIP', 'gcmp': 'GCMP'};

var managedAPs = [];

function keyFunctionToCompareFunction(k) { return (x,y) => k(x) == k(y) ? 0 : k(x) < k(y) ? -1 : 1; }

function diffArrays(a, b, key, left, equal, right)
{
	left = left || (x=> {});
	equal = equal || ((x,y) => {});
	right = right || (x=> {});
	var c = keyFunctionToCompareFunction(key);
	a.sort(c);
	b.sort(c);
	var i = 0, j = 0;
	while(i < a.length && j < b.length)
	{
		if(key(a[i]) < key(b[j])) { left(a[i++]); }
		else if(key(a[i]) > key(b[j])) { right(b[j++]); }
		else { equal(a[i++], b[j++]); }
	}
	while(i < a.length) { left(a[i++]); }
	while(j < b.length) { right(b[j++]); }
}

function union(...arrays)
{
	var r = [];
	arrays.forEach(a => { a.forEach(x => { if(!r.find(y => y == x)) { r.push(x); }})});
	r.sort();
	return r;
}

function leftComplementIntersectionRightComplement(a, b, key)
{
	var l = [], i = [], r = [];
	var f = function(a) { return x => { a.push(x); }; };
	key = key || (x=>x);
	diffArrays(a, b, key, f(l), f(i), f(r));
	return [l, i, r];
}

function intersection(a, b, key) { return leftComplementIntersectionRightComplement(a, b, key)[1]; }

function complement(a, b, key) { return leftComplementIntersectionRightComplement(a, b, key)[0]; }

function saveChanges()
{
	var mainCommands = [];
	var packageAndSection = 'ap_management_gargoyle.ap_management';
	function addManagedAP(ap)
	{
		if(ap.name != currentHostName)
		{
			mainCommands.push('uci -q add_list ' + packageAndSection + '.managed_aps=' + ap.name);
		}
	}
	function deleteManagedAP(ap)
	{
		if(ap.name != currentHostName)
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
		if(oldValue == newValue) { return []; }
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
		if(newType && oldType != newType) {	cmds.push('uci -q set ' + uciKeyValue(key, newType)); }
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
		var origAp = originalManagedAPs.find(origAp => origAp.name == ap.name);
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

function resetData()
{
	disableSaveButton();
	managedAPs = originalManagedAPs.map(ap => {
			return {"name": ap.name, "hostName": ap.hostName, "ip": ap.ip, "config": ap.config.clone(),
				"radios": ap.radios.map(radio => clonePlainFlatObject(radio)) };
		});
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
		if(cells.length > 0 && cells[0].innerText == currentHostName)
		{
			cells[cells.length - 1].innerHTML = "<span/>";
			break;
		}
	}
	var tableContainer = document.getElementById('access_points_table_container');
	if(tableContainer.firstChild != null) {	tableContainer.removeChild(tableContainer.firstChild); }
	tableContainer.appendChild(apTable);
	TSort_Data = new Array ('access_points_table', 's', 'p', 'i', 'i');
	tsRegister();
	tsSetTable('access_points_table');
	tsInit();
	checkAccessPointToBeAdded();
}

function buildRadioTable() {
	var radioTable = Array.prototype.concat.apply([],
		managedAPs.map(ap => ap.config.getAllSectionsOfType("wireless","wifi-device")
			.map(radio => {
				var opts = ["hwmode", "channel", "hwmode", "htmode", "txpower", "country"]
					.map(opt => ap.config.get("wireless", radio, opt));
				opts[0] = channelBandMap[opts[0]];
				var chan = ap.radios.find(x => x.radio == radio).bands.find(x => x.band == channelBandIndex[opts[2]])
					.channels.find(x => x.channel == opts[1]);
				opts[2] = chan ? chan.frequency/1e6 + "" : "?";
				return [ap.hostName, radio].concat(opts).concat(
					originalManagedAPs.find(origAp => origAp.name == ap.name) ?
						createEditButton(editRadioModal) : "");
			})));
	radioTable = createTable(
		["AP", apmS.radio, apmS.channelBand, apmS.channel, apmS.frequency + " (MHz)", apmS.channelMode,
			apmS.txPower + " (dBm)", apmS.country],
		radioTable, "radio_table", false, false);
	var tableContainer = document.getElementById('radio_table_container');
	if(tableContainer.firstChild != null) { tableContainer.removeChild(tableContainer.firstChild); }
	tableContainer.appendChild(radioTable);
	TSort_Data = new Array ('radio_table', 's', 's', 's', 'i', 'i', 's', 'i', 's');
	tsRegister();
	tsSetTable('radio_table');
	tsInit();
}

function getWifiSecurityRelevantUciOptionsFor(x)
{
	if(typeof(x) == "string")
	{
		if (x.match(/^psk|^sae/)) {	return ['encryption', 'key'];	}
		else if (x.match(/^wep/)) {	return ['encryption', 'key', 'key1', 'key2', 'key3', 'key4']; }
		else if (serviceSet.security.type.match(/^wpa/)) { return ['encryption', 'server', 'port', 'key']; }
		else { return ['encryption']; }
	}
	else if(typeof(x) == "object")
	{
		return clonePlainFlatObject(x, getWifiSecurityRelevantUciOptionsFor(x.encryption));
	}
}

function clonePlainFlatObject(obj, keys, defaults)
{
	if(obj == undefined) { return obj; }
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

function gatherServiceSets(aps) {
	var gatheredServiceSets = [];
	aps.forEach(ap => {
		ap.config.getAllSectionsOfType("wireless", "wifi-iface")
			.filter(iface => ap.config.get("wireless", iface, "mode") == 'ap')
			.forEach(iface => {
				var serviceSet = {'ap': ap.hostName, 'iface': iface};
				ap.config.getAllOptionsInSection('wireless', iface + '\\.', true)
					.forEach(opt => serviceSet[opt] = ap.config.get('wireless', iface, opt));
				var existingServiceSet = gatheredServiceSets.find(
					x => [x[0], serviceSet]
						.map(y => clonePlainFlatObject(y,
							['ssid', 'disabled', 'hidden', 'isolate', 'ieee80211r']
								.concat(getWifiSecurityRelevantUciOptionsFor(y.encryption)),
							uciDefaults.wireless['wifi-iface']))
						.map(JSON.stringify).reduce((y,z) => y == z));
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
			x.map(serviceSet => serviceSet.ap + '.' + serviceSet.device).sort().join(', '),
			createCheckbox(x[0].disabled != '1',
					o => changeValueOfBooleanSSIDproperty(x, 'disabled', !o.target.checked)),
			createCheckbox(x[0].hidden == '1',
					o => changeValueOfBooleanSSIDproperty(x, 'hidden', o.target.checked)),
			createCheckbox(x[0].isolate == '1',
					o => changeValueOfBooleanSSIDproperty(x, 'isolate', o.target.checked)),
			createCheckbox(x[0].ieee80211r == '1',
					o => changeValueOfBooleanSSIDproperty(x, 'ieee80211r', o.target.checked)),
			createEditButton(editSSIDmodal)]);
	ssidTable = createTable(
		[apmS.SSID, apmS.security, apmS.aps, apmS.enabled, apmS.hidden, apmS.isolate, apmS.fastRoaming],
		ssidTable, "ssid_table", true, false, removeSSIDfromTable);
	var tableContainer = document.getElementById('ssid_table_container');
	if(tableContainer.firstChild != null) { tableContainer.removeChild(tableContainer.firstChild); }
	tableContainer.appendChild(ssidTable);
	TSort_Data = new Array ('ssid_table', 's', 's', 's');
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
					if (ip == ap.ip)
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
			if(sshResult == "1") { addAccessPointAfterConnectivityTest(ap);	}
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
			if(sshResult == "1") { addAccessPointAfterConnectivityTest(ap);	}
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
					if(sshResult == "0")
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
				.filter(s=>s.split(/=/)[0].trim()=="hash")
				.reduce((r,s)=>s)
				.split(/=/)[1])
	if(disableControlsBeforeRequest)
	{
		setControlsEnabled(false, true, UI.Wait);
	}
	var stateChangeFunction = function(req)
	{
		if(req.readyState == 4)
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
	managedAPs = managedAPs.filter(ap => ap.name != removedAPname);
	buildRadioTable();
	enableSaveButton();
}

function checkAccessPointToBeAdded()
{
	var apNameField = document.getElementById("add_ap_name");
	var button = document.getElementById("add_ap_button");
	if(apNameField.validity.patternMismatch || managedAPs.find(ap => ap.name == apNameField.value))
	{
		button.setAttribute("disabled","disabled");
	}
	else { button.removeAttribute("disabled"); }
}

function togglePass(name)
{
	password_field = document.getElementById(name);
	password_field.type = password_field.type == 'password' ? 'text' : 'password';
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

function editRadioModal()
{
	var editRow = this.parentNode.parentNode;
	var modalButtons = [
		{"title" : UI.CApplyChanges, "classes" : "btn btn-primary", "function" : function() { editRadio(editRow); } },
		"defaultDiscard"
	];
	var editValues = function(i) { return editRow.childNodes[i].firstChild.data; };
	var apHostName = editValues(0);
	var ap = managedAPs.find(ap => ap.hostName == apHostName);
	var apRadio = editValues(1);
	var radio = ap.radios.find(radio => radio.radio == apRadio);
	var allowedChannelBandsForRadio = {};
	radio.bands.forEach(band => {
			allowedChannelBandsForIndex[band.band].forEach(hwmode => {
				allowedChannelBandsForRadio[hwmode] = channelBandMap[hwmode];
			})
		}
	);
	var apRadioBand = channelBandReverseMap[editValues(2)];
	var band = radio.bands.find(band => band.band == channelBandIndex[apRadioBand]);
	var apChannel = editValues(3);
	var allowedChannels = {};
	if(band) { band.channels.forEach(channel => { allowedChannels[channel.channel] = channel.channel; }); }
	var channel = band ? band.channels.find(channel => channel.channel == apChannel) : undefined;
	var allowedChannelModes = {};
	if(channel) { channel.channelWidths.forEach(channelWidth => { allowedChannelModes[channelWidth] = channelWidth; }); }
	var modalElements = [
		{"id": "edit_radio_ap", "value": apHostName},
		{"id": "edit_radio_radio", "value": apRadio},
		{"id": "edit_radio_channel_band", "value": apRadioBand, "options": allowedChannelBandsForRadio},
		{"id": "edit_radio_channel", "value": apChannel, "options": allowedChannels},
		{"id": "edit_radio_frequency", "value": editValues(4)},
		{"id": "edit_radio_channel_mode", "value": editValues(5), "options": allowedChannelModes},
		{"id": "edit_radio_tx_power", "value": editValues(6)},
		{"id": "edit_radio_country", "value": editValues(7)}
	];
	modalPrepare('access_point_edit_radio_modal', apmS.editRadio, modalElements, modalButtons);
	checkAllowedOptionsInRadioEditModal();
	openModalWindow('access_point_edit_radio_modal');
}

function checkAllowedOptionsInRadioEditModal(element)
{
	var truncId = element ? element.id.replace(/^edit_radio_/,"") : "channel_band";
	var apHostName = document.getElementById("edit_radio_ap").value;
	var ap = managedAPs.find(ap => ap.hostName == apHostName);
	var apRadio = document.getElementById("edit_radio_radio").value;
	var radio = ap.radios.find(radio => radio.radio == apRadio);
	var apRadioBand = document.getElementById("edit_radio_channel_band").value;
	var band = radio.bands.find(band => band.band == channelBandIndex[apRadioBand]);
	var channelSelect = document.getElementById("edit_radio_channel");
	var createOption = function(key, value) {
		var option = document.createElement('option');
		option.value = key;
		option.innerHTML = value;
		return option;
	};
	if(truncId == "channel_band")
	{
		var selectedChannel = channelSelect.value;
		removeAllOptionsFromSelectElement(channelSelect);
		band.channels.forEach(channel => { channelSelect.options.add(createOption(channel.channel, channel.channel))});
		channelSelect.value = band.channels.find(channel => channel.channel == selectedChannel) ?
			selectedChannel : band.channels[0].channel;
	}
	if(truncId == "channel_band" || truncId == "channel")
	{
		var selectedChannel = channelSelect.value;
		var channel = selectedChannel ?	band.channels.find(channel => channel.channel == selectedChannel) : undefined;
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
			channelModeSelect.value = channel.channelWidths.find(channelWidth => channelWidth == selectedChannelMode) ?
				selectedChannelMode : channel.channelWidths[0];
		}
	}
}

function editRadio(editRow)
{
	var changed = false;
	var editValues = function(i) { return editRow.childNodes[i].firstChild.data; };
	var txPowerField = document.getElementById('edit_radio_tx_power');
	if(txPowerField.value && (txPowerField.value < txPowerField.min || txPowerField.max < txPowerField.value))
	{
		txPowerField.style.border = "solid red";
		return;
	}
	else { txPowerField.style.border = ""; }
	var radioField = document.getElementById('edit_radio_radio');
	var apRadio = editValues(1);
	var newRadio = radioField.value;
	if(!newRadio || managedAPs.find(ap => ap.hostName == editValues(0))
		.config.getAllSectionsOfType('wireless','wifi-device')
		.filter(radio => radio != apRadio).find(radio => radio == newRadio))
	{
		radioField.style.border = "solid red";
		return;
	}
	var apHostName = document.getElementById("edit_radio_ap").value;
	var ap = managedAPs.find(ap => ap.hostName == apHostName);
	if(apRadio != newRadio)
	{
		ap.config.set('wireless', newRadio, '', 'wifi-device');
		ap.config.getAllOptionsInSection('wireless', apRadio + '\\.', true)
			.forEach(opt => {
				var value = ap.config.get('wireless', apRadio, opt);
				ap.config.remove('wireless', apRadio, opt);
				if(isArray(value)) { ap.config.createListOption('wireless', newRadio, opt); }
				ap.config.set('wireless', newRadio, opt, value);
			});
		ap.config.getAllSectionsOfType('wireless', 'wifi-iface')
			.filter(iface => ap.config.get('wireless', iface, 'device') == apRadio)
			.forEach(iface => { ap.config.set('wireless', iface, 'device', newRadio); });
		ap.config.remove('wireless', apRadio, '');
		ap.radios.find(radio => radio.radio == apRadio).radio = newRadio;
		apRadio = newRadio;
		changed = true;
		buildSSIDtable();
	}
	var checkAndSetUciValue = function(opt, id)
	{
			var oldValue = ap.config.get('wireless', apRadio, opt);
			var newValue = document.getElementById(id).value;
			if(oldValue != newValue)
			{
				ap.config.set('wireless', apRadio, opt, newValue)
				return true;
			}
			return false;
	};
	changed |= checkAndSetUciValue('hwmode', 'edit_radio_channel_band');
	changed |= checkAndSetUciValue('channel', 'edit_radio_channel');
	changed |= checkAndSetUciValue('htmode', 'edit_radio_channel_mode');
	changed |= checkAndSetUciValue('txpower', 'edit_radio_tx_power');
	changed |= checkAndSetUciValue('country', 'edit_radio_country');
	buildRadioTable();
	if(changed) { enableSaveButton(); }
	closeModalWindow('access_point_edit_radio_modal');
}

function createCheckbox(checked, callback, enabled)
{
	var checkbox = document.createElement('input');
	checkbox.type = 'checkbox';
	if(enabled == false) { checkbox.setAttribute("disabled", "disabled"); }
	checkbox.checked = checked;
	checkbox.onclick = callback;
	return checkbox;
}

function removeSSIDfromTable(table, row)
{
	var SSIDtoRemove = row.childNodes[0].firstChild.data;
	row.childNodes[2].firstChild.data.split(', ')
		.map(apRadio => apRadio.match(/^(.*)\.([^.]*)/))
		.map(m => { return {'ap': m[1], 'radio': m[2]}; })
		.forEach(apr => {
			var ap = managedAPs.find(ap => ap.hostName == apr.ap);
			ap.config.getAllSectionsOfType('wireless', 'wifi-iface')
				.filter(iface => ap.config.get('wireless', iface, 'ssid') == SSIDtoRemove
					&& ap.config.get('wireless', iface, 'device') == apr.radio)
				.forEach(iface => { ap.config.removeSection('wireless', iface)});
		});
	buildSSIDtable();
	enableSaveButton();
}

function changeValueOfBooleanSSIDproperty(gatheredServiceSets, option, checked)
{
	var newValue = checked ? '1' : '0';
	gatheredServiceSets.forEach(serviceSet => {
		managedAPs.find(ap => ap.hostName == serviceSet.ap).config.set('wireless', serviceSet.iface, option, newValue);
	});
	enableSaveButton();
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
	var selectedAps = editValues(2).split(/, /);
	var serviceSets = gatherServiceSets(managedAPs).find(
		serviceSets => serviceSets[0].ssid == ssid
			&& selectedAps.indexOf(serviceSets[0].ap + '.' + serviceSets[0].device) >= 0);
	var allRadios = {};
	managedAPs.forEach(ap => { ap.radios.forEach(radio => {
			var s = ap.hostName + '.' + radio.radio;
			allRadios[s] = s; })});
	var ifaceDefaults = uciDefaults.wireless['wifi-iface'];
	var getOption = function(opt) { return serviceSets[0][opt] || uciDefaults.wireless['wifi-iface'][opt]; };
	var encryption = getOption('encryption').split('+');
	if(encryption.length > 1)
	{
		encryption = [encryption[0], encryption.slice(1).join('+').replace(/aes/, 'ccmp')];
	}
	else { encryption.push('ccmp'); }
	var modalElements = [
		{'id': 'edit_ssid_ssid', 'value': ssid},
		{'id': 'edit_ssid_aps', 'values': editValues(2).split(/, /), 'options': allRadios},
		{'id': 'edit_ssid_encryption', 'value': encryption[0],
			'options': getWifiEncryptionMap()},
		{'id': 'edit_ssid_encryption_cipher', 'value': encryption[0] != 'wep' ? encryption[1] : 'ccmp',
			'options': encryptionCiphers},
		{'id': 'edit_ssid_encryption_key', 'value': serviceSets[0].key},
		{'id': 'edit_ssid_radius_server', 'value': serviceSets[0].server},
		{'id': 'edit_ssid_radius_port', 'value': getOption('port')},
		{'id': 'edit_ssid_wep_mode', 'value': encryption[0] == 'wep' && encryption[1] ? encryption[1] : 'open'},
		{'id': 'edit_ssid_wep_key', 'value': serviceSets[0].key},
		{'id': 'edit_ssid_wep_key1', 'value': serviceSets[0].key1},
		{'id': 'edit_ssid_wep_key2', 'value': serviceSets[0].key2},
		{'id': 'edit_ssid_wep_key3', 'value': serviceSets[0].key3},
		{'id': 'edit_ssid_wep_key4', 'value': serviceSets[0].key4}
	];
	modalPrepare('access_points_edit_ssid_modal', apmS.editSSID, modalElements, modalButtons);
	[{'id': 'edit_ssid_enabled', 'value': getOption('disabled') == '0'},
		{'id': 'edit_ssid_hidden', 'value': getOption('hidden') == '1'},
		{'id': 'edit_ssid_isolate', 'value': getOption('isolate') == '1'}]
		.forEach(x => { document.getElementById(x.id).checked = x.value; });
	showCorrespondingEncryptionFieldsInSsidEditModal();
	openModalWindow('access_points_edit_ssid_modal');
}

function showCorrespondingEncryptionFieldsInSsidEditModal()
{

	var changeVisibilityOfEditField = function(subid, show) {
		document.getElementById('edit_ssid_' + subid + '_container').style.display =
			show != false ? 'block' : 'none';
	};
	var wepRowIds = ['wep_mode', 'wep_key', 'wep_key1', 'wep_key2', 'wep_key3', 'wep_key4'];
	var pskRowIds = ['encryption_key', 'encryption_cipher'];
	var wpaRowIds = [...pskRowIds, 'radius_server', 'radius_port'];
	var allRowIds = union(wepRowIds, pskRowIds, wpaRowIds);
	var showOnly = function(ids) {
		complement(allRowIds, ids).forEach(id => changeVisibilityOfEditField(id, false));
		ids.forEach(id => changeVisibilityOfEditField(id, true));
	};
	var selectedSecurity = document.getElementById('edit_ssid_encryption').value;
	if(selectedSecurity.match(/^wep/)) { showOnly(wepRowIds); }
	else if(selectedSecurity.match(/^psk|^sae/)) { showOnly(pskRowIds); }
	else if(selectedSecurity.match(/^wpa/)) { showOnly(wpaRowIds); }
	else { showOnly([]); }
}

function editSSID(editRow) {

}

function addSSID()
{

}
