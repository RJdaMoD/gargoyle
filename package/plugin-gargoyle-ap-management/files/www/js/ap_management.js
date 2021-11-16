/*
 * This program is copyright © 2021 Roger John and is distributed under the terms of
 *  the GNU GPL
 * version 2.0 with a special clarification/exception that permits adapting the program to
 * configure proprietary "back end" software provided that all modifications to the web interface
 * itself remain covered by the GPL.
 * See http://gargoyle-router.com/faq.html#qfoss for more information
 */
var apmS=new Object(); //part of i18n

var pkg = "ap_management";
var sec = "config";

var managedAPs = [];

function saveChanges()
{
	var apCommands = [];
	var packageAndSection = "ap_management_gargoyle.ap_management";
	function addManagedAP(ap)
	{
		if(ap.name != currentHostName)
		{
			apCommands.push("uci -q add_list " + packageAndSection + ".managed_aps=" + ap.name);
		}
	}
	function deleteManagedAP(ap)
	{
		if(ap.name != currentHostName)
		{
			apCommands.push("uci -q del_list " + packageAndSection + ".managed_aps=" + ap.name);
			apCommands.push("rm -f /tmp/wifiConfig." + ap.name);
			apCommands.push("rm -f /tmp/wifiStatus." + ap.name);
		}
	}
	managedAPs.sort(ap => ap.name);
	var i = 0, j = 0;
	while(i < managedAPs.length && j < originalManagedAPs.length)
	{
		if(managedAPs[i].name < originalManagedAPs[j].name) { addManagedAP(managedAPs[i++]); }
		else if(managedAPs[i].name > originalManagedAPs[j].name) { deleteManagedAP(originalManagedAPs[j++]); }
		else { i++; j++; }
	}
	while(i < managedAPs.length) { addManagedAP(managedAPs[i++]); }
	while(j < originalManagedAPs.length) { deleteManagedAP(originalManagedAPs[j++]); }

	if(apCommands.length > 0)
	{
		apCommands.push("uci -q commit\n");
		apCommands.push("/usr/lib/ap_management/define_ap_wifi_config.sh originalManagedAPs");
		var callback = function(response)
		{
			if(successfulResponse(response))
			{
				originalManagedAPs = [];
				eval(stripSuccessFromResponse(response));
				resetData();
			}
		}
		runCommandsWithCallback(apCommands, callback);
	}
}

function resetData()
{
	managedAPs = originalManagedAPs.map(ap => { return {"name": ap.name, "ip": ap.ip, "config": ap.config.clone()} });
	buildAccessPointTable();
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
	if(tableContainer.firstChild != null)
	{
		tableContainer.removeChild(tableContainer.firstChild);
	}
	tableContainer.appendChild(apTable);
	TSort_Data = new Array ('access_points_table', 's', 'p', 'i', 'i');
	tsRegister();
	tsSetTable('access_points_table');
	tsInit();
	checkAccessPointToBeAdded();
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
			"sshpass -p '"+pass.replace("'","'\"'\"'")+"'openssh-ssh "+ap.name
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
			checkAccessPointToBeAdded();
			buildAccessPointTable();
		}
	}
	return runCommandsWithCallback(
		"/usr/lib/ap_management/define_ap_wifi_config.sh managedAPs " + ap.hostName,
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
}

function checkAccessPointToBeAdded()
{
	var apNameField = document.getElementById("add_ap_name");
	var button = document.getElementById("add_ap_button");
	button.innerHTML = apmS.addAP;
	if(apNameField.validity.patternMismatch || managedAPs.find(ap => ap.name == apNameField.value))
	{ button.setAttribute("disabled","disabled"); }
	else
	{ button.removeAttribute("disabled"); }
}
function togglePass(name)
{
	password_field = document.getElementById(name);
	password_field.type = password_field.type == 'password' ? 'text' : 'password';
}
function replaceAP(str, ap) { return str.replaceAll("$AP", ap.hostName); }