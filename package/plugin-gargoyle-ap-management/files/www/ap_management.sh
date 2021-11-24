#!/usr/bin/haserl
<%
	# This program is copyright © 2021 Roger John and is distributed under the terms of the GNU GPL
	# version 2.0 with a special clarification/exception that permits adapting the program to
	# configure proprietary "back end" software provided that all modifications to the web interface
	# itself remain covered by the GPL.
	# See http://gargoyle-router.com/faq.html#qfoss for more information
	eval $( gargoyle_session_validator -c "$COOKIE_hash" -e "$COOKIE_exp" -a "$HTTP_USER_AGENT" -i "$REMOTE_ADDR" \
		-r "login.sh" -t $(uci get gargoyle.global.session_timeout) -b "$COOKIE_browser_time" )
	gargoyle_header_footer -h -i -s "connection" -p "ap_management" -j "gs_sortable.js table.js ap_management.js" \
		-z "ap_management.js" ap_management
%>

<script>
<!--
originalManagedAPs = [];
<%
	echo "currentHostName = '$HOSTNAME';"
	/usr/lib/ap_management/define_ap_wifi_config.sh originalManagedAPs
	/usr/lib/ap_management/define_ap_wifi_capabilities.sh originalManagedAPs
%>
//-->
</script>


<h1 class="page-header"><%~ ap_management.apManagement %></h1>

<div class="row">
	<div class="col-lg-5">
		<div class="panel panel-default">
			<div class="panel-heading">
				<h3 class="panel-title"><%~ ap_management.aps %></h3>
			</div>
			<div class="panel-body">

				<div id="access_points_table_heading_container" class="row form-group">
					<span class="col-xs-12" style="text-decoration:underline">
						<%~ ap_management.managedAPs %>:
					</span>
				</div>

				<div class="row form-group">
					<div id="access_points_table_container" class="table-responsive col-xs-12"></div>
					<div class="col-xs-12">
						<input type="text" id="add_ap_name" class="form-control" size="20" oninput="checkAccessPointToBeAdded()"
							pattern="[0-9A-Za-z][0-9A-Za-z\-]*"/>
						<button class="btn btn-default btn-add" id="add_ap_button" onclick="addAccessPoint()" >
							<%~ ap_management.addAP %>
						</button>
					</div>
				</div>
			</div>
		</div>
	</div>
	<div class="col-lg-7">
		<div class="panel panel-default">
			<div class="panel-heading">
				<h3 class="panel-title"><%~ ap_management.radios %></h3>
			</div>
			<div class="panel-body">

				<div id="radios_table_heading_container" class="row form-group">
					<span class="col-xs-12" style="text-decoration:underline">
						<%~ ap_management.managedRadios %>:
					</span>
				</div>

				<div class="row form-group">
					<div id="radio_table_container" class="table-responsive col-xs-12"></div>
				</div>
			</div>
		</div>
	</div>
</div>

<div id="firefox3_bug_correct" style="display:none">
	<input type="text" value="firefox3_bug" />
</div>

<div id="bottom_button_container" class="panel panel-default">
	<button id="save_button" class="btn btn-primary btn-lg" onclick="saveChanges()"><%~ SaveChanges %></button>
	<button id="reset_button" class="btn btn-warning btn-lg" onclick="resetData()"><%~ Reset %></button>
</div>

<div class="modal fade" tabindex="-1" role="dialog" id="access_point_supply_ip_address_modal" aria-hidden="true"
		aria-labelledby="access_point_supply_ip_address_modal_title">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h3 id="access_point_supply_ip_address_modal_title" class="panel-title">
					<%~ ap_management.supplyIpAddress %>
				</h3>
			</div>
			<div class="modal-body">
				<%in templates/access_point_supply_ip_address_template %>
			</div>
			<div class="modal-footer" id="access_point_supply_ip_address_modal_button_container">
			</div>
		</div>
	</div>
</div>

<div class="modal fade" tabindex="-1" role="dialog" id="access_point_confirm_host_key_modal" aria-hidden="true"
		aria-labelledby="access_point_confirm_host_key_modal_title">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h3 id="access_point_confirm_host_key_modal_title" class="panel-title">
					<%~ ap_management.confirmAPhostKey %>
				</h3>
			</div>
			<div class="modal-body">
				<%in templates/access_point_confirm_host_key_template %>
			</div>
			<div class="modal-footer" id="access_point_confirm_host_key_modal_button_container">
			</div>
		</div>
	</div>
</div>

<div class="modal fade" tabindex="-1" role="dialog" id="access_point_enter_password_modal"
		aria-hidden="true" aria-labelledby="access_point_enter_password_modal_title">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h3 id="access_point_enter_password_modal_title" class="panel-title">
					<%~ ap_management.enterPasswordForSshKeyTransfer %>
				</h3>
			</div>
			<div class="modal-body">
				<%in templates/access_point_enter_password_template %>
			</div>
			<div class="modal-footer" id="access_point_enter_password_modal_button_container">
			</div>
		</div>
	</div>
</div>

<div class="modal fade" tabindex="-1" role="dialog" id="access_point_edit_radio_modal"
		aria-hidden="true" aria-labelledby="access_point_edit_radio_modal_title">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h3 id="access_point_edit_radio_modal_title" class="panel-title">
					<%~ ap_management.editRadio %>
				</h3>
			</div>
			<div class="modal-body">
				<%in templates/access_point_edit_radio_template %>
			</div>
			<div class="modal-footer" id="access_point_edit_radio_modal_button_container">
			</div>
		</div>
	</div>
</div>

<script>
<!--
	resetData();
//-->
</script>

<%
	gargoyle_header_footer -f -s "connection" -p "ap_management"
%>
