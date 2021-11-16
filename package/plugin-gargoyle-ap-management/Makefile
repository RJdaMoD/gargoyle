#
# Copyright (C) 2021 Roger John
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=plugin_gargoyle_ap_management
PKG_VERSION:=$(GARGOYLE_VERSION)
ifeq ($(GARGOYLE_VERSION),)
     PKG_VERSION:=1.0.0
endif

PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/plugin-gargoyle-ap-management
	SECTION:=admin
	CATEGORY:=Administration
	SUBMENU:=Gargoyle Web Interface
	TITLE:=Access Point Management for Gargoyle
	DEPENDS:=+gargoyle +openssh-client-utils +patch +sshpass
	MAINTAINER:=Roger John
	PKGARCH:=all
endef

define Package/plugin-gargoyle-ap-management/description
	Access Point Management for Gargoyle
endef

define Build/Prepare
endef


define Build/Configure
endef

define Build/Compile
endef

define Package/plugin-gargoyle-ap-management/install
	$(INSTALL_DIR) $(1)
	$(CP) ./files/* $(1)/
endef

define Package/plugin-gargoyle-ap-management/postinst
	if [ -z "$${IPKG_INSTROOT}" ] ; then
		menu_name="AP Management"
    	[ -n `which i18n` ] && {
    		mn=$$(i18n-menu gargoyle.display.connection_ap_management)
    		if [ -n "$$mn" ] ; then
    			menu_name="$$mn"
    		fi
    	}
		uci set gargoyle.display.connection_ap_management=""$$menu_name""
		uci set gargoyle.scripts.connection_ap_management="ap_management.sh"
		uci set gargoyle.connection.ap_management="700"
		uci commit
	fi
endef

define Package/plugin-gargoyle-ap-management/postrm
	if [ -z "$${IPKG_INSTROOT}" ] ; then 
		uci del gargoyle.display.connection_ap_management
		uci del gargoyle.scripts.connection_ap_management
		uci del gargoyle.connection.ap_management
		uci commit
	fi
endef

$(eval $(call BuildPackage,plugin-gargoyle-ap-management))
