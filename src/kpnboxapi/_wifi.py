"""WiFi: networks, guest and extra WiFi, radios, schedules, spectrum and MAC filtering."""

from typing import Any, Dict, List, Optional, Tuple, Union

from ._devices import DevicesMixin
from ._utils import (
    bedtime_blocks,
    validate_hours,
)


class WifiMixin(DevicesMixin):
    """WiFi: networks, guest and extra WiFi, radios, schedules, spectrum and MAC filtering."""

    def get_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Get WiFi network configurations (regular networks, not guest).

        Returns:
            List of WiFi network dictionaries with fields:
            - SSID: Network name
            - VAPStatus: Status ("Up" or "Down")
            - BSSID: MAC address of the access point
            - MACAddress: MAC address
            - Security: Security configuration including:
              - ModeEnabled: Security mode (e.g., "WPA2-Personal")
              - KeyPassPhrase: WiFi password
            - MaxAssociatedDevices: Maximum number of devices
            - AssociatedDeviceNumberOfEntries: Current connected devices
            - EssIdentifier: Network identifier ("Primary", "Secondary")
            - BridgeInterface: Network bridge interface
            - And many other WiFi configuration fields
        """
        response = self._make_api_call(
            service="NeMo.Intf.lan",
            method="getMIBs",
            parameters={"mibs": "wlanvap", "flag": "!backhaul"},
        )

        networks = []

        # Extract WiFi networks from response
        if isinstance(response, dict) and "status" in response:
            wlanvap_data = self._status_dict(response).get("wlanvap")
            if not isinstance(wlanvap_data, dict):
                wlanvap_data = {}
            for vap_name, vap_config in wlanvap_data.items():
                if isinstance(vap_config, dict):
                    # Add the VAP name to the config for reference
                    vap_config["VAPName"] = vap_name
                    networks.append(vap_config)

        return networks

    def get_guest_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Get guest WiFi network configurations.

        Returns:
            List of guest WiFi network dictionaries with same structure as get_wifi_networks()
            but for guest networks which typically have:
            - EssIdentifier: "Guest"
            - BridgeInterface: "brguest"
            - More restrictive settings
        """
        response = self._make_api_call(
            service="NeMo.Intf.brguest",
            method="getMIBs",
            parameters={
                "mibs": "wlanvap",
                "flag": "!backhaul",
                "traverse": "one level down",
            },
        )

        networks = []

        # Extract guest WiFi networks from response
        if isinstance(response, dict) and "status" in response:
            wlanvap_data = self._status_dict(response).get("wlanvap")
            if not isinstance(wlanvap_data, dict):
                wlanvap_data = {}
            for vap_name, vap_config in wlanvap_data.items():
                if isinstance(vap_config, dict):
                    # Add the VAP name to the config for reference
                    vap_config["VAPName"] = vap_name
                    networks.append(vap_config)

        return networks

    def get_all_wifi_networks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all WiFi networks (both regular and guest).

        Returns:
            Dictionary with keys:
            - 'regular': List of regular WiFi networks
            - 'guest': List of guest WiFi networks
        """
        return {
            "regular": self.get_wifi_networks(),
            "guest": self.get_guest_wifi_networks(),
        }

    def set_wifi_config(
        self,
        ssid_2g: Optional[str] = None,
        ssid_5g: Optional[str] = None,
        password_2g: Optional[str] = None,
        password_5g: Optional[str] = None,
        security_mode_2g: Optional[str] = None,
        security_mode_5g: Optional[str] = None,
        mfp_config_2g: str = "",
        mfp_config_5g: str = "",
    ) -> bool:
        """
        Configure WiFi network settings (SSID, password, security).

        Args:
            ssid_2g: 2.4GHz network name/SSID
            ssid_5g: 5GHz network name/SSID
            password_2g: 2.4GHz network password
            password_5g: 5GHz network password
            security_mode_2g: 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            security_mode_5g: 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            mfp_config_2g: 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
            mfp_config_5g: 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")

        Returns:
            True if successful (returns {"status": null} on success)
        """
        vap_2g, vap_5g = self._private_vap_names()

        return self._set_wifi_config_internal(
            vap_2g=vap_2g,
            vap_5g=vap_5g,
            ssid_2g=ssid_2g,
            ssid_5g=ssid_5g,
            password_2g=password_2g,
            password_5g=password_5g,
            security_mode_2g=security_mode_2g,
            security_mode_5g=security_mode_5g,
            mfp_config_2g=mfp_config_2g,
            mfp_config_5g=mfp_config_5g,
            include_penable=False,
        )

    def set_wifi_visibility(
        self, visible_2g: Optional[bool] = None, visible_5g: Optional[bool] = None
    ) -> bool:
        """
        Enable or disable WiFi network visibility (SSID advertisement).

        Args:
            visible_2g: Whether 2.4GHz network should be visible (broadcast SSID)
            visible_5g: Whether 5GHz network should be visible (broadcast SSID)

        Returns:
            True if successful (returns {"status": null} on success)
        """
        vap_2g, vap_5g = self._private_vap_names()

        return self._set_wifi_visibility_internal(
            vap_2g=vap_2g, vap_5g=vap_5g, visible_2g=visible_2g, visible_5g=visible_5g
        )

    def set_wps_enabled(
        self, enabled_2g: Optional[bool] = None, enabled_5g: Optional[bool] = None
    ) -> Dict[str, bool]:
        """
        Enable or disable WPS (WiFi Protected Setup) for WiFi networks.

        Args:
            enabled_2g: Whether to enable WPS on 2.4GHz network
            enabled_5g: Whether to enable WPS on 5GHz network

        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        results = {}
        vap_2g, vap_5g = self._private_vap_names()

        # Configure 2.4GHz WPS
        if enabled_2g is not None:
            result = self._make_api_call(
                service=f"NeMo.Intf.{vap_2g}.WPS",
                method="set",
                parameters={"Enable": enabled_2g},
            )
            results["band_2g"] = self._is_true(result)

        # Configure 5GHz WPS
        if enabled_5g is not None:
            result = self._make_api_call(
                service=f"NeMo.Intf.{vap_5g}.WPS",
                method="set",
                parameters={"Enable": enabled_5g},
            )
            results["band_5g"] = self._is_true(result)

        return results

    def enable_guest_network(self, enabled: bool = True) -> bool:
        """
        Enable or disable the guest WiFi network.

        Args:
            enabled: Whether to enable guest network (default: True)

        Returns:
            True if all operations successful
        """
        # Step 1: Enable/disable guest network service
        result1 = self._make_api_call(
            service="NMC.Guest",
            method="set",
            parameters={"Enable": "1" if enabled else "0"},
        )

        # Step 2: Enable/disable 2.4GHz guest VAP
        result2 = self._make_api_call(
            service="NeMo.Intf.vap2g0guest",
            method="set",
            parameters={"PersistentEnable": enabled},
        )

        # Step 3: Enable/disable 5GHz guest VAP
        result3 = self._make_api_call(
            service="NeMo.Intf.vap5g0guest",
            method="set",
            parameters={"PersistentEnable": enabled},
        )

        return all(self._is_true(result) for result in (result1, result2, result3))

    def set_guest_wifi_config(
        self,
        ssid_2g: Optional[str] = None,
        ssid_5g: Optional[str] = None,
        password_2g: Optional[str] = None,
        password_5g: Optional[str] = None,
        security_mode_2g: Optional[str] = None,
        security_mode_5g: Optional[str] = None,
        mfp_config_2g: str = "",
        mfp_config_5g: str = "",
    ) -> bool:
        """
        Configure guest WiFi network settings (SSID, password, security).

        Args:
            ssid_2g: 2.4GHz guest network name/SSID
            ssid_5g: 5GHz guest network name/SSID
            password_2g: 2.4GHz guest network password
            password_5g: 5GHz guest network password
            security_mode_2g: 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            security_mode_5g: 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            mfp_config_2g: 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
            mfp_config_5g: 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")

        Returns:
            True if successful (returns {"status": null} on success)
        """
        return self._set_wifi_config_internal(
            vap_2g="vap2g0guest",
            vap_5g="vap5g0guest",
            ssid_2g=ssid_2g,
            ssid_5g=ssid_5g,
            password_2g=password_2g,
            password_5g=password_5g,
            security_mode_2g=security_mode_2g,
            security_mode_5g=security_mode_5g,
            mfp_config_2g=mfp_config_2g,
            mfp_config_5g=mfp_config_5g,
            include_penable=True,
        )

    def set_guest_wifi_visibility(
        self, visible_2g: Optional[bool] = None, visible_5g: Optional[bool] = None
    ) -> bool:
        """
        Enable or disable guest WiFi network visibility (SSID advertisement).

        Args:
            visible_2g: Whether 2.4GHz guest network should be visible (broadcast SSID)
            visible_5g: Whether 5GHz guest network should be visible (broadcast SSID)

        Returns:
            True if successful (returns {"status": null} on success)
        """
        return self._set_wifi_visibility_internal(
            vap_2g="vap2g0guest",
            vap_5g="vap5g0guest",
            visible_2g=visible_2g,
            visible_5g=visible_5g,
        )

    def set_guest_bandwidth_limit(self, limit_mbps: int = 0) -> bool:
        """
        Set bandwidth limitation for guest network.

        Args:
            limit_mbps: Bandwidth limit in Mbps (0 = unlimited, max 50000 = 50 Gbps)

        Returns:
            True if successful (returns {"status": true} on success)
        """
        if limit_mbps < 0 or limit_mbps > 50000:
            raise ValueError("Bandwidth limit must be between 0 and 50000 Mbps")

        result = self._make_api_call(
            service="NMC.Guest",
            method="set",
            parameters={"BandwidthLimitation": limit_mbps},
        )

        return self._is_true(result)

    def _set_wifi_config_internal(
        self,
        vap_2g: str,
        vap_5g: str,
        ssid_2g: Optional[str] = None,
        ssid_5g: Optional[str] = None,
        password_2g: Optional[str] = None,
        password_5g: Optional[str] = None,
        security_mode_2g: Optional[str] = None,
        security_mode_5g: Optional[str] = None,
        mfp_config_2g: str = "",
        mfp_config_5g: str = "",
        include_penable: bool = False,
    ) -> bool:
        """
        Internal method for WiFi configuration shared by regular/guest/extra networks.

        Args:
            vap_2g: 2.4GHz VAP name (e.g., "vap2g0priv", "vap2g0guest", "vap2g0ext")
            vap_5g: 5GHz VAP name (e.g., "vap5g0priv", "vap5g0guest", "vap5g0ext")
            include_penable: Whether to include penable section (needed for guest networks)
            ... other parameters same as public methods
        """
        # Build configuration parameters
        wlanvap_config = {}
        penable_config = {}

        # Configure 2.4GHz network
        if any([ssid_2g, password_2g, security_mode_2g, mfp_config_2g]):
            config_2g: Dict[str, Any] = {}

            if ssid_2g is not None:
                config_2g["SSID"] = ssid_2g

            if any([password_2g, security_mode_2g, mfp_config_2g]):
                security_config = {}
                if password_2g is not None:
                    security_config["KeyPassPhrase"] = password_2g
                if security_mode_2g is not None:
                    security_config["ModeEnabled"] = security_mode_2g
                if mfp_config_2g is not None:
                    security_config["MFPConfig"] = mfp_config_2g

                config_2g["Security"] = security_config

            wlanvap_config[vap_2g] = config_2g
            if include_penable:
                penable_config[vap_2g] = {
                    "Enable": "",
                    "PersistentEnable": "",
                    "Status": "",
                }

        # Configure 5GHz network
        if any([ssid_5g, password_5g, security_mode_5g, mfp_config_5g]):
            config_5g: Dict[str, Any] = {}

            if ssid_5g is not None:
                config_5g["SSID"] = ssid_5g

            if any([password_5g, security_mode_5g, mfp_config_5g]):
                security_config = {}
                if password_5g is not None:
                    security_config["KeyPassPhrase"] = password_5g
                if security_mode_5g is not None:
                    security_config["ModeEnabled"] = security_mode_5g
                if mfp_config_5g is not None:
                    security_config["MFPConfig"] = mfp_config_5g

                config_5g["Security"] = security_config

            wlanvap_config[vap_5g] = config_5g
            if include_penable:
                penable_config[vap_5g] = {
                    "Enable": "",
                    "PersistentEnable": "",
                    "Status": "",
                }

        if not wlanvap_config:
            return True

        # Build the complete parameters
        parameters: Dict[str, Dict[str, Any]] = {"mibs": {}}
        if include_penable and penable_config:
            parameters["mibs"]["penable"] = penable_config
        if wlanvap_config:
            parameters["mibs"]["wlanvap"] = wlanvap_config

        result = self._make_api_call(
            service="NeMo.Intf.lan", method="setWLANConfig", parameters=parameters
        )

        return self._succeeded(result)

    def _set_wifi_visibility_internal(
        self,
        vap_2g: str,
        vap_5g: str,
        visible_2g: Optional[bool] = None,
        visible_5g: Optional[bool] = None,
    ) -> bool:
        """
        Internal method for WiFi visibility shared by regular/guest/extra networks.

        Args:
            vap_2g: 2.4GHz VAP name (e.g., "vap2g0priv", "vap2g0guest", "vap2g0ext")
            vap_5g: 5GHz VAP name (e.g., "vap5g0priv", "vap5g0guest", "vap5g0ext")
            visible_2g: Whether 2.4GHz network should be visible
            visible_5g: Whether 5GHz network should be visible
        """
        if visible_2g is None and visible_5g is None:
            return True

        wlanvap_config = {}

        if visible_2g is not None:
            wlanvap_config[vap_2g] = {"SSIDAdvertisementEnabled": visible_2g}

        if visible_5g is not None:
            wlanvap_config[vap_5g] = {"SSIDAdvertisementEnabled": visible_5g}

        result = self._make_api_call(
            service="NeMo.Intf.lan",
            method="setWLANConfig",
            parameters={"mibs": {"wlanvap": wlanvap_config}},
        )

        return self._succeeded(result)

    def enable_extra_wifi(
        self, enabled_2g: Optional[bool] = None, enabled_5g: Optional[bool] = None
    ) -> Dict[str, bool]:
        """
        Enable or disable extra WiFi networks.

        Args:
            enabled_2g: Whether to enable 2.4GHz extra network
            enabled_5g: Whether to enable 5GHz extra network

        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        results = {}

        # Enable/disable 2.4GHz extra WiFi
        if enabled_2g is not None:
            result = self._make_api_call(
                service="NeMo.Intf.vap2g0ext",
                method="set",
                parameters={"PersistentEnable": enabled_2g},
            )
            results["band_2g"] = self._is_true(result)

        # Enable/disable 5GHz extra WiFi
        if enabled_5g is not None:
            result = self._make_api_call(
                service="NeMo.Intf.vap5g0ext",
                method="set",
                parameters={"PersistentEnable": enabled_5g},
            )
            results["band_5g"] = self._is_true(result)

        return results

    def set_extra_wifi_config(
        self,
        ssid_2g: Optional[str] = None,
        ssid_5g: Optional[str] = None,
        password_2g: Optional[str] = None,
        password_5g: Optional[str] = None,
        security_mode_2g: Optional[str] = None,
        security_mode_5g: Optional[str] = None,
        mfp_config_2g: str = "",
        mfp_config_5g: str = "",
    ) -> bool:
        """
        Configure extra WiFi network settings (SSID, password, security).

        Args:
            ssid_2g: 2.4GHz extra network name/SSID
            ssid_5g: 5GHz extra network name/SSID
            password_2g: 2.4GHz extra network password
            password_5g: 5GHz extra network password
            security_mode_2g: 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            security_mode_5g: 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            mfp_config_2g: 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
            mfp_config_5g: 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")

        Returns:
            True if successful
        """
        return self._set_wifi_config_internal(
            vap_2g="vap2g0ext",
            vap_5g="vap5g0ext",
            ssid_2g=ssid_2g,
            ssid_5g=ssid_5g,
            password_2g=password_2g,
            password_5g=password_5g,
            security_mode_2g=security_mode_2g,
            security_mode_5g=security_mode_5g,
            mfp_config_2g=mfp_config_2g,
            mfp_config_5g=mfp_config_5g,
            include_penable=False,
        )

    def set_extra_wifi_visibility(
        self, visible_2g: Optional[bool] = None, visible_5g: Optional[bool] = None
    ) -> bool:
        """
        Enable or disable extra WiFi network visibility (SSID advertisement).

        Args:
            visible_2g: Whether 2.4GHz extra network should be visible (broadcast SSID)
            visible_5g: Whether 5GHz extra network should be visible (broadcast SSID)

        Returns:
            True if successful
        """
        return self._set_wifi_visibility_internal(
            vap_2g="vap2g0ext",
            vap_5g="vap5g0ext",
            visible_2g=visible_2g,
            visible_5g=visible_5g,
        )

    def get_wifi_status(self) -> Dict[str, Any]:
        """
        Get overall WiFi status and configuration.

        Returns:
            Dictionary with WiFi status including:
            - Enable: Whether WiFi is globally enabled
            - Status: Current WiFi status
            - Various WiFi configuration fields
        """
        response = self._make_api_call(service="NMC.Wifi", method="get", parameters={})

        return self._status_dict(response)

    def set_wifi_enabled(
        self, enabled: bool = True, sync_extenders: bool = True
    ) -> bool:
        """
        Enable or disable WiFi radios completely.

        Args:
            enabled: Whether to enable WiFi (default: True)
            sync_extenders: Whether to keep WiFi on extenders enabled (default: True)

        Returns:
            True if all operations successful
        """
        success_count = 0
        total_operations = 6 if sync_extenders else 5

        # Enable/disable overall WiFi
        result1 = self._make_api_call(
            service="NMC.Wifi", method="set", parameters={"Enable": enabled}
        )
        if self._is_true(result1):
            success_count += 1

        # Enable/disable 2.4GHz radio
        result2 = self._make_api_call(
            service="NeMo.Intf.rad2g0", method="set", parameters={"Enable": enabled}
        )
        if self._is_true(result2):
            success_count += 1

        # Enable/disable 5GHz radio
        result3 = self._make_api_call(
            service="NeMo.Intf.rad5g0", method="set", parameters={"Enable": enabled}
        )
        if self._is_true(result3):
            success_count += 1

        # Enable/disable main 2.4GHz network
        result4 = self._make_api_call(
            service="NeMo.Intf.vap2g0priv",
            method="set",
            parameters={"PersistentEnable": enabled},
        )
        if self._is_true(result4):
            success_count += 1

        # Enable/disable main 5GHz network
        result5 = self._make_api_call(
            service="NeMo.Intf.vap5g0priv",
            method="set",
            parameters={"PersistentEnable": enabled},
        )
        if self._is_true(result5):
            success_count += 1

        # Optionally sync with extenders
        if sync_extenders:
            result6 = self._make_api_call(
                service="SSW.Steering.MasterConfig",
                method="set",
                parameters={"SyncEnableField": True},
            )
            if self._is_true(result6):
                success_count += 1

        return success_count == total_operations

    def set_wifi_radio_config(
        self,
        band_2g_config: Optional[Dict[str, Any]] = None,
        band_5g_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, bool]:
        """
        Configure WiFi radio settings for 2.4GHz and/or 5GHz bands.

        Args:
            band_2g_config: 2.4GHz radio configuration dictionary with keys:
                - AutoChannelEnable: Whether to enable auto channel selection (bool)
                - OperatingChannelBandwidth: Channel bandwidth ("20MHz", "40MHz")
                - OperatingStandards: Supported standards (e.g., "g,n,ax")
            band_5g_config: 5GHz radio configuration dictionary with keys:
                - AutoChannelEnable: Whether to enable auto channel selection (bool)
                - OperatingChannelBandwidth: Channel bandwidth ("20MHz", "40MHz", "80MHz", "160MHz")
                - OperatingStandards: Supported standards (e.g., "a,n,ac,ax")

        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        results = {}

        # Configure 2.4GHz radio
        if band_2g_config is not None:
            result = self._make_api_call(
                service="NeMo.Intf.rad2g0",
                method="setWLANConfig",
                parameters={"mibs": {"wlanradio": {"rad2g0": band_2g_config}}},
            )
            results["band_2g"] = self._succeeded(result)

        # Configure 5GHz radio
        if band_5g_config is not None:
            result = self._make_api_call(
                service="NeMo.Intf.rad5g0",
                method="setWLANConfig",
                parameters={"mibs": {"wlanradio": {"rad5g0": band_5g_config}}},
            )
            results["band_5g"] = self._succeeded(result)

        return results

    def set_wifi_radio_defaults(self) -> Dict[str, bool]:
        """
        Set WiFi radio configuration to recommended defaults.

        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        return self.set_wifi_radio_config(
            band_2g_config={
                "AutoChannelEnable": True,
                "OperatingChannelBandwidth": "20MHz",
                "OperatingStandards": "g,n,ax",
            },
            band_5g_config={
                "AutoChannelEnable": True,
                "OperatingChannelBandwidth": "80MHz",
                "OperatingStandards": "a,n,ac,ax",
            },
        )

    def enable_wifi_schedule(
        self, network_id: str = "wl0", enabled: bool = True
    ) -> bool:
        """
        Enable or disable WiFi time scheduling.

        Args:
            network_id: WiFi network identifier (default: "wl0")
            enabled: Whether to enable scheduling (default: True)

        Returns:
            True if successful
        """
        result = self._make_api_call(
            service="Scheduler",
            method="enableSchedule",
            parameters={"type": "WLAN", "ID": network_id, "enable": enabled},
        )

        return self._is_true(result)

    def set_wifi_schedule(
        self,
        network_id: str = "wl0",
        disable_blocks: Optional[List[Dict[str, int]]] = None,
        enabled: bool = True,
    ) -> bool:
        """
        Set WiFi time schedule with specific disable periods.

        Args:
            network_id: WiFi network identifier (default: "wl0")
            disable_blocks: List of time blocks when WiFi should be disabled.
                           Each block is a dict with 'begin' and 'end' keys (seconds from Monday 00:00)
            enabled: Whether the schedule should be enabled (default: True)

        Returns:
            True if successful

        Example:
            # Disable WiFi from 10 PM to 6 AM on weekdays
            api.set_wifi_schedule(disable_blocks=[
                {"begin": 79200, "end": 108000},  # Monday 22:00-06:00+1
                {"begin": 165600, "end": 194400}, # Tuesday 22:00-06:00+1
                # ... more days
            ])
        """
        if disable_blocks is None:
            disable_blocks = []

        # Convert disable blocks to schedule format
        schedule = []
        for block in disable_blocks:
            schedule.append(
                {"state": "Disable", "begin": block["begin"], "end": block["end"]}
            )

        schedule_info = {
            "base": "Weekly",
            "def": "Enable",  # Default state is enabled
            "ID": network_id,
            "schedule": schedule,
            "enable": enabled,
            "override": "",
        }

        result = self._make_api_call(
            service="Scheduler",
            method="addSchedule",
            parameters={"type": "WLAN", "info": schedule_info},
        )

        return self._is_true(result)

    def set_wifi_bedtime_schedule(
        self,
        network_id: str = "wl0",
        bedtime_hour: int = 22,
        wakeup_hour: int = 6,
        weekdays_only: bool = True,
    ) -> bool:
        """
        Set a simple bedtime WiFi schedule (disable during night hours).

        Args:
            network_id: WiFi network identifier (default: "wl0")
            bedtime_hour: Hour to disable WiFi (0-23, default: 22 = 10 PM)
            wakeup_hour: Hour to enable WiFi (0-23, default: 6 = 6 AM)
            weekdays_only: Whether to apply only on weekdays (default: True)

        Returns:
            True if successful
        """
        validate_hours(bedtime_hour, wakeup_hour)

        days = range(5) if weekdays_only else range(7)  # 0 = Monday
        disable_blocks = bedtime_blocks(bedtime_hour, wakeup_hour, days)

        return self.set_wifi_schedule(network_id, disable_blocks, enabled=True)

    def clear_wifi_schedule(self, network_id: str = "wl0") -> bool:
        """
        Clear WiFi schedule (remove all time restrictions).

        Args:
            network_id: WiFi network identifier (default: "wl0")

        Returns:
            True if successful
        """
        # Set empty schedule (WiFi always enabled)
        return self.set_wifi_schedule(network_id, disable_blocks=[], enabled=False)

    def get_wifi_radio_info(self, band: str = "2g") -> Dict[str, Any]:
        """
        Get detailed WiFi radio information for a specific band.

        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")

        Returns:
            Dictionary with comprehensive radio information including:
            - Name: Radio name (e.g., "rad2g0", "rad5g0")
            - Enable: Whether radio is enabled
            - Status: Current radio status
            - RadioStatus: Radio operational status ("Up", "Down")
            - OperatingFrequencyBand: Current frequency band ("2.4GHz", "5GHz")
            - CurrentOperatingChannelBandwidth: Current channel bandwidth (e.g., "20MHz", "80MHz")
            - MaxChannelBandwidth: Maximum supported bandwidth (e.g., "40MHz", "160MHz")
            - SupportedStandards: Supported WiFi standards (e.g., "a,b,g,n,ax")
            - OperatingStandards: Currently enabled standards
            - Channel: Current operating channel
            - ChannelsInUse: Channels currently in use (for 80MHz/160MHz)
            - AutoChannelEnable: Whether auto channel selection is enabled
            - AutoBandwidthEnable: Whether auto bandwidth selection is enabled
            - ChannelLoad: Current channel load percentage (0-100)
            - Interference: Interference level percentage
            - Noise: Noise level in dBm
            - TransmitPower: Transmit power setting (-1 = auto)
            - MaxAssociatedDevices: Maximum allowed connected devices
            - ActiveAssociatedDevices: Currently connected devices
            - BeaconPeriod: Beacon transmission interval (milliseconds)
            - DTIMPeriod: DTIM period
            - OfdmaEnable: Whether OFDMA is enabled
            - MultiUserMIMOEnabled: Whether MU-MIMO is enabled
            - ImplicitBeamFormingEnabled: Whether implicit beamforming is enabled
            - ExplicitBeamFormingEnabled: Whether explicit beamforming is enabled
            - IEEE80211hEnabled: Whether 802.11h (DFS) is enabled
            - IEEE80211rSupported: Whether 802.11r (fast roaming) is supported
            - IEEE80211kSupported: Whether 802.11k (neighbor reports) is supported
            - RegulatoryDomain: Regulatory domain (e.g., "NL")
            - And many other detailed radio configuration fields

        Raises:
            ValueError: If band is not "2g" or "5g"
        """
        if band not in ["2g", "5g"]:
            raise ValueError("band must be '2g' or '5g'")

        radio_name = f"rad{band}0"

        response = self._make_api_call(
            service=f"NeMo.Intf.{radio_name}", method="get", parameters={}
        )

        return self._status_dict(response)

    def get_wifi_spectrum_info(
        self, band: str = "2g", update: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get WiFi spectrum analysis information for a specific band.

        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")
            update: Whether to update spectrum data before returning (default: True)

        Returns:
            List of channel analysis dictionaries with fields:
            - channel: Channel number (e.g., 1-13 for 2.4GHz, 36-140 for 5GHz)
            - bandwidth: Channel bandwidth in MHz (typically 20)
            - isBanned: Whether channel is banned/restricted
            - Bonus: Channel bonus score for selection
            - availability: Channel availability percentage (0-100, higher = less congested)
            - ourUsage: Our own usage on this channel (0-100)
            - noiselevel: Background noise level in dBm
            - accesspoints: Number of other access points detected on this channel

        Raises:
            ValueError: If band is not "2g" or "5g"

        Note:
            Higher availability percentages indicate less congested channels.
            Lower noise levels (more negative dBm) indicate cleaner channels.
            Fewer access points indicate less competition for the channel.
        """
        if band not in ["2g", "5g"]:
            raise ValueError("band must be '2g' or '5g'")

        radio_name = f"rad{band}0"

        response = self._make_api_call(
            service=f"NeMo.Intf.{radio_name}",
            method="getSpectrumInfo",
            parameters={"update": update},
        )

        return self._status_list(response)

    def get_wifi_scan_results(self, band: str = "2g") -> List[Dict[str, Any]]:
        """
        Get WiFi scan results showing all detected networks in a specific band.

        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")

        Returns:
            List of detected network dictionaries with fields:
            - SSID: Network name (may be empty for hidden networks)
            - BSSID: MAC address of the access point
            - SignalNoiseRatio: Signal-to-noise ratio
            - Noise: Noise level in dBm
            - RSSI: Received Signal Strength Indicator in dBm
            - Channel: WiFi channel number
            - CentreChannel: Center channel for wide channels
            - Bandwidth: Channel bandwidth in MHz (20, 40, 80, 160)
            - SignalStrength: Signal strength in dBm (same as RSSI)
            - SecurityModeEnabled: Security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            - MFPConfig: Management Frame Protection configuration
            - WPSConfigMethodsSupported: Supported WPS methods
            - EncryptionMode: Encryption type (e.g., "AES")
            - OperatingStandards: Supported WiFi standards (e.g., "a,n,ac,ax")
            - VendorIEs: Vendor-specific information elements

        Raises:
            ValueError: If band is not "2g" or "5g"

        Note:
            Hidden networks will have empty SSID but still show other information.
            Signal strength values are in dBm (higher/less negative = stronger signal).
        """
        if band not in ["2g", "5g"]:
            raise ValueError("band must be '2g' or '5g'")

        radio_name = f"rad{band}0"

        response = self._make_api_call(
            service=f"NeMo.Intf.{radio_name}", method="getScanResults", parameters={}
        )

        return self._status_list(response)

    def get_all_wifi_radio_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get WiFi radio information for both 2.4GHz and 5GHz bands.

        Returns:
            Dictionary with keys:
            - 'band_2g': 2.4GHz radio information
            - 'band_5g': 5GHz radio information
        """
        return {
            "band_2g": self.get_wifi_radio_info("2g"),
            "band_5g": self.get_wifi_radio_info("5g"),
        }

    def get_all_wifi_spectrum_info(
        self, update: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get WiFi spectrum analysis for both 2.4GHz and 5GHz bands.

        Args:
            update: Whether to update spectrum data before returning (default: True)

        Returns:
            Dictionary with keys:
            - 'band_2g': 2.4GHz spectrum analysis
            - 'band_5g': 5GHz spectrum analysis
        """
        return {
            "band_2g": self.get_wifi_spectrum_info("2g", update),
            "band_5g": self.get_wifi_spectrum_info("5g", update),
        }

    def get_all_wifi_scan_results(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get WiFi scan results for both 2.4GHz and 5GHz bands.

        Returns:
            Dictionary with keys:
            - 'band_2g': 2.4GHz scan results
            - 'band_5g': 5GHz scan results
        """
        return {
            "band_2g": self.get_wifi_scan_results("2g"),
            "band_5g": self.get_wifi_scan_results("5g"),
        }

    def get_best_wifi_channels(
        self, band: str = "2g", top_n: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Get the best WiFi channels based on availability and interference.

        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")
            top_n: Number of top channels to return (default: 3)

        Returns:
            List of best channel dictionaries sorted by score, with additional fields:
            - score: Calculated channel score (higher = better)
            - congestion_level: Text description of congestion ("Low", "Medium", "High")
            - recommendation: Text recommendation for this channel
            Plus all original spectrum info fields

        Raises:
            ValueError: If band is not "2g" or "5g"
        """
        spectrum_data = self.get_wifi_spectrum_info(band)

        if not spectrum_data:
            return []

        # Calculate scores and add analysis
        scored_channels = []
        for channel_info in spectrum_data:
            # Calculate a score based on availability, noise, and access point count
            availability = channel_info.get("availability", 0)
            noise_level = channel_info.get("noiselevel", -50)  # dBm
            access_points = channel_info.get("accesspoints", 0)

            # Score calculation (0-100):
            # - High availability is good
            # - Low noise is good (more negative dBm)
            # - Fewer access points is good
            # - Our own usage doesn't count against the channel
            score = availability
            score += (
                max(0, (noise_level + 100)) * 0.5
            )  # Noise bonus (better for lower noise)
            score -= access_points * 5  # Penalty for each access point
            score = max(0, min(100, score))  # Clamp to 0-100

            # Determine congestion level
            if availability > 80 and access_points <= 1:
                congestion_level = "Low"
                recommendation = "Excellent choice - low congestion"
            elif availability > 60 and access_points <= 3:
                congestion_level = "Medium"
                recommendation = "Good choice - moderate usage"
            else:
                congestion_level = "High"
                recommendation = "Avoid if possible - high congestion"

            # Create enhanced channel info
            enhanced_info = channel_info.copy()
            enhanced_info.update(
                {
                    "score": round(score, 1),
                    "congestion_level": congestion_level,
                    "recommendation": recommendation,
                }
            )

            scored_channels.append(enhanced_info)

        # Sort by score (highest first) and return top N
        scored_channels.sort(key=lambda x: x["score"], reverse=True)
        return scored_channels[:top_n]

    def analyze_wifi_environment(self) -> Dict[str, Any]:
        """
        Perform comprehensive WiFi environment analysis for both bands.

        Returns:
            Dictionary with comprehensive WiFi analysis including:
            - summary: Overall environment summary
            - band_2g: 2.4GHz analysis with radio info, spectrum data, best channels
            - band_5g: 5GHz analysis with radio info, spectrum data, best channels
            - recommendations: List of optimization recommendations
            - total_networks: Total number of detected networks across both bands
        """
        # Get data for both bands
        radio_2g = self.get_wifi_radio_info("2g")
        radio_5g = self.get_wifi_radio_info("5g")
        spectrum_2g = self.get_wifi_spectrum_info("2g")
        spectrum_5g = self.get_wifi_spectrum_info("5g")
        scan_2g = self.get_wifi_scan_results("2g")
        scan_5g = self.get_wifi_scan_results("5g")
        best_2g = self.get_best_wifi_channels("2g", 3)
        best_5g = self.get_best_wifi_channels("5g", 3)

        # Count total networks
        total_networks_2g = len([n for n in scan_2g if n.get("SSID", "").strip()])
        total_networks_5g = len([n for n in scan_5g if n.get("SSID", "").strip()])
        total_networks = total_networks_2g + total_networks_5g

        # Analyze current channel usage
        current_channel_2g = radio_2g.get("Channel", 0)
        current_channel_5g = radio_5g.get("Channel", 0)

        current_2g_info = next(
            (ch for ch in spectrum_2g if ch.get("channel") == current_channel_2g), {}
        )
        current_5g_info = next(
            (ch for ch in spectrum_5g if ch.get("channel") == current_channel_5g), {}
        )

        # Generate recommendations
        recommendations = []

        if current_2g_info.get("availability", 100) < 50:
            best_2g_channel = best_2g[0]["channel"] if best_2g else None
            if best_2g_channel and best_2g_channel != current_channel_2g:
                recommendations.append(
                    f"Consider switching 2.4GHz from channel {current_channel_2g} to {best_2g_channel}"
                )

        if current_5g_info.get("availability", 100) < 70:
            best_5g_channel = best_5g[0]["channel"] if best_5g else None
            if best_5g_channel and best_5g_channel != current_channel_5g:
                recommendations.append(
                    f"Consider switching 5GHz from channel {current_channel_5g} to {best_5g_channel}"
                )

        if total_networks > 20:
            recommendations.append(
                "High WiFi density detected - consider using 5GHz for better performance"
            )

        if radio_2g.get("CurrentOperatingChannelBandwidth") == "40MHz":
            recommendations.append(
                "Consider using 20MHz bandwidth on 2.4GHz to reduce interference"
            )

        # Generate summary
        if total_networks < 10:
            environment = "Light"
        elif total_networks < 25:
            environment = "Moderate"
        else:
            environment = "Congested"

        summary = (
            f"{environment} WiFi environment with {total_networks} networks detected"
        )

        return {
            "summary": summary,
            "band_2g": {
                "radio_info": radio_2g,
                "spectrum_analysis": spectrum_2g,
                "scan_results": scan_2g,
                "best_channels": best_2g,
                "current_channel": current_channel_2g,
                "current_channel_info": current_2g_info,
                "networks_detected": total_networks_2g,
            },
            "band_5g": {
                "radio_info": radio_5g,
                "spectrum_analysis": spectrum_5g,
                "scan_results": scan_5g,
                "best_channels": best_5g,
                "current_channel": current_channel_5g,
                "current_channel_info": current_5g_info,
                "networks_detected": total_networks_5g,
            },
            "recommendations": recommendations,
            "total_networks": total_networks,
        }

    def get_wifi_mac_filter_status(self) -> Dict[str, Any]:
        """
        Get WiFi MAC filtering status and current whitelist.

        Returns:
            Dictionary with MAC filtering status including:
            - enabled: Whether MAC filtering is enabled
            - mode: Current filtering mode ("WhiteList" or "Off")
            - allowed_devices: List of MAC addresses on whitelist
            - count: Number of devices on whitelist

        Note:
            MAC filtering only affects home and extra WiFi networks.
            Guest networks and wired devices are not affected.
        """
        # Get current WiFi configuration
        wifi_networks = self.get_wifi_networks()

        status: Dict[str, Any] = {
            "enabled": False,
            "mode": "Off",
            "allowed_devices": [],
            "count": 0,
        }

        # Check 2.4GHz home network for MAC filtering status
        for network in wifi_networks:
            if network.get("Name") == "vap2g0priv":
                mac_filtering = network.get("MACFiltering", {})
                status["mode"] = mac_filtering.get("Mode", "Off")
                status["enabled"] = status["mode"] == "WhiteList"

                # Extract MAC addresses from entries
                entries = mac_filtering.get("Entry", {})
                if isinstance(entries, dict):
                    for entry in entries.values():
                        if isinstance(entry, dict) and "MACAddress" in entry:
                            mac_addr = entry["MACAddress"]
                            if mac_addr not in status["allowed_devices"]:
                                status["allowed_devices"].append(mac_addr)

                break

        status["count"] = len(status["allowed_devices"])
        return status

    def set_wifi_mac_filtering(
        self, enabled: bool = True, mac_addresses: Optional[List[str]] = None
    ) -> bool:
        """
        Enable or disable WiFi MAC filtering with optional device list.

        Args:
            enabled: Whether to enable MAC filtering (default: True)
            mac_addresses: List of MAC addresses to allow (default: None = keep current list)

        Returns:
            True if successful

        Note:
            - When enabled, only devices on the whitelist can connect to WiFi
            - Affects home and extra networks only (not guest networks)
            - Wired devices are always allowed regardless of this setting
            - If mac_addresses is None, keeps current whitelist
        """
        # Get current MAC filter list if not provided
        if mac_addresses is None:
            current_status = self.get_wifi_mac_filter_status()
            mac_addresses = current_status.get("allowed_devices", [])

        # Create entry dictionary from MAC addresses
        entry_dict = {}
        for i, mac_addr in enumerate(mac_addresses, 1):
            entry_dict[str(i)] = {"MACAddress": mac_addr}

        # Set mode based on enabled flag
        mode = "WhiteList" if enabled else "Off"

        # Configure MAC filtering for all relevant VAPs
        result = self._make_api_call(
            service="NeMo.Intf.lan",
            method="setWLANConfig",
            parameters={
                "mibs": {
                    "wlanvap": {
                        "vap2g0priv": {
                            "MACFiltering": {"Mode": mode, "Entry": entry_dict}
                        },
                        "vap5g0priv": {
                            "MACFiltering": {"Mode": mode, "Entry": entry_dict}
                        },
                        "vap2g0ext": {
                            "MACFiltering": {"Mode": mode, "Entry": entry_dict}
                        },
                        "vap5g0ext": {
                            "MACFiltering": {"Mode": mode, "Entry": entry_dict}
                        },
                    }
                }
            },
        )

        return self._succeeded(result)  # API returns null on success

    def enable_wifi_mac_filtering(
        self, mac_addresses: Optional[List[str]] = None
    ) -> bool:
        """
        Enable WiFi MAC filtering with optional device list.

        Args:
            mac_addresses: List of MAC addresses to allow (default: None = keep current list)

        Returns:
            True if successful

        Note: Convenience method that calls set_wifi_mac_filtering(True, mac_addresses).
        """
        return self.set_wifi_mac_filtering(True, mac_addresses)

    def disable_wifi_mac_filtering(self) -> bool:
        """
        Disable WiFi MAC filtering (allow all devices).

        Returns:
            True if successful

        Note:
            - Convenience method that calls set_wifi_mac_filtering(False)
            - Keeps the current whitelist for when filtering is re-enabled
        """
        return self.set_wifi_mac_filtering(False)

    def get_wifi_mac_filter_list(self) -> List[str]:
        """
        Get list of MAC addresses on WiFi whitelist.

        Returns:
            List of MAC addresses currently on the whitelist
        """
        status = self.get_wifi_mac_filter_status()
        return status.get("allowed_devices", [])

    def add_wifi_mac_filter(self, mac_addresses: Union[str, List[str]]) -> bool:
        """
        Add MAC addresses to WiFi whitelist.

        Args:
            mac_addresses: Single MAC address (str) or list of MAC addresses to add

        Returns:
            True if successful

        Note:
            - Automatically enables MAC filtering if not already enabled
            - Avoids duplicates when adding addresses
        """
        # Convert single MAC address to list
        if isinstance(mac_addresses, str):
            mac_addresses = [mac_addresses]

        # Get current whitelist
        current_list = self.get_wifi_mac_filter_list()

        # Add new MAC addresses (avoid duplicates)
        updated_list = current_list.copy()
        for mac_addr in mac_addresses:
            if mac_addr not in updated_list:
                updated_list.append(mac_addr)

        # Enable filtering with updated list
        return self.set_wifi_mac_filtering(True, updated_list)

    def remove_wifi_mac_filter(self, mac_addresses: Union[str, List[str]]) -> bool:
        """
        Remove MAC addresses from WiFi whitelist.

        Args:
            mac_addresses: Single MAC address (str) or list of MAC addresses to remove

        Returns:
            True if successful

        Note: Keeps MAC filtering enabled even if list becomes empty.
        """
        # Convert single MAC address to list
        if isinstance(mac_addresses, str):
            mac_addresses = [mac_addresses]

        # Get current whitelist
        current_list = self.get_wifi_mac_filter_list()

        # Remove specified MAC addresses
        updated_list = [mac for mac in current_list if mac not in mac_addresses]

        # Get current filtering state
        current_status = self.get_wifi_mac_filter_status()
        is_enabled = current_status.get("enabled", False)

        # Update with new list, keeping current enabled state
        return self.set_wifi_mac_filtering(is_enabled, updated_list)

    def clear_wifi_mac_filter(self) -> bool:
        """
        Clear all MAC addresses from WiFi whitelist.

        Returns:
            True if successful

        Note: Keeps MAC filtering enabled but with empty whitelist (blocks all WiFi devices).
        """
        return self.set_wifi_mac_filtering(True, [])

    def set_wifi_mac_filter_list(
        self, mac_addresses: List[str], enabled: bool = True
    ) -> bool:
        """
        Set complete WiFi MAC filter whitelist.

        Args:
            mac_addresses: Complete list of MAC addresses to allow
            enabled: Whether to enable MAC filtering (default: True)

        Returns:
            True if successful

        Note: Replaces entire whitelist with provided list.
        """
        return self.set_wifi_mac_filtering(enabled, mac_addresses)

    def add_connected_wifi_devices_to_filter(self) -> Dict[str, Any]:
        """
        Add all currently connected WiFi devices to MAC filter whitelist.

        Returns:
            Dictionary with operation results including:
            - added_devices: List of devices added to whitelist
            - already_allowed: List of devices already on whitelist
            - total_devices: Total number of WiFi devices found
            - success: Whether operation was successful

        Note:
            - Only adds WiFi-connected devices (excludes wired devices)
            - Automatically enables MAC filtering
            - Useful for quickly allowing all current WiFi devices
        """
        # Get all connected devices
        devices = self.get_devices("active")

        # Filter for WiFi devices only (exclude ETH0 = wired)
        wifi_devices = []
        for device in devices:
            interface = device.get("Layer2Interface", "")
            if interface and interface != "ETH0":  # ETH0 is wired
                wifi_devices.append(
                    {
                        "mac_address": device.get("PhysAddress", ""),
                        "name": device.get("Name", "Unknown"),
                        "interface": interface,
                    }
                )

        # Get current whitelist
        current_list = self.get_wifi_mac_filter_list()

        # Determine which devices to add
        added_devices = []
        already_allowed = []

        for device in wifi_devices:
            mac_addr = device["mac_address"]
            if mac_addr:
                if mac_addr in current_list:
                    already_allowed.append(device)
                else:
                    added_devices.append(device)
                    current_list.append(mac_addr)

        # Update MAC filter with new list
        success = self.set_wifi_mac_filtering(True, current_list)

        return {
            "added_devices": added_devices,
            "already_allowed": already_allowed,
            "total_devices": len(wifi_devices),
            "success": success,
        }

    def manage_wifi_mac_filter(
        self,
        action: str,
        mac_addresses: Optional[Union[str, List[str]]] = None,
        enabled: Optional[bool] = None,
    ) -> Union[bool, Dict[str, Any], List[str]]:
        """
        Unified WiFi MAC filter management interface.

        Args:
            action: Action to perform - "enable", "disable", "add", "remove", "clear",
                   "set", "list", "status", "add_connected"
            mac_addresses: MAC addresses for add/remove/set actions
            enabled: Enable state for "set" action

        Returns:
            - For enable/disable/add/remove/clear/set: True if successful
            - For list: List of MAC addresses
            - For status: Dictionary with status information
            - For add_connected: Dictionary with operation results

        Raises:
            ValueError: If action is not valid or required parameters are missing

        Examples:
            # Enable filtering
            api.manage_wifi_mac_filter("enable")

            # Add device
            api.manage_wifi_mac_filter("add", "AA:BB:CC:DD:EE:FF")

            # Set complete list
            api.manage_wifi_mac_filter("set", ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"])

            # Get status
            status = api.manage_wifi_mac_filter("status")
        """
        if isinstance(mac_addresses, str):
            mac_addresses = [mac_addresses]

        if action == "enable":
            return self.enable_wifi_mac_filtering(mac_addresses)

        elif action == "disable":
            return self.disable_wifi_mac_filtering()

        elif action == "add":
            if mac_addresses is None:
                raise ValueError("mac_addresses is required for 'add' action")
            return self.add_wifi_mac_filter(mac_addresses)

        elif action == "remove":
            if mac_addresses is None:
                raise ValueError("mac_addresses is required for 'remove' action")
            return self.remove_wifi_mac_filter(mac_addresses)

        elif action == "clear":
            return self.clear_wifi_mac_filter()

        elif action == "set":
            if mac_addresses is None:
                raise ValueError("mac_addresses is required for 'set' action")
            if enabled is None:
                enabled = True
            return self.set_wifi_mac_filter_list(mac_addresses, enabled)

        elif action == "list":
            return self.get_wifi_mac_filter_list()

        elif action == "status":
            return self.get_wifi_mac_filter_status()

        elif action == "add_connected":
            return self.add_connected_wifi_devices_to_filter()

        else:
            raise ValueError(
                "action must be one of: enable, disable, add, remove, clear, set, list, status, add_connected"
            )

    def _private_vap_names(self) -> Tuple[str, str]:
        """Names of the 2.4GHz and 5GHz home VAPs, falling back to the defaults."""
        vap_2g = None
        vap_5g = None

        for network in self.get_wifi_networks():
            vap_name = network.get("VAPName", "")
            if "2g" in vap_name and "priv" in vap_name:
                vap_2g = vap_name
            elif "5g" in vap_name and "priv" in vap_name:
                vap_5g = vap_name

        if not vap_2g or not vap_5g:
            return "vap2g0priv", "vap5g0priv"
        return vap_2g, vap_5g
