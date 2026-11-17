"""Connected devices: listing, naming, schedules and cleanup."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ._base import KPNBoxBase
from ._utils import (
    validate_mac,
)
from .exceptions import APIError


def _parse_last_seen(value: Any) -> Optional[datetime]:
    """Parse the router's ISO timestamp into a naive datetime, or None."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Rough approximation: the offset is dropped rather than converted
    return parsed.replace(tzinfo=None)


class DevicesMixin(KPNBoxBase):
    """Connected devices: listing, naming, schedules and cleanup."""

    def get_connected_devices(self) -> Any:
        """
        Get raw device data from the KPN Box.

        Returns:
            Raw device data from the API
        """
        return self._make_api_call(
            service="Devices.Device.lan",
            method="topology",
            parameters={"expression": "not logical", "flags": "no_recurse|no_actions"},
        )

    def get_devices(self, filter: str = "all") -> List[Dict[str, Any]]:
        """
        Get connected devices with optional filtering.

        Args:
            filter: Device filter - 'all', 'active', or 'inactive' (default: 'all')

        Returns:
            List of device dictionaries with fields:
            - Name: Device name
            - PhysAddress: MAC address
            - IPAddress: IP address
            - Active: Connection status (True/False)
            - DeviceType: Type of device
            - Layer2Interface: Network interface
            - FirstSeen: First connection timestamp
            - LastConnection: Last connection timestamp
            - Plus many other fields from the raw API

        Raises:
            ValueError: If filter parameter is invalid
        """
        if filter not in ["all", "active", "inactive"]:
            raise ValueError("Filter must be 'all', 'active', or 'inactive'")

        raw_data = self.get_connected_devices()
        devices: List[Dict[str, Any]] = []

        def extract_devices(data: Any) -> None:
            if isinstance(data, list):
                for item in data:
                    extract_devices(item)
            elif isinstance(data, dict):
                # Filter actual devices (not network interfaces)
                if (
                    data.get("PhysAddress")
                    and not data.get("Name", "").startswith("ETH")
                    and not data.get("Name", "").startswith("vap")
                    and data.get("Name") != "lan"
                ):
                    is_active = data.get("Active", False)
                    if (
                        filter == "all"
                        or (filter == "active" and is_active)
                        or (filter == "inactive" and not is_active)
                    ):
                        devices.append(data)

                if "Children" in data:
                    extract_devices(data["Children"])

        # Handle response format
        if isinstance(raw_data, dict) and "status" in raw_data:
            extract_devices(raw_data["status"])
        else:
            extract_devices(raw_data)

        return devices

    def get_device_schedules(self, schedule_type: str = "ToD") -> List[Dict[str, Any]]:
        """
        Get device access schedules (Time of Day restrictions).

        Args:
            schedule_type: Type of schedule to retrieve (default: "ToD")

        Returns:
            List of device schedule dictionaries with fields:
            - ID: Device identifier (usually MAC address)
            - name: Device name
            - enable: Whether scheduling is enabled for this device
            - base: Schedule base type (e.g., "Weekly")
            - def: Default state ("Enable" or "Disable")
            - stateMode: Current state mode ("Default", "Override")
            - override: Override setting ("Enable", "Disable", or "")
            - temporaryOverride: Whether temporary override is active
            - value: Current effective value ("Enable" or "Disable")
            - schedule: List of schedule rules
            - device: Device location ("LOCAL")
            - target: List of target devices
        """
        response = self._make_api_call(
            service="Scheduler",
            method="getCompleteSchedules",
            parameters={"type": schedule_type},
        )

        schedules = self._data_dict(response).get("scheduleInfo")
        if not isinstance(schedules, list):
            return []
        return [schedule for schedule in schedules if isinstance(schedule, dict)]

    def get_device_details(self, mac_address: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific connected device.

        Args:
            mac_address: MAC address of the device (e.g., "DC:A6:32:C2:61:E3")

        Returns:
            Dictionary with comprehensive device information including:
            - Key: Device MAC address identifier
            - Name: Device name/hostname
            - DeviceType: Device type (e.g., "Computer", "Smartphone", "Tablet")
            - Active: Whether device is currently connected
            - Tags: Device capability tags (e.g., "lan", "ipv4", "dhcp")
            - FirstSeen: First connection timestamp
            - LastConnection: Last connection timestamp
            - LastChanged: Last configuration change timestamp
            - IPAddress: Current IP address
            - IPAddressSource: How IP was assigned ("DHCP", "Static")
            - PhysAddress: Physical MAC address
            - Layer2Interface: Network interface (e.g., "ETH2", "WLAN")
            - Owner: Device owner (if set)
            - Location: Device location (if set)
            - Actions: Available management actions (setName, setType, etc.)
            - IPv4Address: List of IPv4 addresses with status
            - IPv6Address: List of IPv6 addresses with status
            - Security: Security scoring information
            - Priority: QoS priority configuration
            - WANAccess: WAN access control information
            - BDD: Device fingerprinting information
            - Names: Historical device names from different sources
            - DeviceTypes: Historical device types from different sources

        Raises:
            ValueError: If mac_address format is invalid
        """
        validate_mac(mac_address)

        response = self._make_api_call(
            service=f"Devices.Device.{mac_address}",
            method="get",
            parameters={"flags": "full_links"},
        )

        return self._status_dict(response)

    def get_device_schedule(self, mac_address: str) -> Dict[str, Any]:
        """
        Get Time of Day access schedule for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

        Returns:
            Dictionary with device schedule information including:
            - base: Schedule base type ("Weekly")
            - def: Default state ("Enable" or "Disable")
            - ID: Device identifier (MAC address)
            - schedule: List of time restriction blocks
            - enable: Whether scheduling is enabled for this device
            - override: Current override setting ("Enable", "Disable", or "")

            Returns False if no schedule is configured for the device.

        Raises:
            ValueError: If mac_address format is invalid
        """
        validate_mac(mac_address)

        response = self._make_api_call(
            service="Scheduler",
            method="getSchedule",
            parameters={"type": "ToD", "ID": mac_address},
        )

        # Documented contract: the schedule, or False when the device has none
        schedule = self._status_dict(response)
        return schedule if schedule else False  # type: ignore[return-value]

    def set_device_schedule(
        self,
        mac_address: str,
        schedule_blocks: Optional[List[Dict[str, int]]] = None,
        enabled: bool = True,
        default_state: str = "Enable",
        override: str = "",
    ) -> bool:
        """
        Set Time of Day access schedule for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            schedule_blocks: List of time blocks when device should be disabled.
                           Each block is a dict with 'begin' and 'end' keys (seconds from Monday 00:00)
            enabled: Whether the schedule should be enabled (default: True)
            default_state: Default access state - "Enable" or "Disable" (default: "Enable")
            override: Override setting - "Enable", "Disable", or "" (default: "")

        Returns:
            True if successful

        Raises:
            ValueError: If mac_address format is invalid or default_state is invalid

        Example:
            # Block device from 8 PM to 8 AM on weekdays
            api.set_device_schedule(
                "A8:A1:59:33:F1:E4",
                schedule_blocks=[
                    {"begin": 72000, "end": 115200},   # Monday 20:00-08:00+1
                    {"begin": 158400, "end": 201600},  # Tuesday 20:00-08:00+1
                    # ... more days
                ],
                enabled=True
            )

            # Block device completely (always disabled)
            api.set_device_schedule(
                "A8:A1:59:33:F1:E4",
                schedule_blocks=[],
                enabled=True,
                override="Disable"
            )
        """
        validate_mac(mac_address)

        if default_state not in ["Enable", "Disable"]:
            raise ValueError("default_state must be 'Enable' or 'Disable'")

        if schedule_blocks is None:
            schedule_blocks = []

        # Convert schedule blocks to proper format
        schedule = []
        for block in schedule_blocks:
            schedule.append(
                {"state": "Disable", "begin": block["begin"], "end": block["end"]}
            )

        schedule_info = {
            "base": "Weekly",
            "def": default_state,
            "ID": mac_address,
            "schedule": schedule,
            "enable": enabled,
            "override": override,
        }

        result = self._make_api_call(
            service="Scheduler",
            method="addSchedule",
            parameters={"type": "ToD", "info": schedule_info},
        )

        return self._is_true(result)

    def remove_device_schedule(self, mac_address: str) -> bool:
        """
        Remove Time of Day access schedule for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

        Returns:
            True if successful

        Raises:
            ValueError: If mac_address format is invalid
        """
        validate_mac(mac_address)

        result = self._make_api_call(
            service="Scheduler",
            method="removeSchedules",
            parameters={"type": "ToD", "ID": [mac_address]},
        )

        return self._is_true(result)

    def set_device_name(
        self, mac_address: str, name: str, source: str = "manual"
    ) -> bool:
        """
        Set the display name for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            name: New device name (e.g., "John's Laptop")
            source: Source of the name change (default: "manual")

        Returns:
            True if successful

        Raises:
            ValueError: If mac_address format is invalid or name is empty
        """
        validate_mac(mac_address)

        if not name or not name.strip():
            raise ValueError("Device name cannot be empty")

        result = self._make_api_call(
            service=f"Devices.Device.{mac_address}",
            method="setName",
            parameters={"name": name.strip(), "source": source},
        )

        return self._is_true(result)

    def set_device_type(
        self, mac_address: str, device_type: str, source: str = "manual"
    ) -> bool:
        """
        Set the device type/icon for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            device_type: Device type for icon selection. Common types include:
                        "Computer", "Laptop", "Tablet", "Smartphone", "Printer",
                        "Television", "MediaPlayer", "GameConsole", "SmartSpeaker",
                        "SmartWatch", "Camera", "Router", "Switch", "AccessPoint",
                        "IoTDevice", "SmartHome", "NAS", "Server", "Unknown"
            source: Source of the type change (default: "manual")

        Returns:
            True if successful

        Raises:
            ValueError: If mac_address format is invalid or device_type is empty
        """
        validate_mac(mac_address)

        if not device_type or not device_type.strip():
            raise ValueError("Device type cannot be empty")

        result = self._make_api_call(
            service=f"Devices.Device.{mac_address}",
            method="setType",
            parameters={"type": device_type.strip(), "source": source},
        )

        return self._is_true(result)

    def get_device_management_info(self, mac_address: str) -> Dict[str, Any]:
        """
        Get comprehensive device management information including details and schedule.

        Args:
            mac_address: MAC address of the device

        Returns:
            Dictionary with keys:
            - 'device_details': Complete device information
            - 'schedule': Current access schedule (if any)
            - 'is_scheduled': Whether device has active schedule
            - 'is_blocked': Whether device is permanently blocked
            - 'summary': Text summary of device status
        """
        device_details = self.get_device_details(mac_address)
        schedule = self.get_device_schedule(mac_address)

        # Determine device status
        is_scheduled = bool(schedule)
        is_blocked = False

        if is_scheduled and isinstance(schedule, dict):
            # Check if device is permanently blocked (override = "Disable")
            is_blocked = schedule.get("override") == "Disable"

        # Generate summary
        device_name = device_details.get("Name", "Unknown Device")
        device_type = device_details.get("DeviceType", "Unknown")
        is_active = device_details.get("Active", False)

        if is_blocked:
            summary = f"{device_name} ({device_type}) - Permanently blocked"
        elif is_scheduled:
            summary = f"{device_name} ({device_type}) - Time restrictions active"
        elif is_active:
            summary = f"{device_name} ({device_type}) - Connected and unrestricted"
        else:
            summary = f"{device_name} ({device_type}) - Offline"

        return {
            "device_details": device_details,
            "schedule": schedule,
            "is_scheduled": is_scheduled,
            "is_blocked": is_blocked,
            "summary": summary,
        }

    def list_managed_devices(self) -> List[Dict[str, Any]]:
        """
        Get list of all devices with their management status.

        Returns:
            List of device management summaries with:
            - mac_address: Device MAC address
            - name: Device name
            - device_type: Device type
            - active: Whether device is connected
            - scheduled: Whether device has time restrictions
            - blocked: Whether device is permanently blocked
            - last_seen: Last connection time
        """
        devices = self.get_devices("all")
        managed_devices = []

        for device in devices:
            mac_address = device.get("PhysAddress", "")
            if not mac_address:
                continue

            # Get schedule info
            schedule = self.get_device_schedule(mac_address)
            is_scheduled = bool(schedule)
            is_blocked = False

            if is_scheduled and isinstance(schedule, dict):
                is_blocked = schedule.get("override") == "Disable"

            managed_device = {
                "mac_address": mac_address,
                "name": device.get("Name", "Unknown Device"),
                "device_type": device.get("DeviceType", "Unknown"),
                "active": device.get("Active", False),
                "scheduled": is_scheduled,
                "blocked": is_blocked,
                "last_seen": device.get("LastConnection", ""),
                "ip_address": device.get("IPAddress", ""),
                "interface": device.get("Layer2Interface", ""),
            }

            managed_devices.append(managed_device)

        # Sort by name
        managed_devices.sort(key=lambda x: x["name"].lower())

        return managed_devices

    def get_common_device_types(self) -> List[str]:
        """
        Get list of common device types for use with set_device_type().

        Returns:
            List of common device type names
        """
        return [
            "Computer",
            "Laptop",
            "Tablet",
            "Smartphone",
            "Printer",
            "Television",
            "MediaPlayer",
            "GameConsole",
            "SmartSpeaker",
            "SmartWatch",
            "Camera",
            "Router",
            "Switch",
            "AccessPoint",
            "IoTDevice",
            "SmartHome",
            "NAS",
            "Server",
            "Unknown",
        ]

    def delete_device(self, mac_address: str) -> bool:
        """
        Delete/destroy a device from the router's device list.

        This removes the device from the known devices list. Typically used
        for cleaning up old inactive devices that haven't been seen in a while.

        Args:
            mac_address: MAC address of the device to delete (e.g., "96:16:1A:D6:0F:30")

        Returns:
            True if device was successfully deleted

        Raises:
            ValueError: If mac_address format is invalid

        Note:
            - This only removes the device from the router's memory
            - If the device reconnects, it will reappear in the device list
            - Typically used for inactive devices to clean up the device list
            - Device schedules and restrictions are also removed
        """
        validate_mac(mac_address)

        result = self._make_api_call(
            service="Devices", method="destroyDevice", parameters={"key": mac_address}
        )

        return self._is_true(result)

    def cleanup_inactive_devices(self, days_inactive: int = 30) -> Dict[str, Any]:
        """
        Clean up devices that haven't been seen for a specified number of days.

        Args:
            days_inactive: Number of days of inactivity before considering device for cleanup (default: 30)

        Returns:
            Dictionary with cleanup results:
            - 'candidates': List of devices eligible for cleanup
            - 'deleted': List of devices that were deleted
            - 'failed': List of devices that failed to delete
            - 'total_candidates': Number of devices eligible for cleanup
            - 'total_deleted': Number of devices successfully deleted

        Note:
            This function will automatically delete devices, use with caution.
        """
        devices = self.list_managed_devices()
        cutoff_date = datetime.now() - timedelta(days=days_inactive)

        candidates = []
        deleted = []
        failed = []

        for device in devices:
            if device["active"]:
                continue

            last_seen = _parse_last_seen(device.get("last_seen", ""))
            if last_seen is None or last_seen >= cutoff_date:
                continue  # Unknown or recent: never delete on a guess

            candidates.append(device)
            try:
                if self.delete_device(device["mac_address"]):
                    deleted.append(device)
                else:
                    failed.append(device)
            except APIError as e:
                device["error"] = str(e)
                failed.append(device)

        return {
            "candidates": candidates,
            "deleted": deleted,
            "failed": failed,
            "total_candidates": len(candidates),
            "total_deleted": len(deleted),
            "total_failed": len(failed),
        }

    def list_inactive_devices(self, days_inactive: int = 7) -> List[Dict[str, Any]]:
        """
        List devices that haven't been seen for a specified number of days.

        Args:
            days_inactive: Number of days of inactivity to filter by (default: 7)

        Returns:
            List of inactive device dictionaries with additional fields:
            - 'days_since_seen': Number of days since last connection
            - All standard device management fields
        """
        devices = self.list_managed_devices()
        now = datetime.now()
        cutoff_date = now - timedelta(days=days_inactive)

        inactive_devices = []

        for device in devices:
            if device["active"]:
                continue

            last_seen = device.get("last_seen", "")
            if not last_seen:
                device["days_since_seen"] = "Unknown"
                inactive_devices.append(device)
                continue

            if "T" not in last_seen:
                continue

            device_date = _parse_last_seen(last_seen)
            if device_date is None:
                device["days_since_seen"] = "Parse Error"
                inactive_devices.append(device)
                continue

            device["days_since_seen"] = (now - device_date).days
            if device_date < cutoff_date:
                inactive_devices.append(device)

        # Sort by days since seen (most recent first); unknown dates go last
        inactive_devices.sort(
            key=lambda x: (
                x["days_since_seen"]
                if isinstance(x.get("days_since_seen"), int)
                else 999999
            )
        )

        return inactive_devices
