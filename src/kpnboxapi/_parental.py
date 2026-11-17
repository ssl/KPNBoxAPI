"""Parental controls: blocking, bedtime schedules and daily time limits."""

from typing import Any, Dict, List, Optional

from ._devices import DevicesMixin
from ._utils import (
    bedtime_blocks,
    validate_hours,
    validate_mac,
)


class ParentalMixin(DevicesMixin):
    """Parental controls: blocking, bedtime schedules and daily time limits."""

    def block_device_permanently(self, mac_address: str) -> bool:
        """
        Permanently block a device from accessing the internet.

        Args:
            mac_address: MAC address of the device to block

        Returns:
            True if successful
        """
        return self.set_device_schedule(
            mac_address=mac_address,
            schedule_blocks=[],
            enabled=True,
            default_state="Enable",
            override="Disable",
        )

    def unblock_device(self, mac_address: str) -> bool:
        """
        Remove all access restrictions from a device.

        Args:
            mac_address: MAC address of the device to unblock

        Returns:
            True if successful
        """
        return self.remove_device_schedule(mac_address)

    def set_device_bedtime_schedule(
        self,
        mac_address: str,
        bedtime_hour: int = 22,
        wakeup_hour: int = 7,
        weekdays_only: bool = True,
    ) -> bool:
        """
        Set a bedtime schedule for a device (disable during night hours).

        Args:
            mac_address: MAC address of the device
            bedtime_hour: Hour to disable device (0-23, default: 22 = 10 PM)
            wakeup_hour: Hour to enable device (0-23, default: 7 = 7 AM)
            weekdays_only: Whether to apply only on weekdays (default: True)

        Returns:
            True if successful

        Raises:
            ValueError: If hours are invalid
        """
        validate_hours(bedtime_hour, wakeup_hour)

        days = range(5) if weekdays_only else range(7)  # 0 = Monday
        schedule_blocks = bedtime_blocks(bedtime_hour, wakeup_hour, days)

        return self.set_device_schedule(mac_address, schedule_blocks, enabled=True)

    def set_device_study_hours(
        self,
        mac_address: str,
        study_start_hour: int = 19,
        study_end_hour: int = 21,
        study_days: Optional[List[int]] = None,
    ) -> bool:
        """
        Set study hours schedule for a device (disable during study time).

        Args:
            mac_address: MAC address of the device
            study_start_hour: Hour to start study time (0-23, default: 19 = 7 PM)
            study_end_hour: Hour to end study time (0-23, default: 21 = 9 PM)
            study_days: List of study days (0=Monday, 6=Sunday, default: weekdays)

        Returns:
            True if successful
        """
        if not (0 <= study_start_hour <= 23) or not (0 <= study_end_hour <= 23):
            raise ValueError("Hours must be between 0 and 23")

        if study_days is None:
            study_days = [0, 1, 2, 3, 4]  # Weekdays

        schedule_blocks = []

        for day in study_days:
            if day < 0 or day > 6:
                continue

            day_start = day * 24 * 3600
            study_start = day_start + (study_start_hour * 3600)
            study_end = day_start + (study_end_hour * 3600)

            if study_end > study_start:
                schedule_blocks.append({"begin": study_start, "end": study_end})

        return self.set_device_schedule(mac_address, schedule_blocks, enabled=True)

    def get_device_mst_status(self, mac_address: str) -> Dict[str, Any]:
        """
        Get Managed Screen Time (MST) status for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

        Returns:
            Dictionary with MST status including:
            - subject: Device identifier (e.g., "MAC:A8:A1:59:33:F1:E4")
            - enable: Whether MST is enabled for this device
            - status: Current status ("Active" or other status)
            - allowedTime: Dictionary with daily time limits in minutes per day
                          (Mon, Tue, Wed, Thu, Fri, Sat, Sun)

            Returns empty dict if no MST is configured for the device.

        Raises:
            ValueError: If mac_address format is invalid
        """
        validate_mac(mac_address)

        # Create MST ID by removing colons
        mst_id = mac_address.replace(":", "").upper()

        response = self._make_api_call(
            service="ToD", method="getMST", parameters={"id": mst_id}
        )

        return self._data_dict(response)

    def set_device_mst(
        self,
        mac_address: str,
        daily_limits: Optional[Dict[str, int]] = None,
        enabled: bool = True,
    ) -> bool:
        """
        Set Managed Screen Time (MST) daily limits for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            daily_limits: Dictionary with daily time limits in minutes per day.
                         Keys: Mon, Tue, Wed, Thu, Fri, Sat, Sun
                         Values: Minutes allowed per day (0-1440)
                         Example: {"Mon": 120, "Tue": 180, "Wed": 120, ...}
            enabled: Whether to enable MST for this device (default: True)

        Returns:
            True if successful

        Raises:
            ValueError: If mac_address format is invalid or daily_limits contains invalid values

        Note:
            - Automatically removes existing time-based schedules when setting MST
            - Time limits are in minutes per day (0-1440, where 1440 = 24 hours)
            - When MST is active, device will be blocked after time limit is reached
        """
        validate_mac(mac_address)

        # Default daily limits if not provided (2 hours per day)
        if daily_limits is None:
            daily_limits = {
                "Mon": 120,
                "Tue": 120,
                "Wed": 120,
                "Thu": 120,
                "Fri": 120,
                "Sat": 240,
                "Sun": 240,
            }

        # Validate daily limits
        valid_days = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
        for day, minutes in daily_limits.items():
            if day not in valid_days:
                raise ValueError(f"Invalid day: {day}. Must be one of: {valid_days}")
            if not isinstance(minutes, int) or minutes < 0 or minutes > 1440:
                raise ValueError(
                    f"Invalid time limit for {day}: {minutes}. Must be 0-1440 minutes"
                )

        # Remove existing time-based schedules first (MST and schedules conflict)
        self.remove_device_schedule(mac_address)

        # Create MST ID by removing colons
        mst_id = mac_address.replace(":", "").upper()

        # Set MST configuration
        result = self._make_api_call(
            service="ToD",
            method="setMST",
            parameters={
                "id": mst_id,
                "subject": f"MAC:{mac_address}",
                "enable": enabled,
                "allowedTime": daily_limits,
            },
        )

        return self._succeeded(result)  # API returns null on success

    def delete_device_mst(self, mac_address: str) -> bool:
        """
        Delete Managed Screen Time (MST) configuration for a specific device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

        Returns:
            True if successful (also returns True if MST was not configured)

        Raises:
            ValueError: If mac_address format is invalid
        """
        validate_mac(mac_address)

        # Create MST ID by removing colons
        mst_id = mac_address.replace(":", "").upper()

        self._make_api_call(
            service="ToD", method="deleteMST", parameters={"id": mst_id}
        )

        # The router also reports an error when there is no MST to delete. Both
        # outcomes leave the device without MST, so both count as success.
        return True

    def set_device_daily_time_limits(
        self,
        mac_address: str,
        weekday_minutes: int = 120,
        weekend_minutes: int = 240,
        enabled: bool = True,
    ) -> bool:
        """
        Set daily time limits for a device (simplified MST setup).

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            weekday_minutes: Time limit for Mon-Fri in minutes (default: 120 = 2 hours)
            weekend_minutes: Time limit for Sat-Sun in minutes (default: 240 = 4 hours)
            enabled: Whether to enable time limits (default: True)

        Returns:
            True if successful

        Raises:
            ValueError: If mac_address format is invalid or time limits are invalid

        Note: Convenience method that calls set_device_mst with weekday/weekend limits.
        """
        # Validate time limits
        if (
            not isinstance(weekday_minutes, int)
            or weekday_minutes < 0
            or weekday_minutes > 1440
        ):
            raise ValueError("weekday_minutes must be 0-1440")
        if (
            not isinstance(weekend_minutes, int)
            or weekend_minutes < 0
            or weekend_minutes > 1440
        ):
            raise ValueError("weekend_minutes must be 0-1440")

        # Create daily limits
        daily_limits = {
            "Mon": weekday_minutes,
            "Tue": weekday_minutes,
            "Wed": weekday_minutes,
            "Thu": weekday_minutes,
            "Fri": weekday_minutes,
            "Sat": weekend_minutes,
            "Sun": weekend_minutes,
        }

        return self.set_device_mst(mac_address, daily_limits, enabled)

    def set_device_parental_control(
        self, mac_address: str, control_type: str, **kwargs: Any
    ) -> bool:
        """
        Unified parental control management for a device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            control_type: Type of control to apply:
                         - "none": Remove all restrictions
                         - "block": Block device completely
                         - "schedule": Time-based schedule restrictions
                         - "daily_limits": Daily time limits (MST)
            **kwargs: Additional parameters based on control_type:

                     For "schedule":
                     - schedule_blocks: List of time blocks when device should be disabled
                     - enabled: Whether schedule should be enabled (default: True)

                     For "daily_limits":
                     - daily_limits: Dict with daily time limits or
                     - weekday_minutes: Time limit for Mon-Fri (default: 120)
                     - weekend_minutes: Time limit for Sat-Sun (default: 240)
                     - enabled: Whether limits should be enabled (default: True)

        Returns:
            True if successful

        Raises:
            ValueError: If control_type is invalid or required parameters are missing

        Examples:
            # Remove all restrictions
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "none")

            # Block device completely
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "block")

            # Set bedtime schedule (block 10 PM to 6 AM)
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "schedule",
                schedule_blocks=[{"begin": 79200, "end": 108000}])

            # Set daily time limits (2 hours weekdays, 4 hours weekends)
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "daily_limits",
                weekday_minutes=120, weekend_minutes=240)
        """
        validate_mac(mac_address)

        if control_type == "none":
            # Remove all restrictions
            self.remove_device_schedule(mac_address)
            self.delete_device_mst(mac_address)
            return True

        elif control_type == "block":
            # Block device completely using schedule override
            self.delete_device_mst(mac_address)  # Remove MST first
            return self.set_device_schedule(
                mac_address, schedule_blocks=[], enabled=True, override="Disable"
            )

        elif control_type == "schedule":
            # Time-based schedule restrictions
            self.delete_device_mst(mac_address)  # Remove MST first

            schedule_blocks = kwargs.get("schedule_blocks", [])
            enabled = kwargs.get("enabled", True)

            return self.set_device_schedule(
                mac_address, schedule_blocks=schedule_blocks, enabled=enabled
            )

        elif control_type == "daily_limits":
            # Daily time limits (MST)
            self.remove_device_schedule(mac_address)  # Remove schedule first

            # Check if daily_limits dict is provided
            if "daily_limits" in kwargs:
                daily_limits = kwargs["daily_limits"]
                enabled = kwargs.get("enabled", True)
                return self.set_device_mst(mac_address, daily_limits, enabled)
            else:
                # Use weekday/weekend simplified setup
                weekday_minutes = kwargs.get("weekday_minutes", 120)
                weekend_minutes = kwargs.get("weekend_minutes", 240)
                enabled = kwargs.get("enabled", True)
                return self.set_device_daily_time_limits(
                    mac_address, weekday_minutes, weekend_minutes, enabled
                )

        else:
            raise ValueError(
                "control_type must be one of: none, block, schedule, daily_limits"
            )

    def get_device_parental_control_status(self, mac_address: str) -> Dict[str, Any]:
        """
        Get comprehensive parental control status for a device.

        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

        Returns:
            Dictionary with parental control status including:
            - control_type: Type of control ("none", "block", "schedule", "daily_limits")
            - enabled: Whether any control is enabled
            - schedule: Schedule information (if applicable)
            - mst: MST information (if applicable)
            - summary: Human-readable summary of current restrictions

        Raises:
            ValueError: If mac_address format is invalid
        """
        validate_mac(mac_address)

        # Get schedule status
        schedule_status = self.get_device_schedule(mac_address)

        # Get MST status
        mst_status = self.get_device_mst_status(mac_address)

        result = {
            "control_type": "none",
            "enabled": False,
            "schedule": schedule_status,
            "mst": mst_status,
            "summary": "No restrictions",
        }

        # Determine control type and summary
        if mst_status and mst_status.get("enable"):
            result["control_type"] = "daily_limits"
            result["enabled"] = True

            # Calculate total weekly minutes
            allowed_time = mst_status.get("allowedTime", {})
            total_minutes = sum(allowed_time.values())
            avg_daily = total_minutes // 7

            result["summary"] = f"Daily time limits enabled (avg {avg_daily} min/day)"

        elif schedule_status and schedule_status.get("enable"):
            result["control_type"] = "schedule"
            result["enabled"] = True

            override = schedule_status.get("override", "")
            if override == "Disable":
                result["control_type"] = "block"
                result["summary"] = "Device completely blocked"
            else:
                schedule_blocks = schedule_status.get("schedule", [])
                if schedule_blocks:
                    result["summary"] = (
                        f"Time-based restrictions ({len(schedule_blocks)} time blocks)"
                    )
                else:
                    result["summary"] = "Schedule enabled but no restrictions"

        return result

    def list_devices_with_parental_controls(self) -> List[Dict[str, Any]]:
        """
        Get list of all devices that have parental controls configured.

        Returns:
            List of devices with parental control information including:
            - mac_address: Device MAC address
            - name: Device name
            - device_type: Device type
            - active: Whether device is currently connected
            - control_type: Type of parental control
            - enabled: Whether controls are enabled
            - summary: Summary of current restrictions
        """
        # Get all device schedules
        all_schedules = self.get_device_schedules("ToD")

        # Get all devices for name/type lookup
        all_devices = self.get_devices("all")
        device_lookup = {d.get("PhysAddress"): d for d in all_devices}

        controlled_devices = []

        # Process devices with schedules
        for schedule in all_schedules:
            if schedule.get("enable"):
                mac_address = schedule.get("ID")
                if mac_address:
                    device_info = device_lookup.get(mac_address, {})

                    # Get full parental control status
                    control_status = self.get_device_parental_control_status(
                        mac_address
                    )

                    controlled_devices.append(
                        {
                            "mac_address": mac_address,
                            "name": device_info.get("Name", "Unknown"),
                            "device_type": device_info.get("DeviceType", "Unknown"),
                            "active": device_info.get("Active", False),
                            "control_type": control_status.get("control_type"),
                            "enabled": control_status.get("enabled"),
                            "summary": control_status.get("summary"),
                        }
                    )

        # TODO: Also check for devices with MST but no schedules
        # This would require iterating through all devices and checking MST status
        # For now, the schedule-based approach covers most cases

        return controlled_devices

    def format_time_seconds_to_readable(self, seconds: int) -> str:
        """
        Convert seconds from Monday 00:00 to human-readable time.

        Args:
            seconds: Seconds from Monday 00:00

        Returns:
            Human-readable time string (e.g., "Monday 08:30", "Friday 22:00")
        """
        days = [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]

        day_index = seconds // 86400  # 86400 seconds in a day
        remaining_seconds = seconds % 86400

        hours = remaining_seconds // 3600
        minutes = (remaining_seconds % 3600) // 60

        if day_index >= 7:
            # Handle overflow to next week
            day_index = day_index % 7

        return f"{days[day_index]} {hours:02d}:{minutes:02d}"

    def create_bedtime_schedule_blocks(
        self,
        bedtime_hour: int = 22,
        wakeup_hour: int = 6,
        days: Optional[List[int]] = None,
    ) -> List[Dict[str, int]]:
        """
        Create schedule blocks for bedtime restrictions.

        Args:
            bedtime_hour: Hour when device should be blocked (0-23, default: 22 = 10 PM)
            wakeup_hour: Hour when device should be unblocked (0-23, default: 6 = 6 AM)
            days: List of days to apply (0=Monday, 6=Sunday, default: [0,1,2,3,4] = weekdays)

        Returns:
            List of schedule blocks suitable for set_device_schedule
        """
        if days is None:
            days = [0, 1, 2, 3, 4]  # Weekdays only

        schedule_blocks = []

        for day in days:
            # Calculate start time (bedtime)
            bedtime_seconds = day * 86400 + bedtime_hour * 3600

            # Calculate end time (next day wakeup)
            if wakeup_hour <= bedtime_hour:
                # Wakeup is next day
                wakeup_seconds = (day + 1) * 86400 + wakeup_hour * 3600
            else:
                # Wakeup is same day (shouldn't happen for bedtime, but handle it)
                wakeup_seconds = day * 86400 + wakeup_hour * 3600

            schedule_blocks.append({"begin": bedtime_seconds, "end": wakeup_seconds})

        return schedule_blocks
