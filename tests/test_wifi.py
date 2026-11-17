from kpnboxapi._utils import SECONDS_PER_DAY

WLAN = {
    "status": {
        "wlanvap": {
            "vap2g1priv": {"SSID": "home"},
            "vap5g1priv": {"SSID": "home"},
            "ignored": "not a dict",
        }
    }
}


def test_get_wifi_networks_adds_vap_name(router, api):
    router.on("NeMo.Intf.lan", "getMIBs", WLAN)

    assert api.get_wifi_networks() == [
        {"SSID": "home", "VAPName": "vap2g1priv"},
        {"SSID": "home", "VAPName": "vap5g1priv"},
    ]


def test_set_wifi_config_targets_the_detected_vaps(router, api):
    router.on("NeMo.Intf.lan", "getMIBs", WLAN)
    router.on("NeMo.Intf.lan", "setWLANConfig", {"status": None})

    assert api.set_wifi_config(ssid_2g="new", password_2g="hunter22") is True
    (params,) = router.calls_to("NeMo.Intf.lan", "setWLANConfig")
    assert params == {
        "mibs": {
            "wlanvap": {
                "vap2g1priv": {
                    "SSID": "new",
                    "Security": {"KeyPassPhrase": "hunter22", "MFPConfig": ""},
                }
            }
        }
    }


def test_set_wifi_visibility_falls_back_to_default_vap_names(router, api):
    router.on("NeMo.Intf.lan", "getMIBs", {"status": {"wlanvap": {}}})
    router.on(
        "NeMo.Intf.lan", "setWLANConfig", {"status": None, "errors": [{"error": 1}]}
    )

    assert api.set_wifi_visibility(visible_5g=False) is False
    assert router.calls_to("NeMo.Intf.lan", "setWLANConfig") == [
        {"mibs": {"wlanvap": {"vap5g0priv": {"SSIDAdvertisementEnabled": False}}}}
    ]


def test_set_wifi_config_without_changes_makes_no_write(router, api):
    router.on("NeMo.Intf.lan", "getMIBs", WLAN)

    assert api.set_wifi_config() is True
    assert router.calls_to("NeMo.Intf.lan", "setWLANConfig") == []


def test_enable_guest_network_needs_all_three_steps(router, api):
    router.on("NMC.Guest", "set", {"status": True})
    router.on("NeMo.Intf.vap2g0guest", "set", {"status": True})
    router.on("NeMo.Intf.vap5g0guest", "set", {"status": False})

    assert api.enable_guest_network() is False
    assert router.calls_to("NMC.Guest", "set") == [{"Enable": "1"}]


def test_manage_wifi_mac_filter_accepts_a_single_address(router, api):
    router.on("NeMo.Intf.lan", "getMIBs", WLAN)
    router.on("NeMo.Intf.lan", "setWLANConfig", {"status": None})

    assert api.manage_wifi_mac_filter("set", "AA:AA:AA:AA:AA:01") is True
    (params,) = router.calls_to("NeMo.Intf.lan", "setWLANConfig")
    filtering = params["mibs"]["wlanvap"]["vap2g0priv"]["MACFiltering"]
    assert filtering == {
        "Mode": "WhiteList",
        "Entry": {"1": {"MACAddress": "AA:AA:AA:AA:AA:01"}},
    }


def test_wifi_bedtime_schedule_for_the_whole_week(router, api):
    router.on("Scheduler", "addSchedule", {"status": True})

    assert api.set_wifi_bedtime_schedule(
        bedtime_hour=23, wakeup_hour=7, weekdays_only=False
    )
    (params,) = router.calls_to("Scheduler", "addSchedule")
    schedule = params["info"]["schedule"]
    assert params["type"] == "WLAN"
    assert len(schedule) == 13  # 7 evenings + 6 mornings
    assert all(block["state"] == "Disable" for block in schedule)
    assert schedule[-1]["end"] == 7 * SECONDS_PER_DAY


def test_get_best_wifi_channels_ranks_by_score(router, api):
    router.on(
        "NeMo.Intf.rad2g0",
        "getSpectrumInfo",
        {
            "status": [
                {
                    "channel": 1,
                    "availability": 40,
                    "noiselevel": -90,
                    "accesspoints": 6,
                },
                {
                    "channel": 6,
                    "availability": 95,
                    "noiselevel": -95,
                    "accesspoints": 0,
                },
                {
                    "channel": 11,
                    "availability": 70,
                    "noiselevel": -92,
                    "accesspoints": 2,
                },
            ]
        },
    )

    best = api.get_best_wifi_channels("2g", top_n=2)

    assert [c["channel"] for c in best] == [6, 11]
    assert best[0]["congestion_level"] == "Low"
