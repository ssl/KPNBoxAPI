import pytest

MAC = "AA:BB:CC:DD:EE:FF"


def test_block_device_uses_schedule_override(router, api):
    router.on("Scheduler", "addSchedule", {"status": True})

    assert api.block_device_permanently(MAC) is True
    (params,) = router.calls_to("Scheduler", "addSchedule")
    assert params["type"] == "ToD"
    assert params["info"]["ID"] == MAC
    assert params["info"]["override"] == "Disable"


def test_daily_limits_replace_an_existing_schedule(router, api):
    router.on("Scheduler", "removeSchedules", {"status": True})
    router.on("ToD", "setMST", {"status": None})

    assert api.set_device_daily_time_limits(
        MAC, weekday_minutes=60, weekend_minutes=180
    )
    (params,) = router.calls_to("ToD", "setMST")
    assert params["id"] == "AABBCCDDEEFF"
    assert params["subject"] == f"MAC:{MAC}"
    assert params["allowedTime"]["Mon"] == 60
    assert params["allowedTime"]["Sun"] == 180
    assert router.calls_to("Scheduler", "removeSchedules") == [
        {"type": "ToD", "ID": [MAC]}
    ]


def test_daily_limits_validate_minutes(router, api):
    with pytest.raises(ValueError):
        api.set_device_daily_time_limits(MAC, weekday_minutes=1441)
    with pytest.raises(ValueError):
        api.set_device_mst(MAC, {"Funday": 10})
    assert len(router.calls) == 1  # only the login


def test_delete_device_mst_succeeds_when_nothing_to_delete(router, api):
    router.on("ToD", "deleteMST", {"status": None, "errors": [{"error": 1}]})

    assert api.delete_device_mst(MAC) is True


@pytest.mark.parametrize(
    "schedule, mst, control_type",
    [
        ({"status": False}, {"data": {}}, "none"),
        ({"status": {"enable": True, "override": "Disable"}}, {"data": {}}, "block"),
        (
            {"status": {"enable": True, "schedule": [{"begin": 0, "end": 60}]}},
            {"data": {}},
            "schedule",
        ),
        (
            {"status": False},
            {"data": {"enable": True, "allowedTime": {"Mon": 70, "Tue": 70}}},
            "daily_limits",
        ),
    ],
)
def test_parental_control_status(router, api, schedule, mst, control_type):
    router.on("Scheduler", "getSchedule", schedule)
    router.on("ToD", "getMST", mst)

    status = api.get_device_parental_control_status(MAC)

    assert status["control_type"] == control_type
    assert status["enabled"] is (control_type != "none")


def test_set_device_parental_control_rejects_unknown_type(router, api):
    with pytest.raises(ValueError, match="control_type must be one of"):
        api.set_device_parental_control(MAC, "curfew")


def test_study_hours_skip_invalid_days(router, api):
    router.on("Scheduler", "addSchedule", {"status": True})

    assert api.set_device_study_hours(MAC, 19, 21, study_days=[0, 9]) is True
    (params,) = router.calls_to("Scheduler", "addSchedule")
    assert params["info"]["schedule"] == [
        {"state": "Disable", "begin": 19 * 3600, "end": 21 * 3600}
    ]
