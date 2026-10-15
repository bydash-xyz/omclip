"""Unit tests for omclip.bluetooth — health classification and radio lifecycle."""

import unittest

import _support  # noqa: F401 - path setup + hermetic radio
from omclip import bluetooth

BTMGMT_HEAD = "Index list with 1 item\nhci0:\tPrimary controller\n"


def btmgmt(powered):
    return (BTMGMT_HEAD
            + "\tsupported settings: powered connectable le advertising\n"
            + "\tcurrent settings: " + ("powered " if powered else "") + "ssp\n")


class FakeMachine:
    """Just enough of systemctl/rfkill/bluetoothctl/btmgmt to test the lifecycle."""

    def __init__(self, active=False, blocked=False, powered=False):
        self.active = active
        self.blocked = blocked
        self.powered = powered
        self.calls = []
        self.start_rc = 0
        self.start_out = ""
        self.sudo_used = False

    def run(self, cmd, timeout=2.0):
        self.calls.append(cmd)
        name = cmd[0]
        argv = " ".join(cmd)
        if name == "sudo":
            self.sudo_used = True
            return self.run(cmd[2:], timeout)
        if name == "systemctl" and "is-active" in cmd:
            return (0, "active\n") if self.active else (3, "inactive\n")
        if name == "systemctl" and "start" in cmd:
            if self.start_rc == 0:
                self.active = True
            return self.start_rc, self.start_out
        if name == "systemctl" and "stop" in cmd:
            self.active = False
            return 0, ""
        if name == "rfkill" and "unblock" in cmd:
            self.blocked = False
            return 0, ""
        if name == "rfkill" and "block" in cmd:
            self.blocked = True
            return 0, ""
        if name == "rfkill":
            return 0, "Soft blocked: %s\nHard blocked: no\n" % ("yes" if self.blocked else "no")
        if name == "bluetoothctl":
            if self.blocked:
                return 1, "org.bluez.Error.Failed"
            self.powered = True
            return 0, "Changing power on succeeded"
        if name == "btmgmt" and "info" in cmd:
            return 0, btmgmt(self.powered)
        return 0, ""

    def ran(self, *needles):
        return [c for c in self.calls if all(n in c for n in needles)]


class ServiceActive(unittest.TestCase):
    def test_active(self):
        saved = bluetooth.run
        bluetooth.run = lambda cmd, timeout=2.0: (0, "active\n")
        try:
            self.assertTrue(bluetooth.service_active())
        finally:
            bluetooth.run = saved

    def test_inactive(self):
        saved = bluetooth.run
        bluetooth.run = lambda cmd, timeout=2.0: (3, "inactive\n")
        try:
            self.assertFalse(bluetooth.service_active())
        finally:
            bluetooth.run = saved


class SoftBlocked(unittest.TestCase):
    def test_blocked(self):
        saved = bluetooth.run
        bluetooth.run = lambda cmd, timeout=2.0: (0, "Soft blocked: yes\nHard blocked: no\n")
        try:
            self.assertTrue(bluetooth.soft_blocked())
        finally:
            bluetooth.run = saved

    def test_unblocked(self):
        saved = bluetooth.run
        bluetooth.run = lambda cmd, timeout=2.0: (0, "Soft blocked: no\nHard blocked: no\n")
        try:
            self.assertFalse(bluetooth.soft_blocked())
        finally:
            bluetooth.run = saved


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.saved = bluetooth.run
        self.saved_wait = bluetooth.POWER_WAIT_S
        bluetooth.POWER_WAIT_S = 0.0      # one power probe per call, no 3 s loop
        bluetooth.set_owned(False)

    def tearDown(self):
        bluetooth.run = self.saved
        bluetooth.POWER_WAIT_S = self.saved_wait
        bluetooth.set_owned(False)

    def test_inactive_service_is_unblocked_started_powered_and_owned(self):
        machine = FakeMachine(active=False, blocked=True, powered=False)
        bluetooth.run = machine.run
        ok, owned, message = bluetooth.ensure_started()
        self.assertTrue(ok)
        self.assertTrue(owned)
        self.assertIsNone(message)
        self.assertTrue(bluetooth.is_owned())
        self.assertTrue(machine.active)
        self.assertFalse(machine.blocked, "rfkill soft-block must be lifted")
        self.assertTrue(machine.powered)

    def test_active_service_is_powered_but_never_owned(self):
        machine = FakeMachine(active=True, blocked=False, powered=False)
        bluetooth.run = machine.run
        ok, owned, message = bluetooth.ensure_started()
        self.assertTrue(ok)
        self.assertFalse(owned, "a service omclip did not start is not omclip's")
        self.assertFalse(bluetooth.is_owned())
        self.assertTrue(machine.powered)
        self.assertEqual(machine.ran("systemctl", "start"), [])

    def test_soft_blocked_adapter_is_reported_not_owned_when_service_runs(self):
        # A user's rfkill block with the service already up: nothing is claimed.
        machine = FakeMachine(active=True, blocked=True, powered=False)
        bluetooth.run = machine.run
        ok, owned, _message = bluetooth.ensure_started()
        self.assertFalse(ok)
        self.assertFalse(owned)
        self.assertFalse(bluetooth.is_owned())

    def test_failed_start_reports_the_reason_and_owns_nothing(self):
        machine = FakeMachine(active=False, blocked=True)
        machine.start_rc = 1
        machine.start_out = "permission denied"
        bluetooth.run = machine.run
        ok, owned, message = bluetooth.ensure_started()
        self.assertFalse(ok)
        self.assertFalse(owned)
        self.assertIn("permission denied", message)
        self.assertFalse(bluetooth.is_owned())

    def test_start_falls_back_to_passwordless_sudo(self):
        machine = FakeMachine(active=False, blocked=False)
        calls = []

        def run(cmd, timeout=2.0):
            calls.append(cmd)
            if cmd[0] == "systemctl" and "start" in cmd:
                return 1, "Interactive authentication required"
            if cmd[0] == "sudo":
                machine.active = True
                return 0, ""
            return machine.run(cmd, timeout)

        bluetooth.run = run
        ok, owned, _message = bluetooth.ensure_started()
        self.assertTrue(ok)
        self.assertTrue(owned)
        self.assertTrue(any(c[:2] == ["sudo", "-n"] for c in calls))

    def test_stop_releases_only_what_it_owns(self):
        machine = FakeMachine(active=True, blocked=False, powered=True)
        bluetooth.run = machine.run
        ok, message = bluetooth.stop()
        self.assertTrue(ok)
        self.assertEqual(message, "not owned")
        self.assertTrue(machine.active, "never stop a service we did not start")
        self.assertEqual(machine.ran("rfkill", "block"), [])

    def test_stop_releases_an_owned_radio_back_to_the_idle_baseline(self):
        machine = FakeMachine(active=False, blocked=True)
        bluetooth.run = machine.run
        bluetooth.ensure_started()
        self.assertTrue(bluetooth.is_owned())
        ok, _message = bluetooth.stop()
        self.assertTrue(ok)
        self.assertFalse(bluetooth.is_owned())
        self.assertFalse(machine.active)
        self.assertTrue(machine.blocked, "the measured idle baseline is radio soft-blocked")

    def test_stop_can_be_forced_past_ownership_for_a_cleanup_path(self):
        machine = FakeMachine(active=True, blocked=False)
        bluetooth.run = machine.run
        ok, message = bluetooth.stop(only_if_owned=False)
        self.assertTrue(ok)
        self.assertFalse(machine.active)
        self.assertNotEqual(message, "not owned")


class Classification(unittest.TestCase):
    def test_inactive_is_off(self):
        self.assertEqual(bluetooth.classify(False, None).status, bluetooth.OFF)

    def test_missing_controller_is_unknown(self):
        self.assertEqual(bluetooth.classify(True, "no controller").status, bluetooth.UNKNOWN)

    def test_powered_is_ok(self):
        self.assertEqual(bluetooth.classify(True, btmgmt(True), None).status, bluetooth.OK)

    def test_missing_powered_capability_is_wedged(self):
        text = (BTMGMT_HEAD + "\tsupported settings: connectable\n"
                + "\tcurrent settings: connectable\n")
        self.assertEqual(bluetooth.classify(True, text, None).status, bluetooth.WEDGED)

    def test_soft_blocked_off_is_reported_as_off(self):
        health = bluetooth.classify(True, btmgmt(False), "Soft blocked: yes\nHard blocked: no\n")
        self.assertEqual(health.status, bluetooth.OFF)
        self.assertIn("rfkill", health.detail)
