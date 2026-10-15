"""Handoff `0x0c` TLV handling, pinned to real captured frames.

Real captures used:

* A Mac frame captured 2026-10-11 18:32:54, right after a copy (status 0x08,
  counter 0x37ff, 10 sealed bytes, followed by a Nearby Info TLV 0x10).
* Beacon bodies from a 2026-10-11 btmon capture:
  `08ff3793e7c038f32d72006998ff` (clipboard advertised) and
  `0000385d4bffa1d78a3ce55aea8d` (status 0x00: nothing to fetch).

The listener needs BlueZ + PyGObject; this file pins the pure parsing that the
timed-polling fallback and the trigger decision rely on, and drives the real
`BleMonitor._run()` registration against a hermetic fake of bluetoothd's Adv Monitor
Manager — no D-Bus, no controller, no GLib.
"""

import sys
import threading
import time
import types
import unittest
from unittest import mock

import _support  # noqa: F401
from omclip import ble

#: Apple manufacturer data: Handoff TLV 0x0c then Nearby Info 0x10.
MAC_FRAME = bytes.fromhex("0c0e" "08ff3793e7c038f32d72006998ff" "1006" "401dbffe5e58")
#: Raw 0x0c bodies straight out of the capture file.
CLIPBOARD_TLV = bytes.fromhex("08ff3793e7c038f32d72006998ff")
NO_CLIPBOARD_TLV = bytes.fromhex("0000385d4bffa1d78a3ce55aea8d")
#: A replay payload the live client sends as `rAdvPayload` (2019 Handoff-Swift capture).
REPLAY_PAYLOAD = bytes.fromhex("a1072cb8bf1d9818ac")


class TlvSplitting(unittest.TestCase):
    def test_manufacturer_data_is_split_by_tlv(self):
        tlvs = ble.apple_tlvs(MAC_FRAME)
        self.assertEqual(tlvs[0x0C].hex(), "08ff3793e7c038f32d72006998ff")
        self.assertEqual(tlvs[0x10].hex(), "401dbffe5e58")

    def test_truncated_and_empty_input(self):
        self.assertEqual(ble.apple_tlvs(b""), {})
        self.assertEqual(ble.apple_tlvs(b"\x0c"), {})
        # A TLV whose declared length runs past the end keeps whatever is there.
        self.assertEqual(ble.apple_tlvs(b"\x0c\x05ab")[0x0C], b"ab")

    def test_length_prefixed_values_are_not_merged(self):
        blob = bytes.fromhex("0c02aabb" "0c02ccdd")
        self.assertEqual(ble.apple_tlvs(blob)[0x0C].hex(), "aabb")


class Decoding(unittest.TestCase):
    def test_status_and_counter(self):
        self.assertEqual(ble.decode_handoff(CLIPBOARD_TLV), (0x08, 0x37FF))
        self.assertEqual(ble.decode_handoff(NO_CLIPBOARD_TLV), (0x00, 0x3800))
        self.assertEqual(ble.decode_handoff(REPLAY_PAYLOAD), (0xA1, 0x2C07))

    def test_too_short_is_none(self):
        self.assertIsNone(ble.decode_handoff(b""))
        self.assertIsNone(ble.decode_handoff(b"\x08"))
        self.assertIsNone(ble.decode_handoff(b"\x08\xff"))
        self.assertIsNone(ble.decode_handoff(None))

    def test_counter_is_little_endian(self):
        self.assertEqual(ble.decode_handoff(bytes.fromhex("080100")), (0x08, 1))
        self.assertEqual(ble.decode_handoff(bytes.fromhex("08ff01")), (0x08, 0x01FF))


class Trigger(unittest.TestCase):
    def test_only_a_clipboard_advertisement_triggers(self):
        self.assertTrue(ble.clipboard_advertised(0x08))
        self.assertFalse(ble.clipboard_advertised(0x00))
        self.assertFalse(ble.clipboard_advertised(0x02))

    def test_status_bits_are_masked(self):
        # The status byte is a bit field: 0x08 is "clipboard available".
        self.assertTrue(ble.clipboard_advertised(0x0A))
        self.assertTrue(ble.clipboard_advertised(0x88))

    def test_parse_manufacturer_data(self):
        self.assertEqual(ble.parse_manufacturer_data(MAC_FRAME), (0x08, 0x37FF,
                                                                 CLIPBOARD_TLV))
        self.assertIsNone(ble.parse_manufacturer_data(bytes.fromhex("1006" "401dbffe5e58")))
        self.assertIsNone(ble.parse_manufacturer_data(b""))

    def test_captured_idle_mac_beacon_does_not_trigger(self):
        # 2026-10-11 capture at t=16.70: the Mac announced status 0x00 while idle.
        self.assertFalse(ble.clipboard_advertised(ble.decode_handoff(NO_CLIPBOARD_TLV)[0]))


class OptionalBackend(unittest.TestCase):
    def test_dependency_probe_returns_a_reason(self):
        ok, reason = ble.dependencies()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)
        self.assertTrue(reason)
        if ok:
            self.assertEqual(reason, "ok")

    def test_monitor_is_unavailable_without_a_controller(self):
        # Registration failures are reported, never raised: the daemon must fall back to
        # timed polling with one warn line.
        monitor = ble.BleMonitor(lambda *args: None)
        ok, reason = monitor.start(timeout=3.0)
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)
        monitor.stop()

    def test_register_call_is_bounded_inside_the_start_timeout(self):
        # A bluetoothd whose Adv Monitor Manager never answers must fail with its own
        # D-Bus error before `start()` gives up, not at D-Bus's 25 s default.
        monitor = ble.BleMonitor(lambda *args: None)

        def fake_run():                              # no D-Bus, no thread body
            monitor.backend = "monitor"
            monitor._ready.set()

        monitor._run = fake_run
        ok, backend = monitor.start(timeout=3.0)
        self.assertTrue(ok)
        self.assertEqual(backend, "monitor")
        self.assertLess(monitor._register_timeout, 3.0)
        self.assertGreater(monitor._register_timeout, 0.0)


# --------------------------------------------------------------------------
# hermetic Adv Monitor Manager: the real `_run()` registration, no D-Bus at all
#
# `_run()` imports `dbus`/`gi` lazily, so patching `sys.modules` drives the production
# code exactly as it is written — `ble.py` needs no seam for this. The fake reproduces
# the detail that made `RegisterMonitor` fail with `NoReply` on every start (d09c131):
# bluetoothd answers only *after* it has called the app's `GetManagedObjects`, and only
# a running GLib loop can serve that call.
# --------------------------------------------------------------------------


class _FakeError(Exception):
    """Stands in for `dbus.exceptions.DBusException`."""


#: What `RegisterMonitor` came back with on every start before d09c131.
NO_REPLY = ("org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes "
            "include: the remote application did not send a reply, the message bus security "
            "policy blocked the reply, the reply timeout expired, or the network connection "
            "was broken.")


class _FakeLoop:
    """A `GLib.MainLoop` that runs queued callbacks only while `run()` is on the stack."""

    def __init__(self, state):
        self.state = state
        self.running = False
        self.quit_called = False
        self.run_calls = 0
        self._wake = threading.Event()

    def run(self):
        self.run_calls += 1
        self.running = True
        try:
            while not self.quit_called:
                pending, self.state.pending = self.state.pending, []
                for fn in pending:
                    fn()
                if self.quit_called:
                    break
                self._wake.wait(0.01)
                self._wake.clear()
        except BaseException as exc:              # recorded, so a broken callback is visible
            self.state.errors.append(exc)
            raise
        finally:
            self.running = False

    def wake(self):
        self._wake.set()

    def quit(self):
        self.quit_called = True
        self.state.abort.set()
        self._wake.set()


class _FakeBusState:
    """Everything the `dbus`/`gi` bindings inside `_run()` end up talking to.

    `mode` is what the fake bluetoothd does with `RegisterMonitor`: `"ok"` answers it,
    `"error"` calls the error_handler, `"silent"` accepts it and never answers (a wedged
    Adv Monitor Manager) and `"raise"` fails the call itself.
    """

    def __init__(self, mode="ok"):
        self.mode = mode
        self.register_calls = []
        self.deadlocks = 0
        self.managed_objects_calls = 0
        self.managed_objects_served_running = False
        self.served_objects = None
        self.delivered_while_running = False
        self.objects = {}
        self.devices = {}
        self.pending = []
        self.errors = []
        self.abort = threading.Event()
        self.gmainloop_calls = []
        self.adapter_path = None
        self.remote_error = _FakeError("org.bluez.Error.NotSupported: Operation Not Supported")
        self.raise_error = _FakeError("org.bluez.Error.NotPermitted: operation not permitted")
        self.bus = _FakeBus(self)
        self.adapter = _FakeAdapter(self)
        self.manager = _FakeAdvManager(self)
        self.loop = _FakeLoop(self)

    # -- dispatch ----------------------------------------------------------

    def schedule(self, fn):
        self.pending.append(fn)
        self.loop.wake()

    def deliver(self, call):
        """bluetoothd's answer to `RegisterMonitor`, dispatched by the running loop."""
        self.delivered_while_running = self.loop.running
        if self.mode == "silent":
            return
        if self.mode == "error":
            call["error_handler"](self.remote_error)
            return
        # The ObjectManager round trip bluetoothd makes before answering.
        self.managed_objects_calls += 1
        self.managed_objects_served_running = bool(self.loop.running)
        self.served_objects = self.objects[ble.MONITOR_ROOT].GetManagedObjects()
        call["reply_handler"]()

    def await_loop(self, timeout):
        """True if `loop.run()` was entered before `timeout` (or the fixture gave up)."""
        deadline = time.monotonic() + (timeout or 0.0)
        while time.monotonic() < deadline:
            if self.loop.running:
                return True
            if self.abort.is_set():
                break
            time.sleep(0.005)
        return self.loop.running

    def release(self):
        self.abort.set()
        self.loop.quit()


class _FakeBus:
    def __init__(self, state):
        self.state = state

    def get_object(self, name, path):
        if name != "org.bluez":
            raise _FakeError("org.freedesktop.DBus.Error.ServiceUnknown: %s" % name)
        if str(path).startswith("/org/bluez/hci"):
            self.state.adapter_path = str(path)
            return self.state.adapter
        return _FakeRemoteDevice(self.state, str(path))


class _FakeRemoteDevice:
    def __init__(self, state, path):
        self.state = state
        self.path = path

    def GetAll(self, iface, dbus_interface=None):
        return dict(self.state.devices.get(self.path, {}))


class _FakeAdapter:
    """`org.bluez.Adapter1`, which also carries the Adv Monitor Manager properties."""

    def __init__(self, state):
        self.state = state

    def Get(self, iface, prop, dbus_interface=None):
        if prop == "SupportedMonitorTypes":
            return ["or_patterns"]
        raise _FakeError("org.freedesktop.DBus.Error.UnknownProperty: %s" % prop)


class _FakeAdvManager:
    """`org.bluez.AdvertisementMonitorManager1` as bluetoothd presents it."""

    def __init__(self, state):
        self.state = state
        self.unregistered = []

    def RegisterMonitor(self, path, reply_handler=None, error_handler=None, timeout=None):
        state = self.state
        call = {"path": str(path), "reply_handler": reply_handler,
                "error_handler": error_handler, "timeout": timeout,
                "loop_running_when_issued": state.loop.running}
        state.register_calls.append(call)
        if state.mode == "raise":
            raise state.raise_error
        if reply_handler is None and error_handler is None:
            # The pre-d09c131 shape: a blocking call made before `loop.run()`. bluetoothd
            # consults GetManagedObjects before it answers, and the only dispatcher for
            # that call is the loop this caller has not entered — the two sides wait for
            # each other until the call's own D-Bus timeout comes back as `NoReply`.
            state.deadlocks += 1
            state.await_loop(timeout)
            raise _FakeError(NO_REPLY)
        state.schedule(lambda: state.deliver(call))

    def UnregisterMonitor(self, path):
        self.unregistered.append(str(path))


class _FakeServiceObject:
    """`dbus.service.Object`: exports itself on the bus under its path."""

    def __init__(self, bus, path):
        bus.state.objects[str(path)] = self


def _fake_modules(state):
    """`sys.modules` entries for the lazy `dbus`/`gi` imports inside `_run()`."""
    def method(_iface, in_signature=None, out_signature=None):
        return lambda fn: fn

    dbus = types.ModuleType("dbus")
    dbus.SystemBus = lambda: state.bus
    dbus.Interface = lambda obj, iface: state.manager
    dbus.ObjectPath = str
    dbus.UInt16 = int
    dbus.Byte = int
    dbus.Array = lambda items, signature=None: list(items)
    dbus.Struct = lambda fields, signature=None: tuple(fields)

    exceptions = types.ModuleType("dbus.exceptions")
    exceptions.DBusException = _FakeError
    dbus.exceptions = exceptions

    service = types.ModuleType("dbus.service")
    service.Object = _FakeServiceObject
    service.method = method
    dbus.service = service

    mainloop = types.ModuleType("dbus.mainloop")
    glib = types.ModuleType("dbus.mainloop.glib")
    glib.DBusGMainLoop = lambda **kwargs: state.gmainloop_calls.append(kwargs)
    mainloop.glib = glib
    dbus.mainloop = mainloop

    gi = types.ModuleType("gi")
    repository = types.ModuleType("gi.repository")
    glib_mod = types.ModuleType("gi.repository.GLib")
    glib_mod.MainLoop = lambda: state.loop
    repository.GLib = glib_mod
    gi.repository = repository

    return {"dbus": dbus, "dbus.exceptions": exceptions, "dbus.service": service,
            "dbus.mainloop": mainloop, "dbus.mainloop.glib": glib,
            "gi": gi, "gi.repository": repository, "gi.repository.GLib": glib_mod}


class AsyncRegistration(unittest.TestCase):
    """`_run()`'s registration, driven against a fake Adv Monitor Manager.

    Nothing here reaches a real bus, controller or GLib: the entire backend is the
    `sys.modules` patch built by `_fake_modules()`, so `start()` exercises the code that
    runs on the daemon's BLE thread.
    """

    def fake_monitor(self, mode="ok"):
        state = _FakeBusState(mode)
        self.enterContext(mock.patch.dict(sys.modules, _fake_modules(state)))
        monitor = ble.BleMonitor(lambda *args: None)
        self.addCleanup(state.release)          # runs last: unblocks anything still waiting
        self.addCleanup(monitor.stop)           # runs first: unregister needs the fake dbus
        return state, monitor

    def test_registration_reply_marks_the_monitor_usable(self):
        state, monitor = self.fake_monitor()
        ok, backend = monitor.start()
        self.assertTrue(ok, backend)
        self.assertEqual(backend, "monitor")
        self.assertEqual(monitor.backend, "monitor")
        self.assertIsNone(monitor.reason)
        self.assertTrue(monitor._ready.is_set())
        self.assertIs(monitor._manager, state.manager)
        self.assertEqual(state.adapter_path, "/org/bluez/hci0")
        self.assertEqual(state.loop.run_calls, 1)

        (call,) = state.register_calls
        self.assertEqual(call["path"], ble.MONITOR_ROOT)
        self.assertFalse(state.deadlocks)
        # A reply/error pair, not a bare blocking call: without them bluetoothd's answer
        # could only ever surface as a D-Bus timeout, never as a registration.
        self.assertTrue(callable(call["reply_handler"]))
        self.assertTrue(callable(call["error_handler"]))
        self.assertEqual(call["timeout"], ble.REGISTER_TIMEOUT_S)
        self.assertLess(ble.REGISTER_TIMEOUT_S, 25.0)

    def test_the_running_loop_serves_bluetoothds_get_managed_objects(self):
        # The deadlock regression d09c131 fixed: RegisterMonitor is issued before the
        # loop runs, and bluetoothd's GetManagedObjects round trip — plus its answer —
        # is dispatched from inside that loop. Issued as a blocking call first, neither
        # side can proceed and every start ends in NoReply (see state.deadlocks).
        state, monitor = self.fake_monitor()
        ok, backend = monitor.start(timeout=1.0)
        self.assertTrue(ok, backend)
        self.assertEqual(backend, "monitor")

        (call,) = state.register_calls
        self.assertFalse(call["loop_running_when_issued"])
        self.assertEqual(state.managed_objects_calls, 1)
        self.assertTrue(state.managed_objects_served_running)
        self.assertTrue(state.delivered_while_running)
        self.assertFalse(state.deadlocks)
        self.assertEqual(state.errors, [])

        # The app answered with what it exports for a `0x0c` Adv Monitor.
        props = state.served_objects[ble.MONITOR_ROOT + "/monitor"][ble.HANDOFF_IFACE]
        self.assertEqual(props["Type"], "or_patterns")
        self.assertEqual(props["RSSISamplingPeriod"], 0)          # 0 = every packet
        self.assertEqual([bytes(pattern[2]) for pattern in props["Patterns"]],
                         [b"\x4c\x00\x0c"])                       # Apple, 0x0c

    def test_register_error_is_reported_as_a_reason_not_an_exception(self):
        state, monitor = self.fake_monitor("error")
        ok, reason = monitor.start(timeout=1.0)      # never raises: one warn line
        self.assertFalse(ok)
        self.assertIn("RegisterMonitor failed: org.bluez.Error.NotSupported", reason)
        self.assertEqual(reason, monitor.reason)
        self.assertEqual(monitor.backend, "unavailable")
        self.assertIsNone(monitor._manager)
        self.assertTrue(monitor._ready.is_set())
        self.assertTrue(state.loop.quit_called)
        monitor._thread.join(1.0)
        self.assertFalse(monitor._thread.is_alive())

    def test_register_raising_synchronously_fails_gracefully(self):
        state, monitor = self.fake_monitor("raise")
        ok, reason = monitor.start(timeout=1.0)      # never raises
        self.assertFalse(ok)
        self.assertEqual(reason, "RegisterMonitor failed: org.bluez.Error.NotPermitted: "
                                 "operation not permitted")
        self.assertEqual(monitor.reason, reason)
        self.assertEqual(monitor.backend, "unavailable")
        self.assertIsNone(monitor._manager)
        self.assertEqual(state.loop.run_calls, 0)    # nothing left to serve: `_run` returns
        self.assertFalse(state.loop.running)

    def test_a_wedged_manager_hits_the_bounded_register_timeout(self):
        # An Adv Monitor Manager that accepts the call and never answers must be reported
        # by `start()`, not left to D-Bus's 25 s default.
        state, monitor = self.fake_monitor("silent")
        started = time.monotonic()
        ok, reason = monitor.start(timeout=0.6)
        elapsed = time.monotonic() - started
        self.assertFalse(ok)
        self.assertIn("advertisement monitor did not register within 0.6s", reason)
        self.assertEqual(monitor.reason, reason)
        self.assertEqual(monitor.backend, "unavailable")
        self.assertIsNone(monitor._manager)
        self.assertLess(elapsed, 1.5)                # bounded, not the 25 s D-Bus default

        (call,) = state.register_calls
        self.assertEqual(call["timeout"], monitor._register_timeout)
        self.assertLess(call["timeout"], 25.0)
        self.assertEqual(state.loop.run_calls, 1)    # the loop was up while it waited


if __name__ == "__main__":
    unittest.main()
