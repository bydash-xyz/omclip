"""Handoff `0x0c` BLE announcements — the optional poll trigger.

Ground truth (from BLE Continuity research captures): Apple manufacturer data
`0x004c` carrying Continuity TLV `0x0c` has byte 0 = status (`0x08` = clipboard
available), bytes 1-2 = little-endian counter (+1 per advertisement), the rest sealed.
Peers only advertise while their user is active, and **BLE addresses rotate**, so a
`0x0c` frame is never allowed to gate correctness — it only makes the next poll round
happen sooner.

The listener itself needs BlueZ's `org.bluez.AdvertisementMonitor1` over D-Bus with
PyGObject (`gi`/`dbus`), which is **not** the standard library. It is therefore an
optional accelerator, imported lazily and guarded: absent bindings, an inactive
`bluetooth.service` or a failed registration is one `warn` line and timed polling
forever after. No discovery-mode fallback — an active scan costs 2-5 % CPU and would
fight `omdrop`'s advertiser for the shared 2.4 GHz antenna.

The TLV splitting/decoding is pinned by offline tests against real captures.
"""

import threading
import time

APPLE = 0x004C
T_HANDOFF = 0x0C
ST_CLIPBOARD = 0x08

MONITOR_ROOT = "/org/omarchy/omclip_ble"
HANDOFF_IFACE = "org.bluez.AdvertisementMonitor1"

#: D-Bus timeout for `RegisterMonitor` (seconds). Bounded well below the 25 s default
#: so a wedged Adv Monitor Manager reports its real error instead of a bare timeout.
REGISTER_TIMEOUT_S = 2.5


# --------------------------------------------------------------------------
# pure TLV handling (no Bluetooth, no D-Bus)
# --------------------------------------------------------------------------

def apple_tlvs(blob):
    """Split Apple manufacturer data into {type: value}, first occurrence wins."""
    out, i = {}, 0
    while i + 2 <= len(blob):
        t, n = blob[i], blob[i + 1]
        out.setdefault(t, bytes(blob[i + 2:i + 2 + n]))
        i += 2 + n
    return out


def decode_handoff(tlv):
    """(status, counter) from a `0x0c` TLV, or None if it is too short."""
    if tlv is None or len(tlv) < 3:
        return None
    return tlv[0], int.from_bytes(tlv[1:3], "little")


def clipboard_advertised(status):
    """True when the 0x0c status byte says a clipboard item is available."""
    return bool(status & ST_CLIPBOARD)


def parse_manufacturer_data(blob):
    """(addr-less) decode helper: {0x004c: bytes} → (status, counter, tlv) or None."""
    tlv = apple_tlvs(bytes(blob)).get(T_HANDOFF)
    parsed = decode_handoff(tlv) if tlv is not None else None
    if parsed is None:
        return None
    return parsed[0], parsed[1], tlv


# --------------------------------------------------------------------------
# optional BlueZ Advertisement Monitor
# --------------------------------------------------------------------------

def dependencies():
    """(ok, reason) for the optional `gi`/`dbus` bindings."""
    try:
        import dbus  # noqa: F401
        import dbus.mainloop.glib  # noqa: F401
        import dbus.service  # noqa: F401
        from gi.repository import GLib  # noqa: F401
    except Exception as exc:                      # noqa: BLE001 - any import failure
        return False, "python gi/dbus bindings unavailable (%s)" % exc
    return True, "ok"


class BleMonitor:
    """Runs the Advertisement Monitor in a daemon thread; calls `callback(addr, status, counter, tlv)`.

    `start()` returns (ok, backend_or_reason) and only returns once the monitor is
    registered (or has failed), so the caller can log exactly one line and forget it.
    """

    def __init__(self, callback, adapter="hci0", log=None):
        self.callback = callback
        self.adapter = adapter
        self.log = log
        self.backend = "unavailable"
        self.reason = None
        self._thread = None
        self._loop = None
        self._bus = None
        self._manager = None
        self._ready = threading.Event()
        self._seen = {}
        self._rssi = {}
        self._register_timeout = REGISTER_TIMEOUT_S

    # -- lifecycle ---------------------------------------------------------

    def start(self, timeout=3.0):
        ok, reason = dependencies()
        if not ok:
            self.reason = reason
            return False, reason
        # `RegisterMonitor` is bounded inside the wait: a bluetoothd whose Adv Monitor
        # Manager was created with no supported features accepts the call and never
        # answers, which would otherwise surface only at D-Bus's 25 s default timeout.
        self._register_timeout = max(0.5, timeout - 0.5)
        self._thread = threading.Thread(target=self._run, name="omclip-ble", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            self.reason = "advertisement monitor did not register within %.1fs" % timeout
            return False, self.reason
        return (True, self.backend) if self.reason is None else (False, self.reason)

    def stop(self):
        try:
            if self._manager is not None:
                import dbus
                self._manager.UnregisterMonitor(dbus.ObjectPath(MONITOR_ROOT))
        except Exception:                          # noqa: BLE001 - best effort
            pass
        if self._loop is not None:
            try:
                self._loop.quit()
            except Exception:                      # noqa: BLE001
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._thread = None

    # -- thread body -------------------------------------------------------

    def _run(self):
        try:
            import dbus
            import dbus.mainloop.glib
            import dbus.service
            from gi.repository import GLib
        except Exception as exc:                   # noqa: BLE001
            self.reason = "bindings vanished: %s" % exc
            self._ready.set()
            return
        try:
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            bus = dbus.SystemBus()
            adapter = bus.get_object("org.bluez", "/org/bluez/%s" % self.adapter)
            types = adapter.Get("org.bluez.AdvertisementMonitorManager1", "SupportedMonitorTypes",
                                dbus_interface="org.freedesktop.DBus.Properties")
        except Exception as exc:                   # noqa: BLE001
            self.reason = ("bluetoothd has no advertisement monitor (%s); needs "
                           "bluetooth.service running with --experimental" % exc)
            self._ready.set()
            return
        if "or_patterns" not in types:
            self.reason = ("bluetoothd offers monitor types %s, no or_patterns" % list(types))
            self._ready.set()
            return

        callback = self.callback
        seen, rssi = self._seen, self._rssi

        class _Monitor(dbus.service.Object):
            def __init__(self, path):
                super().__init__(bus, path)

            @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s",
                                 out_signature="a{sv}")
            def GetAll(self, iface):
                if iface != HANDOFF_IFACE:
                    return {}
                # RSSISamplingPeriod 0 = pass every packet (0xFF passes only the first
                # per device, which would hide every later beacon).
                return {
                    "Type": "or_patterns",
                    "RSSISamplingPeriod": dbus.UInt16(0),
                    "Patterns": dbus.Array(
                        [dbus.Struct((dbus.Byte(0), dbus.Byte(0xFF),
                                      dbus.Array([dbus.Byte(b) for b in b"\x4c\x00\x0c"],
                                                 signature="y"))),
                         ], signature="(yyay)"),
                }

            @dbus.service.method(HANDOFF_IFACE)
            def Activate(self):
                pass

            @dbus.service.method(HANDOFF_IFACE)
            def Release(self):
                pass

            @dbus.service.method(HANDOFF_IFACE, in_signature="o")
            def DeviceFound(self, device):
                self._found(str(device))

            @dbus.service.method(HANDOFF_IFACE, in_signature="o")
            def DeviceLost(self, device):
                pass

            def _found(self, path):
                try:
                    props = bus.get_object("org.bluez", path).GetAll(
                        "org.bluez.Device1", dbus_interface="org.freedesktop.DBus.Properties")
                except Exception:                  # noqa: BLE001
                    return
                if "RSSI" in props:
                    rssi[path] = int(props["RSSI"])
                blob = (props.get("ManufacturerData") or {}).get(dbus.UInt16(APPLE))
                if blob is None:
                    return
                parsed = parse_manufacturer_data(bytes(blob))
                if parsed is None:
                    return
                status, counter, tlv = parsed
                if tlv in seen:
                    return
                now = time.monotonic()
                seen[tlv] = now
                if len(seen) > 256:
                    for key, at in list(seen.items()):
                        if now - at > 120:
                            del seen[key]
                addr = path.rsplit("dev_", 1)[-1].replace("_", ":")
                try:
                    callback(addr, status, counter, tlv)
                except Exception as exc:            # noqa: BLE001 - never kill the loop
                    if self.log is not None:
                        self.log.warn("ble callback failed: %s" % exc)

        class _MonitorApp(dbus.service.Object):
            def __init__(self, path, monitor):
                self.monitor = monitor
                super().__init__(bus, path)

            @dbus.service.method("org.freedesktop.DBus.ObjectManager",
                                 out_signature="a{oa{sa{sv}}}")
            def GetManagedObjects(self):
                return {dbus.ObjectPath(MONITOR_ROOT + "/monitor"):
                        {HANDOFF_IFACE: self.monitor.GetAll(HANDOFF_IFACE)}}

        monitor = _Monitor(MONITOR_ROOT + "/monitor")
        app = _MonitorApp(MONITOR_ROOT, monitor)     # noqa: F841 - kept alive by the loop
        self._bus = bus
        self._loop = GLib.MainLoop()
        manager = dbus.Interface(adapter, "org.bluez.AdvertisementMonitorManager1")

        # Asynchronous, with the loop already running: bluetoothd answers RegisterMonitor
        # only after it has called our GetManagedObjects, and a blocking call made before
        # `loop.run()` cannot serve that call — both sides wait until the D-Bus timeout
        # (measured 2026-10-13: `NoReply` on every start, read as a wedged controller).
        def registered():
            self._manager = manager
            self.backend = "monitor"
            self._ready.set()

        def failed(exc):
            self.reason = "RegisterMonitor failed: %s" % exc
            self._ready.set()
            self._loop.quit()

        try:
            manager.RegisterMonitor(dbus.ObjectPath(MONITOR_ROOT),
                                    reply_handler=registered, error_handler=failed,
                                    timeout=self._register_timeout)
        except Exception as exc:                   # noqa: BLE001
            failed(exc)
            return
        try:
            self._loop.run()
        except Exception:                          # noqa: BLE001
            pass
