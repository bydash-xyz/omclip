"""Bluetooth controller health, and the lifecycle of the radio omclip borrows.

Measured signatures (2026-10-13, on this machine):

* Wedged controller: `bluetoothctl power on` → `org.bluez.Error.Failed`, bluetoothd logs
  `Adv Monitor Manager created with supported features:0x00000000`, and both the monitor
  and discovery backends fail afterwards. A `btusb` reload did not clear it here.
* `bluetoothctl show` is useless while bluetoothd is down (it prints nothing), and it
  can hang for seconds — so health probing uses `btmgmt info` (kernel mgmt socket, works
  without bluetoothd) plus `rfkill`, both cheap and read-only.
* `rfkill` soft-block survives a `bluetooth.service` stop, so a radio omdrop released
  stays unpowerable until something unblocks it. `ensure_started` does, exactly as
  `/usr/lib/omdrop/omdrop-discoverable` does for its own AWDL window.

This machine keeps `bluetooth.service` inactive and the adapter soft-blocked between
windows to hold its ~3.35 W idle — omclip **never** stops a service it did not start, and
releases (stop + `rfkill block`) only the one it did, so `omclip off` returns the machine
to that baseline.
"""

import re
import time

from .discovery import run

BLUETOOTH_UNIT = "bluetooth.service"

#: Controller states reported as `health.bluetooth`.
OK = "ok"
OFF = "off"
WEDGED = "wedged"
UNKNOWN = "unknown"


class BtHealth:
    __slots__ = ("status", "detail")

    def __init__(self, status, detail=None):
        self.status = status
        self.detail = detail

    def __repr__(self):
        return "BtHealth(%s, %s)" % (self.status, self.detail)

    def as_dict(self):
        return {"bluetooth": self.status, "bluetooth_detail": self.detail}


def _setting(text, label):
    match = re.search(r"^\s*%s:\s*(.*)$" % re.escape(label), text, re.MULTILINE)
    return match.group(1).split() if match else None


_OWNED = False

POWER_WAIT_S = 3.0


def is_owned():
    """True while the radio omclip brought up is still omclip's to release."""
    return _OWNED


def set_owned(value):
    global _OWNED
    _OWNED = bool(value)


def service_active():
    """True when `bluetooth.service` is active. Read-only, ~10 ms."""
    rc, out = run(["systemctl", "is-active", BLUETOOTH_UNIT], timeout=2.0)
    return out.strip() == "active"


def soft_blocked():
    """True when rfkill soft-blocks the adapter, which keeps it unpowerable."""
    _rc, out = run(["rfkill", "list", "bluetooth"], timeout=2.0)
    return bool(re.search(r"Soft blocked:\s*yes", out))


def _power_on(deadline, unblock):
    """Power the adapter until `btmgmt` reports it powered.

    `unblock` lifts an rfkill soft-block first — only ever done for a radio omclip
    brought up, since a block the user set is theirs to keep.
    """
    while True:
        if unblock:
            run(["rfkill", "unblock", "bluetooth"], timeout=2.0)
        if run(["bluetoothctl", "power", "on"], timeout=3.0)[0] != 0:
            # bluez may not be on the bus yet; the kernel-level path still works.
            run(["btmgmt", "power", "on"], timeout=3.0)
        _rc, text = run(["btmgmt", "info"], timeout=2.0)
        if "powered" in (_setting(text, "current settings") or []):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def _unpowerable():
    return "adapter did not power on (soft-blocked? try `rfkill unblock bluetooth`)"


def ensure_started(timeout=5.0):
    """Make the adapter usable: service active, and (when we started it) unblocked+powered.

    Returns (ok, owned, message). `owned` is True only when omclip had to bring the
    radio up itself; an already-running `bluetooth.service` is left exactly as it is,
    so `stop()` releases only what this call created.
    """
    global _OWNED
    deadline = time.monotonic() + POWER_WAIT_S
    if service_active():
        # Somebody else's unit: power the adapter, but never touch their rfkill state.
        ok = _power_on(deadline, unblock=_OWNED)
        return ok, _OWNED, None if ok else _unpowerable()

    rc, out = run(["systemctl", "start", BLUETOOTH_UNIT], timeout=timeout)
    if rc != 0:
        rc, out = run(["sudo", "-n", "systemctl", "start", BLUETOOTH_UNIT], timeout=timeout)
    if rc != 0:
        return False, False, "failed to start %s: %s" % (BLUETOOTH_UNIT, out.strip())

    # Ours from here on, even if the adapter refuses to come up: `_tick_omdrop` retries
    # through this function, and the retry must not start claiming someone else's unit.
    _OWNED = True
    ok = _power_on(deadline, unblock=True)
    return ok, True, None if ok else _unpowerable()


def stop(timeout=4.0, only_if_owned=True):
    """Release the radio we brought up: stop the unit, re-block rfkill.

    Returns (ok, message). With `only_if_owned` (the default) a service omclip never
    started is left running — which is what `omclip off` must do.
    """
    global _OWNED
    if only_if_owned and not _OWNED:
        return True, "not owned"
    rc, out = run(["systemctl", "stop", BLUETOOTH_UNIT], timeout=timeout)
    if rc != 0:
        rc, out = run(["sudo", "-n", "systemctl", "stop", BLUETOOTH_UNIT], timeout=timeout)
    # Back to this machine's measured idle baseline: radio off and soft-blocked.
    run(["rfkill", "block", "bluetooth"], timeout=2.0)
    _OWNED = False
    return rc == 0, out.strip() or ("stop %s rc=%d" % (BLUETOOTH_UNIT, rc))


def ensure_running(timeout=5.0):
    """Start `bluetooth.service` without claiming it: put back one omdrop released.

    `omdrop`'s supervisor stops bluetooth.service when its AWDL window closes, so a
    service that was already running when omclip started needs this to survive
    `omclip off`. Never powers, unblocks or blocks anything — it only undoes a stop.
    """
    if service_active():
        return True, "already active"
    rc, out = run(["systemctl", "start", BLUETOOTH_UNIT], timeout=timeout)
    if rc != 0:
        rc, out = run(["sudo", "-n", "systemctl", "start", BLUETOOTH_UNIT], timeout=timeout)
    return rc == 0, out.strip() or ("start %s rc=%d" % (BLUETOOTH_UNIT, rc))

def classify(active, btmgmt_text, rfkill_text=None):
    """Pure classification from the two command outputs (unit-testable).

    * service inactive → `off`
    * no controller reported → `off`
    * controller reports no `powered` capability → `wedged` (features 0x00000000)
    * powered → `ok`
    * supports power but is off, and not soft-blocked → `wedged`
    """
    if not active:
        return BtHealth(OFF, "%s is inactive (normally disabled on this machine): the BLE "
                             "trigger is unavailable; polling still works" % BLUETOOTH_UNIT)
    if not btmgmt_text or "hci" not in btmgmt_text:
        return BtHealth(UNKNOWN, "btmgmt reports no controller")
    supported = _setting(btmgmt_text, "supported settings") or []
    current = _setting(btmgmt_text, "current settings") or []
    if "powered" not in supported:
        return BtHealth(WEDGED, "controller reports no supported settings "
                                "(supported features 0x00000000); needs a btusb reload "
                                "or a reboot")
    if "powered" in current:
        return BtHealth(OK, None)
    if rfkill_text and re.search(r"Soft blocked:\s*yes", rfkill_text):
        return BtHealth(OFF, "adapter soft-blocked (rfkill); unblock with "
                             "`rfkill unblock bluetooth`")
    return BtHealth(WEDGED, "adapter reports powered off while %s runs; a btusb reload "
                            "or a reboot is normally needed" % BLUETOOTH_UNIT)


def probe(active=None):
    """Live health: (status, detail). Never raises, never mutates anything."""
    if active is None:
        active = service_active()
    if not active:
        return classify(False, None)
    _rc, btmgmt = run(["btmgmt", "info"], timeout=2.0)
    _rc2, rfkill = run(["rfkill", "list", "bluetooth"], timeout=2.0)
    return classify(True, btmgmt, rfkill)
