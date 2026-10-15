// SPDX-License-Identifier: MIT
// Bound is what makes the `root.fg` / `root.fontFamily` references inside this
// file's inline components and Repeater delegates legal to qmllint and to the
// QML compiler: the outer ids resolve statically instead of through a copied
// context. Delegates therefore declare their model data as required
// properties.
pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// omclip panel. Owns every conversation with the CLI: the polling, the status
// snapshot, the daemon's config and the on/off actions. BarWidget.qml only
// draws a summary of what lands here.
//
// It is a consumer panel, not a dashboard: a switch, the two devices, the last
// thing that crossed, and the two switches a person actually changes. The
// internals — socket health, the log tail, skip counters, credential file
// paths, addresses and ports — are the CLI's business (`omclip status --json`,
// `omclip log`, `omclip doctor`), not the desktop's.
//
// Everything the panel shows comes from `omclip --json`, parsed with
// JSON.parse. Human output is never parsed, and a malformed answer never
// invents state: the last good snapshot stays on screen with a stale marker,
// which is why there is a `pollFailed` distinct from the daemon's own
// `stale` field.
//
// The panel must survive omclip not being installed at all — that is the
// state of every machine until install.sh has run — so the pill, the toggle
// and the IPC target all work with no CLI present.
Panel {
  id: root
  moduleName: "bxshi.omclip"
  ipcTarget: "bxshi.omclip"
  manageIpc: false

  property var anchorItem: null
  property bool openedFromHotkey: false
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  // ---- Theme hooks ---------------------------------------------------------
  // Every colour and size comes from the bar / Color / Style singletons, so
  // the panel re-skins with the Omarchy theme and no literal colour exists in
  // this file.
  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property color accent: Color.accent
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color warnColor: Qt.tint(accent, Util.alpha(urgent, 0.55))
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color dim: Util.alpha(fg, 0.66)
  readonly property color dimmer: Util.alpha(fg, 0.46)
  readonly property color cardFill: Util.alpha(fg, 0.035)
  readonly property int radius: Style.cornerRadius

  // Glyphs, verified against JetBrainsMono Nerd Font's cmap, kept as escapes:
  // private-use glyphs get dropped when a file is written through some editors.
  readonly property string glyphClipboard: "\udb80\udc45"      // md-clipboard
  readonly property string glyphClipboardOn: "\udb80\udc4c"    // md-clipboard_check
  readonly property string glyphClipboardOff: "\udb85\udd18"   // md-clipboard_off
  readonly property string glyphClipboardWait: "\udb81\uddc6"  // md-clipboard_flow
  readonly property string glyphAlert: "\udb80\udc47"          // md-clipboard_alert
  readonly property string glyphLaptop: "\udb80\ude20"         // md-laptop
  readonly property string glyphPhone: "\udb80\udc1a"          // md-cellphone
  readonly property string glyphCircle: "\udb82\udcdd"         // md-circle_small

  readonly property string macHandoffDir: {
    // The daemon's own config points to the identity directory; fallback to
    // ~/.config/omclip if not set.
    var dir = String(cfg.identity_dir || "")
    var cut = dir.lastIndexOf("/")
    if (cut > 0) return dir.substring(0, cut)
    return home ? (home + "/.config/omclip") : ""
  }

  function levelColor(level) { return level >= 2 ? urgent : (level === 1 ? accent : dimmer) }

  // ---- Settings ------------------------------------------------------------
  function num(key, def) { var v = parseInt(setting(key, def), 10); return isNaN(v) ? def : v }
  readonly property int pollSeconds: Math.max(1, num("pollSeconds", 2))
  readonly property bool notifyDefault: setting("notify", true) === true || String(setting("notify", true)) === "true"

  // ---- Paths ---------------------------------------------------------------
  readonly property string home: Quickshell.env("HOME") || ""
  // The install directory this file was loaded from. Install.sh links
  // ~/.config/omarchy/plugins/bxshi.omclip here, so it is the same folder.
  readonly property string pluginDir: {
    var u = String(Qt.resolvedUrl("."))
    if (u.indexOf("file://") === 0) u = u.substring(7)
    return decodeURIComponent(u).replace(/\/+$/, "")
  }
  readonly property string localCli: pluginDir + "/bin/omclip"
  readonly property string userCli: home + "/.local/bin/omclip"
  property string cli: userCli
  property bool installed: false

  // Resolve the CLI the way the contract names it — ~/.local/bin/omclip, the
  // symlink install.sh makes — and fall back to the copy shipped beside these
  // files so the widget still works before install.sh has run.
  //
  // Both Process objects below are driven through `startProc`, never by
  // assigning `running: true` straight to an already-stuck object: when the
  // binary is missing, Quickshell's process fails to start and leaves
  // `running` set with nothing behind it, so a guard on that flag would
  // silently disable polling (and the re-probe) for the rest of the session.
  function startProc(proc) {
    proc.running = false
    proc.running = true
  }

  Process {
    id: locateProc
    command: ["bash", "-c", "for p in \"$1\" \"$2\"; do if [[ -x $p ]]; then printf '%s' \"$p\"; exit 0; fi; done; exit 1",
              "bash", root.userCli, root.localCli]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var p = String(text || "").trim()
        if (p !== "") root.cli = p
      }
    }
    onExited: function(code) {
      if (code === 0) root.installed = true
      // The probe is the first thing that runs, so this is also what starts
      // the first poll once the CLI path is known.
      root.refreshNow()
    }
  }

  // While nothing is installed there is no other process to notice install.sh
  // having run: the status timer is gated on `installed`. A slow re-probe is
  // what picks the CLI up without making the user restart the shell, and it
  // costs one bash per half minute until then.
  Timer {
    interval: 30000
    repeat: true
    running: !root.installed
    onTriggered: if (!locateProc.running) root.startProc(locateProc)
  }

  onCliChanged: root.refreshNow()

  // ---- Status snapshot -----------------------------------------------------
  property var snap: null
  property bool pollFailed: false
  property double lastGoodMs: 0
  property bool actionBusy: false
  property bool turningOn: false
  property bool turningOff: false
  readonly property bool busy: actionBusy || turningOn || turningOff
  property string actionError: ""

  property string busyDots: ""
  Timer {
    interval: 350
    repeat: true
    running: root.turningOn || root.turningOff || root.clipState === "starting" || root.actionBusy
    onTriggered: {
      if (root.busyDots === "") root.busyDots = "."
      else if (root.busyDots === ".") root.busyDots = ".."
      else if (root.busyDots === "..") root.busyDots = "..."
      else root.busyDots = ""
    }
    onRunningChanged: if (!running) root.busyDots = ""
  }

  Timer {
    id: transitionWatchdog
    interval: 15000
    repeat: false
    onTriggered: {
      if (root.turningOn || root.turningOff) {
        if (root.actionError === "") {
          root.actionError = root.turningOn ? "Starting omclip timed out" : "Stopping omclip timed out"
        }
        root.turningOn = false
        root.turningOff = false
      }
    }
  }

  readonly property bool haveSnap: snap !== null
  readonly property string clipState: (snap && typeof snap.state === "string") ? snap.state : "off"
  readonly property bool starting: turningOn || clipState === "starting"
  readonly property bool on: snap ? (snap.on === true || clipState === "on" || clipState === "starting") : false
  readonly property bool daemonStale: snap ? (snap.stale === true && !starting) : false
  readonly property bool stale: !starting && (pollFailed || daemonStale)
  function consolidatePeers(list) {
    if (!Array.isArray(list)) return []
    var out = []
    var seen = {}
    for (var i = 0; i < list.length; i++) {
      var p = list[i]
      if (!p) continue
      var label = String(p.label || p.key || "").trim().toLowerCase()
      if (seen[label] !== undefined) {
        var prevIdx = seen[label]
        if (p.transport === "lan" && out[prevIdx].transport !== "lan") {
          out[prevIdx] = p
        }
        continue
      }
      seen[label] = out.length
      out.push(p)
    }
    return out
  }

  readonly property var peers: consolidatePeers((snap && Array.isArray(snap.peers)) ? snap.peers : [])
  readonly property var clipInfo: (snap && snap.clipboard && typeof snap.clipboard === "object") ? snap.clipboard : ({})
  readonly property var credentials: (snap && Array.isArray(snap.credentials)) ? snap.credentials : []
  readonly property var statusErrors: (snap && Array.isArray(snap.errors)) ? snap.errors : []

  readonly property int livePeers: {
    var n = 0
    for (var i = 0; i < peers.length; i++) {
      var s = String(peers[i] && peers[i].state ? peers[i].state : "")
      if (s === "authenticated" || s === "polling") n++
    }
    return n
  }

  // Only the credentials that need doing something about, and only their own
  // words: the file paths are the CLI's business.
  readonly property var credProblems: {
    var out = []
    for (var i = 0; i < credentials.length; i++) {
      var s = String(credentials[i] && credentials[i].status ? credentials[i].status : "")
      if (s === "warn" || s === "expired" || s === "missing") out.push(credentials[i])
    }
    return out
  }

  readonly property int mirroredTotal: {
    var n = Number(clipInfo.mirrored_total)
    return isFinite(n) ? n : 0
  }

  // 0 off / not installed, 1 on, 2 problem. Same ranking the pill paints.
  readonly property int alertLevel: {
    if (!installed || !snap) return 0
    if (clipState === "degraded" || clipState === "error") return 2
    if (stale) return 2
    if (credProblems.length > 0) return 2
    if (statusErrors.length > 0 && on) return 2
    if (on || starting) return 1
    return 0
  }

  // Off, up-but-not-wired, wired, or broken. The pill's colour only has three
  // settings; the glyph carries the fourth.
  readonly property string stateGlyph: {
    if (alertLevel >= 2) return glyphAlert
    if (!installed) return glyphClipboardOff
    if (starting) return glyphClipboardWait
    if (!on) return glyphClipboardOff
    return livePeers > 0 ? glyphClipboardOn : glyphClipboardWait
  }

  readonly property string peerSummary: {
    if (!installed || !on) return "off"
    if (peers.length === 0) return "no devices"
    var live = []
    for (var i = 0; i < peers.length; i++) {
      var s = String(peers[i].state || "")
      if (s === "authenticated" || s === "polling" || s === "idle") live.push(peerLabel(peers[i]))
    }
    return live.length > 0 ? live.join("+") : peers.length + " waiting"
  }

  readonly property string barTooltip: {
    if (!installed) return "omclip not installed — run install.sh"
    var lines = ["omclip: " + stateWord()]
    lines.push(scopeText + " · " + remainingText)
    for (var i = 0; i < peers.length; i++) {
      var p = peers[i]
      var bit = peerLabel(p) + " · " + peerStateWord(p)
      var t = peerTransport(p)
      if (t !== "") bit += " · " + t
      lines.push(bit)
    }
    if (snap && clipInfo.mirrored_total !== undefined) lines.push("Mirrored " + mirroredTotal + " item" + (mirroredTotal === 1 ? "" : "s"))
    if (stale) lines.push(haveSnap ? "status unavailable — showing the last snapshot" : "omclip did not answer status --json")
    if (credProblems.length > 0) lines.push(credentialNotice)
    else if (statusErrors.length > 0) lines.push("Error: " + String(statusErrors[0]))
    return lines.join("\n")
  }

  function stateWord() {
    if (!installed) return "not installed"
    if (turningOn || clipState === "starting") return "starting"
    if (turningOff) return "stopping"
    if (!haveSnap) return "unknown"
    switch (clipState) {
    case "off": return "off"
    case "starting": return "starting"
    case "on": return "on"
    case "degraded": return "degraded"
    case "error": return "error"
    default: return clipState
    }
  }

  readonly property string scopeText: "Mac + iPhone"

  readonly property string remainingText: {
    if (!installed) return "not installed"
    if (starting) return "starting"
    if (!on) return "off"
    var left = haveSnap ? snap.seconds_left : null
    if (left === null || left === undefined) return "until you turn it off"
    return fmtSeconds(left) + " left"
  }

  readonly property string heroTitle: {
    if (!installed) return "omclip is not installed"
    if (turningOn || clipState === "starting") return "Starting omclip" + busyDots
    if (turningOff) return "Stopping omclip" + busyDots
    if (!haveSnap) return "omclip"
    switch (clipState) {
    case "off": return "omclip is off"
    case "starting": return "Starting omclip" + busyDots
    case "on": return "omclip is on"
    case "degraded": return "omclip is on, but nothing is reachable"
    case "error": return "omclip has a problem"
    default: return "omclip"
    }
  }

  readonly property string heroMeta: {
    if (!installed) return "Run install.sh in the plugin folder, then restart the shell."
    if (starting) return "Waking the radio and connecting to devices…"
    if (!haveSnap) return "Reading status…"
    if (stale) return "Status unavailable — showing the last snapshot"
    if (!on) return "Turn it on to share the clipboard with the Mac and the iPhone."
    return scopeText + " · " + remainingText
  }

  // ---- Polling -------------------------------------------------------------
  // 2 s while the panel is open, 10 s while it is closed — enough for the bar
  // pill to notice a peer dropping or a window expiring without keeping a
  // process a second busy on a 4 GB machine.
  readonly property int effectivePoll: opened ? pollSeconds : Math.max(10, pollSeconds)

  Timer {
    id: statusTimer
    interval: root.effectivePoll * 1000
    repeat: true
    running: root.installed
    triggeredOnStart: false
    onTriggered: root.refreshNow()
  }

  // A poll in flight answers this tick; a second process would only stack up
  // waiting on the same answer. The flag is ours rather than `statusProc.
  // running` because that one is unreliable after a failed exec.
  property bool statusInFlight: false

  function refreshNow() {
    if (statusInFlight) return
    statusInFlight = true
    statusWatchdog.restart()
    startProc(statusProc)
  }

  function statusSettled(failed) {
    statusInFlight = false
    statusWatchdog.stop()
    if (failed) pollFailed = true
  }

  // A run that never reports back — the binary vanishing mid-flight, a CLI
  // that hangs — must not wedge polling: after this long the panel gives up on
  // it, marks the snapshot stale rather than pretending, and lets the next
  // tick try again.
  Timer {
    id: statusWatchdog
    interval: 15000
    repeat: false
    onTriggered: if (root.statusInFlight) root.statusSettled(true)
  }

  Process {
    id: statusProc
    command: [root.cli, "status", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.applyStatus(text)
        root.statusSettled(false)
      }
    }
    // A nonzero exit means the CLI answered nothing usable, and a process that
    // never started (CLI deleted under us) lands here too, so a vanished
    // omclip shows up as a stale panel rather than as a silent gap.
    onExited: function(code) {
      if (code !== 0) root.statusSettled(true)
      else root.statusSettled(false)
    }
  }

  // The contract is one JSON object per command, so anything else is a
  // failure — but a daemon that prefixes a warning line must not turn the
  // panel into a stale marker, so the last object-shaped line is retried.
  function parseJsonObject(raw) {
    var text = String(raw || "").trim()
    if (text === "") return null
    try { return JSON.parse(text) } catch (e) {}
    var lines = text.split("\n")
    for (var i = lines.length - 1; i >= 0; i--) {
      var t = lines[i].trim()
      if (t.charAt(0) !== "{") continue
      try { return JSON.parse(t) } catch (e2) { return null }
    }
    return null
  }

  function applyStatus(raw) {
    var s = parseJsonObject(raw)
    if (!s || typeof s !== "object") {
      root.pollFailed = true
      return
    }
    root.snap = s
    root.installed = true
    root.pollFailed = false
    root.lastGoodMs = Date.now()
    if (!root.cfgLoaded) root.loadConfig()

    var st = typeof s.state === "string" ? s.state : (s.on ? "on" : "off")
    if (root.turningOn && (st === "on" || st === "degraded")) {
      root.turningOn = false
      transitionWatchdog.stop()
    } else if (root.turningOff && st === "off") {
      root.turningOff = false
      transitionWatchdog.stop()
    } else if (st === "error") {
      root.turningOn = false
      root.turningOff = false
      transitionWatchdog.stop()
    }
  }

  // ---- Daemon config -------------------------------------------------------
  // These are the daemon's, not the plugin's: the bar-display preferences are
  // the manifest's business, everything the daemon acts on is read from and
  // written back through `omclip config`. The window length is one of them too
  // — the panel is a switch, and `omclip on 10m` is the CLI's business.
  property var cfg: ({})
  property bool cfgLoaded: false
  property string cfgError: ""
  property bool notifyOn: true
  property bool previewOn: true

  Process {
    id: configProc
    command: [root.cli, "config", "list", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyConfig(text)
    }
  }

  function loadConfig() {
    if (!installed || configProc.running) return
    configProc.running = true
  }

  function boolish(v, dflt) {
    if (v === undefined || v === null) return dflt
    if (typeof v === "boolean") return v
    var s = String(v).toLowerCase()
    if (s === "true" || s === "1" || s === "yes" || s === "on") return true
    if (s === "false" || s === "0" || s === "no" || s === "off") return false
    var n = Number(v)
    return isFinite(n) ? n > 0 : dflt
  }

  function applyConfig(raw) {
    var d = parseJsonObject(raw)
    var s = d && d.settings && typeof d.settings === "object" ? d.settings : null
    if (!s) {
      root.cfgError = "could not read omclip's config"
      return
    }
    root.cfg = s
    root.cfgLoaded = true
    root.cfgError = ""
    if (s.notify !== undefined) root.notifyOn = boolish(s.notify, root.notifyOn)
    if (s.preview !== undefined) root.previewOn = boolish(s.preview, root.previewOn)
  }

  // ---- Actions -------------------------------------------------------------
  Process {
    id: actionProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyActionResult(text)
    }
    onExited: function(code) {
      root.actionBusy = false
      if (code !== 0 && root.actionError === "") {
        root.actionError = "omclip exited with " + code
        root.turningOn = false
        root.turningOff = false
        transitionWatchdog.stop()
      }
      if (root.actionError === "") {
        root.refreshNow()
        root.loadConfig()
      } else {
        root.turningOn = false
        root.turningOff = false
        transitionWatchdog.stop()
      }
    }
  }

  function applyActionResult(raw) {
    var d = parseJsonObject(raw)
    if (d && d.ok === false) {
      root.actionError = String(d.error || "omclip refused the command")
      root.turningOn = false
      root.turningOff = false
      transitionWatchdog.stop()
    }
  }

  function runAction(args) {
    if (!installed) {
      root.actionError = "omclip not installed — run install.sh"
      return false
    }
    if (actionBusy) return false
    root.actionError = ""
    root.actionBusy = true
    actionProc.command = [root.cli].concat(args)
    actionProc.running = true
    return true
  }

  function toggleMirroring() {
    if (!installed) {
      root.actionError = "omclip not installed — run install.sh"
      return
    }
    if (busy) return
    root.actionError = ""
    if (root.on) {
      root.turningOff = true
      root.turningOn = false
      transitionWatchdog.restart()
      runAction(["off", "--json"])
    } else {
      root.turningOn = true
      root.turningOff = false
      transitionWatchdog.restart()
      runAction(["on", "--json"])
    }
  }

  function setNotify(value) {
    root.notifyOn = value
    runAction(["config", "set", "notify", value ? "true" : "false", "--json"])
  }

  function setPreview(value) {
    root.previewOn = value
    runAction(["config", "set", "preview", value ? "true" : "false", "--json"])
  }

  // ---- Lifecycle -----------------------------------------------------------
  function open() { openedFromHotkey = false; root.controller.show() }
  function openFromHotkey() { openedFromHotkey = true; root.controller.show() }
  function close() { root.controller.hide() }
  function toggle() { root.opened ? root.close() : root.open() }

  // Opening is the only moment the config is worth spawning for: it changes
  // rarely, and the status poll runs on its own timer.
  onOpenedChanged: {
    if (!opened) return
    root.refreshNow()
    root.loadConfig()
  }

  Component.onCompleted: {
    root.notifyOn = root.notifyDefault
    // Probe before polling: asking `~/.local/bin/omclip` while the plugin-local
    // one is the real CLI would only log a failed exec. locateProc's exit
    // starts the first poll with the path it resolved.
    root.startProc(locateProc)
  }

  IpcHandler {
    target: root.ipcTarget

    function open(): string { root.open(); return "ok" }
    function close(): string { root.close(); return "ok" }
    // omdrop's convention for a plugin panel: `toggle` flips the thing the
    // widget exists for, so a keybind or a script reaches the daemon without
    // opening anything. Opening the panel is `open` (or a click on the pill).
    function toggle(): string { root.toggleMirroring(); return "ok" }
    function refresh(): string { root.refreshNow(); return "ok" }
    function status(): string {
      return JSON.stringify({
        installed: root.installed,
        state: root.clipState,
        on: root.on,
        turningOn: root.turningOn,
        turningOff: root.turningOff,
        busy: root.busy,
        scope: root.scopeText,
        live_peers: root.livePeers,
        peers: root.peers.length,
        mirrored_total: root.mirroredTotal,
        seconds_left: root.haveSnap ? root.snap.seconds_left : null,
        stale: root.stale,
        level: root.alertLevel,
        // What the panel's red line is showing, for anyone debugging the bar
        // without hovering it.
        error: root.actionError
      })
    }

    // A text surrogate for the pixels: every string the pill and the panel are
    // currently bound to, so a rendered panel can be checked from a log or by
    // someone who cannot see the screen. `glyph` is the codepoint, which is what
    // makes "which of the four glyphs is painted" answerable without eyes.
    function view(): string {
      var peerRows = []
      for (var i = 0; i < root.peers.length; i++) {
        peerRows.push({
          label: root.peerLabel(root.peers[i]),
          state: root.peerStateWord(root.peers[i]),
          transport: root.peerTransport(root.peers[i]),
          detail: root.peerDetail(root.peers[i])
        })
      }
      return JSON.stringify({
        installed: root.installed,
        state: root.clipState,
        on: root.on,
        checked: (root.on || root.turningOn) && !root.turningOff,
        busy: root.busy,
        turningOn: root.turningOn,
        turningOff: root.turningOff,
        level: root.alertLevel,
        heroTitle: root.heroTitle,
        heroMeta: root.heroMeta,
        glyph: glyphCode(root.stateGlyph),
        remaining: root.remainingText,
        scope: root.scopeText,
        notify: root.notifyOn,
        preview: root.previewOn,
        peers: peerRows,
        peerSummary: root.peerSummary,
        mirroredTotal: root.mirroredTotal,
        lastCopied: root.lastCopied,
        lastFile: root.lastFileName,
        lastFileWhere: root.lastFileCaption,
        credentialNotice: root.credProblems.length > 0 ? root.credentialNotice : "",
        installHint: root.installed ? "" : ("Expected at " + root.userCli + " / install with " + root.pluginDir + "/install.sh"),
        error: root.actionError,
        poll: (root.opened ? "open " : "closed ") + root.effectivePoll + "s",
        card: [Math.round(popout.contentWidth), Math.round(popout.contentHeight)],
        contentHeight: Math.round(content.implicitHeight),
        pill: root.hostWidget ? {
          text: root.hostWidget.pillText,
          tooltip: root.hostWidget.pillTooltip,
          active: root.hostWidget.activeState,
          urgent: root.hostWidget.urgentState,
          dimmed: !root.hostWidget.activeState,
          barStyle: root.hostWidget.barStyle
        } : null
      })
    }
  }

  // ---- Formatting ----------------------------------------------------------
  // "U+F1518" for the first codepoint of a glyph string, so a log reader can
  // tell which of the four state glyphs the widget is painting.
  function glyphCode(s) {
    var t = String(s || "")
    if (t.length === 0) return ""
    var cp = t.charCodeAt(0)
    if (cp >= 0xD800 && cp <= 0xDBFF && t.length > 1)
      cp = (cp - 0xD800) * 0x400 + (t.charCodeAt(1) - 0xDC00) + 0x10000
    var hex = cp.toString(16).toUpperCase()
    while (hex.length < 4) hex = "0" + hex
    return "U+" + hex
  }

  function fmtSeconds(value) {
    var s = Math.max(0, Math.round(Number(value) || 0))
    if (s < 60) return s + "s"
    var m = Math.floor(s / 60)
    if (m < 60) return (s % 60) === 0 ? m + "m" : m + "m " + (s % 60) + "s"
    return Math.floor(m / 60) + "h " + (m % 60) + "m"
  }

  // "1.6 MB" for 1631561 — decimal units, the same ones `omclip status` prints. An
  // unknown size is "", never "NaN bytes".
  function fmtBytes(value) {
    var n = Number(value)
    if (!isFinite(n) || n < 0) return ""
    if (n < 1000) return Math.round(n) + " B"
    if (n < 1e6) return (n / 1e3).toFixed(1) + " kB"
    if (n < 1e9) return (n / 1e6).toFixed(1) + " MB"
    return (n / 1e9).toFixed(1) + " GB"
  }

  function fmtWhen(value) {
    if (value === undefined || value === null || value === "") return ""
    var ms
    if (typeof value === "number" || /^[0-9]+(\.[0-9]+)?$/.test(String(value))) {
      // The daemon reports unix seconds; anything that large in milliseconds
      // would be a date far past anything this panel will ever show.
      var n = Number(value)
      if (!isFinite(n) || n <= 0) return String(value)
      ms = n > 1e11 ? n : n * 1000
    } else {
      var d = new Date(String(value))
      if (isNaN(d.getTime())) return String(value)
      ms = d.getTime()
    }
    var delta = Math.max(0, Math.round((Date.now() - ms) / 1000))
    if (delta < 45) return "just now"
    if (delta < 3600) return Math.round(delta / 60) + "m ago"
    if (delta < 86400) return Math.round(delta / 3600) + "h ago"
    return Math.round(delta / 86400) + "d ago"
  }

  // ---- Devices -------------------------------------------------------------
  function peerLabel(p) { return String((p && (p.label || p.key)) || "device") }
  function peerStateWord(p) {
    // The daemon's states, in the words a person would use for them.
    switch (String((p && p.state) || "")) {
    case "authenticated":
    case "polling":
    case "idle": return "Ready"
    case "connecting": return "Connecting"
    case "resolving": return "Looking for it"
    case "locked": return "Locked"
    case "unreachable": return "Not found"
    case "error": return "Problem"
    case "disabled": return "Off"
    default: return "Unknown"
    }
  }
  function peerReady(p) {
    var s = String((p && p.state) || "")
    return s === "authenticated" || s === "polling" || s === "idle"
  }
  function peerTransport(p) {
    var t = String((p && p.transport) || "")
    if (t === "lan") return "LAN"
    if (t === "awdl") return "AWDL"
    return t
  }
  function peerColor(p) {
    switch (String((p && p.state) || "")) {
    case "authenticated":
    case "polling":
    case "idle": return root.accent
    case "connecting":
    case "resolving":
    case "locked": return root.warnColor
    case "error":
    case "unreachable": return root.urgent
    default: return root.dim
    }
  }
  function peerGlyph(p) {
    var kind = String((p && p.kind) || "")
    if (kind === "mac") return glyphLaptop
    // The CLI reports the phone peer as "iphone"; "phone" stays accepted so a
    // future rename does not silently downgrade the glyph to a transport one.
    if (kind === "phone" || kind === "iphone" || kind === "ios") return glyphPhone
    return glyphCircle
  }
  // Only a device that is not simply ready needs a sentence under it; `detail`
  // is the daemon's own reason and is never invented here.
  function peerDetail(p) {
    if (peerReady(p)) return ""
    return String((p && p.detail) || "")
  }

  // ---- What crossed last ---------------------------------------------------
  // A file mirror has no text preview — the clipboard holds a `text/uri-list` offer, not
  // the bytes — so the row names the file that landed instead: `clipboard.last_file`
  // carries its name, its own size and where it landed. A snapshot from a build that
  // predates the field (or a non-file mirror) leaves this empty and the text preview
  // carries the row exactly as it always did.
  readonly property var lastFile: {
    var f = clipInfo.last_file
    return (f && typeof f === "object") ? f : ({})
  }

  readonly property string lastCopied: {
    var p = clipInfo.last_preview
    if (p === undefined || p === null) return ""
    var s = String(p).replace(/\s+/g, " ").trim()
    return s.length > 140 ? s.substring(0, 140) + "…" : s
  }

  readonly property string lastCopiedWhen: {
    if (!haveSnap || (clipInfo.last_mirrored_at === undefined || clipInfo.last_mirrored_at === null)) return ""
    return fmtWhen(clipInfo.last_mirrored_at)
  }

  // "IMG_1739.HEIC · 1.6 MB" — the file's name and the file's own size, never the byte
  // count of the URI offer that is actually on the clipboard.
  readonly property string lastFileName: {
    var name = root.lastFile.name
    if (name === undefined || name === null || String(name) === "") return ""
    var size = root.lastFile.bytes
    var text = (size === undefined || size === null) ? "" : fmtBytes(Number(size))
    return text === "" ? String(name) : String(name) + "  ·  " + text
  }

  // Where it landed, under the name: the directory, and when it crossed.
  readonly property string lastFileCaption: {
    var when = root.lastCopiedWhen
    var path = root.lastFile.path
    if (path === undefined || path === null || String(path) === "") return when
    var cut = String(path).lastIndexOf("/")
    var where = cut > 0 ? String(path).substring(0, cut) : String(path)
    return when === "" ? where : (where + "  ·  " + when)
  }

  // ---- Credentials, in one line --------------------------------------------
  readonly property string credentialNotice: {
    if (credProblems.length === 0) return ""
    var worst = credProblems[0]
    var st = String(worst.status || "unknown")
    var days = (worst.days_left === undefined || worst.days_left === null) ? null : Number(worst.days_left)
    var what
    if (st === "missing") what = "Apple credentials are missing"
    else if (st === "expired") what = "Apple credentials have expired"
    else if (days !== null && isFinite(days)) what = "Apple credentials expire in " + Math.max(0, days) + " day" + (Math.max(0, days) === 1 ? "" : "s")
    else what = "Apple credentials need attention"
    if (credProblems.length > 1) what += " (and " + (credProblems.length - 1) + " more)"
    return what + " — refresh them from " + macHandoffDir
  }

  // ---- UI ------------------------------------------------------------------
  component Label: Text {
    textFormat: Text.PlainText
    color: root.fg
    font.family: root.fontFamily
    font.pixelSize: Style.font.body
    elide: Text.ElideRight
  }

  component Caption: Text {
    textFormat: Text.PlainText
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    elide: Text.ElideRight
  }

  component SectionRow: Item {
    property string title: ""
    property string trailing: ""
    implicitHeight: Math.max(head.implicitHeight, tail.implicitHeight)
    PanelSectionHeader {
      id: head
      text: parent.title
      foreground: root.fg
      fontFamily: root.fontFamily
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
    }
    Caption {
      id: tail
      text: parent.trailing
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
    }
  }

  component SettingRow: Item {
    id: row
    property string label: ""
    property bool value: false
    signal flipped()
    implicitHeight: Math.max(rowLabel.implicitHeight, rowSwitch.implicitHeight + Style.space(2))
    Label {
      id: rowLabel
      anchors.left: parent.left
      anchors.right: rowSwitch.left
      anchors.rightMargin: Style.space(10)
      anchors.verticalCenter: parent.verticalCenter
      text: row.label
      font.pixelSize: Style.font.bodySmall
    }
    ToggleSwitch {
      id: rowSwitch
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      checked: row.value
      interactive: root.installed && !root.busy
      foreground: root.fg
      accent: root.accent
      onToggled: row.flipped()
    }
  }

  KeyboardPanel {
    id: popout
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: popout.fittedContentWidth(Style.space(340))
    contentHeight: popout.fittedContentHeight(Math.min(content.implicitHeight, Style.space(720)))

    Item {
      id: keyCatcher
      anchors.fill: parent
      focus: true
      // Keys.BeforeItem so the panel's keys win even once a child has focus.
      // This panel does not use Ui/PanelKeyCatcher because its vim-style
      // h/j/k/l/x map collides with this panel's `r` (re-read the status and
      // the config), which has no equivalent there.
      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Escape) {
          root.close()
          event.accepted = true
          return
        }
        if (event.key === Qt.Key_Space || event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
          root.toggleMirroring()
          event.accepted = true
          return
        }
        if (String(event.text || "").toLowerCase() === "r") {
          root.refreshNow()
          root.loadConfig()
          event.accepted = true
        }
      }

      Flickable {
        id: scroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: content.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        Column {
          id: content
          width: scroll.width
          spacing: Style.space(12)

          // --- the switch, and what it is switching --------------------------
          Item {
            width: parent.width
            implicitHeight: Math.max(heroGlyph.implicitHeight, heroLabels.implicitHeight, heroSwitch.implicitHeight)

            Text {
              id: heroGlyph
              text: root.stateGlyph
              color: root.levelColor(root.alertLevel)
              font.family: root.fontFamily
              font.pixelSize: Style.font.display
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            ToggleSwitch {
              id: heroSwitch
              checked: (root.on || root.turningOn) && !root.turningOff
              // Disabled rather than hidden when omclip is missing: the panel
              // still has to explain itself.
              interactive: root.installed && !root.busy
              busy: root.busy || root.turningOn || root.turningOff
              foreground: root.fg
              accent: root.accent
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              onToggled: root.toggleMirroring()
            }

            Column {
              id: heroLabels
              anchors.left: heroGlyph.right
              anchors.leftMargin: Style.space(14)
              anchors.right: heroSwitch.left
              anchors.rightMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Label {
                width: parent.width
                text: root.heroTitle
                font.pixelSize: Style.font.title
                font.bold: true
              }
              Caption {
                width: parent.width
                text: root.heroMeta
                wrapMode: Text.WordWrap
                elide: Text.ElideNone
              }
            }
          }

          // Where to install it from, when there is nothing to run.
          Column {
            width: parent.width
            visible: !root.installed
            spacing: Style.space(2)
            Caption { width: parent.width; text: "Expected at " + root.userCli; elide: Text.ElideMiddle }
            Caption { width: parent.width; text: "Install with " + root.pluginDir + "/install.sh"; elide: Text.ElideMiddle }
          }

          Label {
            width: parent.width
            visible: text !== ""
            text: root.actionError !== "" ? root.actionError
                : (root.statusErrors.length > 0 ? String(root.statusErrors[0]) : "")
            color: root.urgent
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
            elide: Text.ElideNone
          }

          // One discreet line, and no file paths: what to do, not where it is.
          Caption {
            width: parent.width
            visible: text !== ""
            text: root.credProblems.length > 0 ? root.credentialNotice : ""
            color: root.warnColor
            wrapMode: Text.WordWrap
            elide: Text.ElideNone
          }

          PanelSeparator { foreground: root.fg }

          // --- the devices --------------------------------------------------
          SectionRow {
            width: parent.width
            title: "DEVICES"
            trailing: root.peers.length === 0 ? "" : (root.livePeers + " of " + root.peers.length + " live")
          }

          Column {
            width: parent.width
            spacing: Style.space(6)

            Caption {
              width: parent.width
              visible: root.peers.length === 0
              text: root.installed ? "No device has been configured yet." : "Nothing to show while omclip is not installed."
            }

            Repeater {
              model: root.peers

              delegate: Rectangle {
                id: peerCard
                required property var modelData
                readonly property var peer: modelData
                width: parent.width
                implicitHeight: peerCol.implicitHeight + Style.space(Style.spacing.rowGap)
                radius: root.radius
                color: root.cardFill

                Column {
                  id: peerCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(1)

                  Item {
                    width: parent.width
                    implicitHeight: Math.max(peerLeft.implicitHeight, peerState.implicitHeight)

                    Row {
                      id: peerLeft
                      anchors.left: parent.left
                      anchors.right: peerState.left
                      anchors.rightMargin: Style.space(8)
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(6)

                      Text {
                        id: peerGlyphText
                        text: root.peerGlyph(peerCard.peer)
                        color: root.peerColor(peerCard.peer)
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.iconSmall
                        anchors.verticalCenter: parent.verticalCenter
                      }
                      Label {
                        width: parent.width - peerGlyphText.width - parent.spacing
                        text: root.peerLabel(peerCard.peer)
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                        anchors.verticalCenter: parent.verticalCenter
                      }
                    }

                    Caption {
                      id: peerState
                      text: root.peerStateWord(peerCard.peer)
                      color: root.peerColor(peerCard.peer)
                      font.bold: true
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                    }
                  }

                  Caption {
                    width: parent.width
                    visible: text !== ""
                    text: root.peerDetail(peerCard.peer)
                    wrapMode: Text.WordWrap
                    elide: Text.ElideNone
                  }
                }
              }
            }
          }

          // --- what crossed last --------------------------------------------
          Column {
            width: parent.width
            visible: root.on && (root.lastCopied !== "" || root.lastFileName !== "")
            spacing: Style.space(2)

            Label {
              width: parent.width
              text: root.lastCopied !== "" ? "“" + root.lastCopied + "”" : root.lastFileName
              color: root.dim
              font.pixelSize: Style.font.bodySmall
            }

            Caption {
              width: parent.width
              visible: text !== ""
              text: root.lastCopied !== "" ? root.lastCopiedWhen : root.lastFileCaption
            }
          }

          PanelSeparator { foreground: root.fg }

          // --- the two switches the daemon acts on ---------------------------
          Column {
            width: parent.width
            spacing: Style.space(4)

            SettingRow {
              width: parent.width
              label: "Notify on sync"
              value: root.notifyOn
              onFlipped: root.setNotify(!root.notifyOn)
            }
            SettingRow {
              width: parent.width
              label: "Show copied text"
              value: root.previewOn
              onFlipped: root.setPreview(!root.previewOn)
            }
            Caption {
              width: parent.width
              visible: text !== ""
              text: root.cfgError
              color: root.urgent
            }
          }
        }
      }
    }
  }
}