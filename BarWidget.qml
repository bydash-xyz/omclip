// SPDX-License-Identifier: MIT
import QtQuick
import qs.Commons
import qs.Ui

// Bar entry point for omclip. The pill is thin: Panel.qml owns the polling,
// the CLI calls and the settings, and this file only renders a summary of
// whatever that panel last read. Everything here degrades to a dim, off
// glyph when the panel has not loaded or omclip is not installed yet, so a
// half-installed plugin can never take the bar down with it.
//
// States, in the order they win:
//   problem  urgent  degraded / error / stale snapshot / credential expiring
//   on       accent  mirroring is on; the glyph says whether a peer is wired
//   off      dim     daemon off, or omclip not installed
BarWidget {
  id: root
  moduleName: "bxshi.omclip"

  readonly property var panel: panelLoader.item

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  function togglePanel() { if (panel && panel.toggle) panel.toggle() }

  // Shape contract the bar's popout coordinator, the shell's summon/hide
  // routing and KeyboardPanel read on the slot item.
  readonly property bool opened: panel ? panel.opened === true : false
  function open() { if (panel && panel.open) panel.open() }
  function close() { if (panel && panel.close) panel.close() }
  readonly property bool popoutSwitchClosing: panel ? panel.popoutSwitchClosing === true : false
  function closeForPopoutSwitch() { if (panel) panel.closeForPopoutSwitch() }

  // ---------------------------------------------------------------- summary
  // Glyphs are checked against JetBrainsMono Nerd Font's cmap: md-clipboard_off
  // U+F1518, md-clipboard_check U+F004C, md-clipboard_flow U+F05C6.
  readonly property string offGlyph: "\udb85\udd18"
  readonly property string pillGlyph: panel ? panel.stateGlyph : offGlyph

  readonly property bool installed: panel ? panel.installed === true : false
  readonly property int level: panel ? panel.alertLevel : 0
  readonly property bool urgentState: level >= 2
  readonly property bool activeState: level >= 1

  readonly property string barStyle: String(setting("barStyle", "Icon + count"))

  readonly property string pillText: {
    if (barStyle === "Icon") return pillGlyph
    if (!panel || !installed) return pillGlyph
    if (barStyle === "Icon + peers") return pillGlyph + "  " + panel.peerSummary
    return pillGlyph + "  " + panel.mirroredTotal
  }

  readonly property string pillTooltip: {
    if (!panel) return "omclip widget failed to load"
    return panel.barTooltip
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.pillText
    fontSize: root.barStyle === "Icon" ? Style.bar.iconFont : Style.font.bodySmall
    horizontalMargin: root.barStyle === "Icon" ? 6 : 8.75
    // Urgent when something needs attention, the theme accent while mirroring.
    active: root.activeState
    activeColor: root.urgentState ? (root.bar ? root.bar.urgent : Color.urgent) : Color.accent
    dimmed: !root.activeState
    tooltipText: root.pillTooltip

    onPressed: function(b) {
      if (!root.panel) return
      // omdrop and caffeine both put the on/off flip on right-click; mirroring
      // that here means the switch is one click away without opening anything.
      if (b === Qt.RightButton) root.panel.toggleMirroring()
      else if (b === Qt.MiddleButton) root.panel.refreshNow()
      else root.togglePanel()
    }
  }
}
