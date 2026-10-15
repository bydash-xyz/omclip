# omclip UI

The bar pill and the panel that turn Apple Universal Clipboard mirroring on and
off. Both live in this plugin directory and talk only to the `omclip` CLI
(`~/.local/bin/omclip`, or the `bin/omclip` shipped beside these files before
`install.sh` has run). Neither file talks to the Mac, Bluetooth or AWDL itself.

Files: `BarWidget.qml` (the pill), `Panel.qml` (the panel, and everything that
shells out), `manifest.json` (bar-widget declaration and settings).

## The pill

Three states, plus one glyph that carries the fourth:

| state | look | when |
| --- | --- | --- |
| off | dim, `md-clipboard_off` | daemon off, or `omclip` not installed |
| on | theme accent, `md-clipboard_check` | `on`, and at least one peer is `authenticated` or `polling` |
| on, not wired yet | theme accent, `md-clipboard_flow` | `on`, but no peer has reached `authenticated`/`polling` |
| problem | urgent, `md-clipboard_alert` | `degraded`, `error`, a stale snapshot, or a credential in `warn`/`expired`/`missing` |

A credential problem is urgent **even while mirroring is off**: it is a problem
either way, and it is the one that quietly stops working later.

Tooltip: `omclip: <state>`, the scope and the remaining window, one line per peer
(label · state · transport), the mirrored total, and — when they apply — the
stale marker, the credential notice and the first entry of `errors[]`. The scope
is always reported as `Mac + iPhone`: both peers are mirrored together and the
panel offers no scope choice.

Clicks:

- **left** — open the panel
- **right** — flip mirroring (`omclip on …` / `omclip off`), like omdrop and
  caffeine
- **middle** — refresh now, without waiting for the poll

`barStyle` chooses the label: `Icon`, `Icon + peers` (live peer labels, `off`
when the daemon is off, `no peers` when it is on but unattached) or
`Icon + count` (`clipboard.mirrored_total`).

## The panel

A consumer panel, not a dashboard. Top to bottom:

- **Header** — the state glyph, `omclip is on` / `omclip is off` (or
  `omclip is not installed`), one status line (`Mac + iPhone · until you turn it
  off`, or why it is not mirroring), and the on/off switch. The switch is inert
  (not hidden) when `omclip` is missing, and the not-installed case adds the
  expected path and the `install.sh` that creates it.
- **Error line** — the CLI's own `error` from a refused command, or the first
  `errors[]` entry.
- **Credential notice** — only when a credential is `warn`, `expired` or
  `missing`: one line saying what it means and that it is refreshed by
  re-extracting it (README → *Credentials*). No file paths, no per-file dump.
- **Devices** — one row per peer: glyph (laptop/phone), label, and the state in
  a person's words (`Ready`, `Locked`, `Not found`, `Off`). A row that is not
  ready adds the daemon's own `detail` sentence underneath. Addresses, ports,
  transports and last-seen times are deliberately not shown.
- **What crossed last** — `clipboard.last_preview`, whitespace collapsed and cut
  at 140 characters, in quotes, with `last_mirrored_at` under it. A file copy has no
  preview — the clipboard holds a `text/uri-list` offer, not the bytes — so the row
  names the file that landed instead, from `clipboard.last_file`: the file's name and
  its own size (`IMG_1739.HEIC · 1.6 MB`), with the directory it landed in under it.
  The byte count of the URI offer (48) is never what this row shows. Absent while
  mirroring is off, or while nothing has crossed yet.
- **Switches** — `Notify on sync` and `Show copied text`, written with
  `omclip config set notify|preview true|false` and read back from
  `omclip config list`. The manifest's `notify` only seeds a machine whose
  daemon config has no opinion yet.

Deliberately **not** in the panel — it is the CLI's business, not the desktop's:
the log tail (`omclip log`), socket health chips (`health.*`), the
`clipboard.skipped` counters, credential file paths, and a window-length picker
(the panel is a switch; `omclip on 10m` is the CLI's). `status --json` still
carries all of it, and `omclip doctor` is the diagnostic surface.

Polling: `omclip status --json` every `pollSeconds` (default 2) while the panel
is open, every 10 s while it is closed. Only JSON is parsed; human output never
is. A malformed, empty or missing answer keeps the last good snapshot on screen
and marks it stale rather than inventing a state. `omclip config list` is read
on open (and after a successful action), not on the poll.

## Keys

| key | action |
| --- | --- |
| `space` / `Enter` | flip mirroring |
| `r` | refresh status (and re-read the config) |
| `Esc` | close the panel |

The panel handles its own keys instead of using `Ui/PanelKeyCatcher` because
that catcher maps `r` to something else (vim style), which collides with the
status refresh.

## IPC

`omarchy-shell bxshi.omclip <verb>`:

| verb | effect |
| --- | --- |
| `toggle` | flip mirroring (`omclip on …` / `omclip off`) — the daemon, omdrop's convention |
| `open` / `close` | the panel |
| `status` | one JSON line describing what the panel currently shows |
| `refresh` | poll now |
| `view` | every string the pill and the panel are currently bound to, as a text surrogate for the pixels — including the state glyph as a codepoint, the peer rows, the last copied text, the last crossed file (`lastFile`/`lastFileWhere`, empty when a mirror was not a file), the credential notice, the rendered card size, and the pill's own text/tooltip/active/dimmed. Use this to check a rendered panel from a log, or when nobody can see the screen |

`status` returns
`{installed, state, on, scope, live_peers, peers, mirrored_total, seconds_left, stale, level, error}`
where `level` is the pill's own ranking (0 off, 1 on, 2 problem) and `error` is
the text of the panel's red line. A click on the pill, or
`omarchy-shell shell toggle bxshi.omclip`, opens the panel.

## Settings

`omarchy bar set bxshi.omclip <key> <value>` — plugin-side, stored in
`shell.json`:

- `barStyle` (enum: `Icon`, `Icon + peers`, `Icon + count`; default
  `Icon + count`)
- `pollSeconds` (integer, min 1, default 2) — the *open* poll interval; the
  closed one is 10 s
- `notify` (boolean, default true) — seeds the daemon config on a machine whose
  config has no `notify` yet

The daemon's own settings are not duplicated here: notify and preview go
through `omclip config set`, because the daemon is the thing that acts on them.
Scope is not a setting at all any more — every run mirrors both peers.

## When omclip is not installed

The pill shows the dim off glyph, the panel says so and offers the `install.sh`
path, the switch does nothing, and every IPC verb still answers. Nothing in the
widget spawns a process while the CLI is missing except a re-probe of the two
candidate paths every 30 s — that is what notices `install.sh` having run
without the user restarting the shell.
