# Gorce TUI design contract

Status: canonical product and implementation specification. The sole approved visual/interactive acceptance reference is [`tui-proposal-conversation-operations.html`](tui-proposal-conversation-operations.html); its behavior and focus-state companion is [`tui-proposal-conversation-operations.md`](tui-proposal-conversation-operations.md). This document is normative for implementation and incorporates that approved conversation-first interaction model.

## 1. Product boundary

The daemon is headless. The TUI is a client that may attach to, detach from, and later reattach to a session. It renders confirmed daemon events and local connection state.

The TUI must never claim that an action happened because it was requested locally. A command, tool call, file change, approval, cost, task transition, or background-run transition is displayed as completed only after the corresponding daemon event is received.

The TUI may display local intent as `queued locally` or `requesting`, but these are not completion states.

Current implementation concepts that this contract preserves include `App` state/reducer/rendering, bounded transcript/history, permission modes, `ClientAdapter`, `InputEvent`, OSC52, bracketed paste, attachments, task/diff models, and the `ClientEvent` event stream.

## 2. Information hierarchy

The screen answers these questions in order:

1. Is the session connected, attached, and safe to act on?
2. What is the current foreground activity?
3. Is a decision required from the user?
4. What durable work continues in the background?
5. What task graph, files, diff, budget, and connectivity state explain the activity?

The main surface is a real chronological user/agent conversation: requests, responses, safe activity summaries, tool results, diffs, and confirmed changes. The Operations rail is persistent context, not a dashboard of competing cards. Approvals, bypass, actual failures, and reconnect state outrank routine progress. Child activity opens as a full safe transcript in the main pane; private reasoning is never rendered.

## 3. Layout contract

### Wide: 120 or more columns

- Main content: 78%.
- Operations: 22%, fixed on the right.
- Header: 1 terminal row.
- Main body: stream/diff surface.
- Composer: 3 terminal rows minimum; it may grow for wrapped attachment chips.
- Sidebar has a single subtle left divider, not independent large cards.

### Medium: 90–119 columns

- Keep the 78/22 relationship where both panes remain readable.
- Shorten secondary labels and metadata before reducing text size.
- Sidebar task rows may truncate titles with an ellipsis.
- Activity and background rows show the latest useful entries only.

### Narrow: below 90 columns

- Main stream occupies the full width.
- Operations stacks below the conversation as readable text sections; it is not an unreadable miniature sidebar or a blocking drawer.
- The header retains connection, permission, and attention status.
- Composer remains at the bottom and may wrap chips. While approval is pending, an inline approval dock temporarily replaces it and preserves the draft.
- Never render a 22% sidebar that is too narrow to read.

### Structural rules

- Use one-cell dividers in dark gray.
- Do not use shadows, gradients, rounded cards, large logos, decorative marketing text, or animated full-screen transitions.
- The terminal surface is full-height and visually continuous. Documentation controls, viewport labels, and explanatory notes live outside the frame and never compete with it.
- The default wide view is a continuous chronological work transcript, not a dashboard: there is no large stream title, no repeated section card, and no stacked panel framing in the main surface.
- Empty regions are quiet; they do not contain filler copy.
- Pane content scrolls independently where practical.

## 4. Tokens

### Color

Names are semantic; exact terminal palette mapping may use indexed or RGB colors.

| Token | Intended use | Baseline |
|---|---|---|
| `bg` | terminal background | near-black, approximately `#0A0B0D` |
| `surface` | focused input or selected row | `#26282C` |
| `text` | primary content | soft gray, approximately `#D4D6D8` |
| `muted` | timestamps, metadata, empty state | dark gray, approximately `#747980` |
| `divider` | pane/header rule | `#2D2F33` |
| `focus` | keyboard focus, selected row, composer/dock focus | warm peach/salmon, approximately `#F0A08D` |
| `progress` | current agent activity, concise execution summaries, waiting work | warm orange, approximately `#FFAD5A` |
| `category` | provider/model groups and secondary categories | blue/violet, approximately `#82AAFF` / `#B8A1EA` |
| `success` | confirmed completion | neutral text/glyph; muted green is allowed only on an actual `+` diff addition |
| `danger` | actual error, conflict, denial, or bypass | coral, approximately `#FF6F61` |

Red is not used for ordinary progress. Orange is not a transcript-wide highlight: reserve it for current activity, pending attention, and waiting state. No green/lime token, tint, border, shadow, focus state, or action hint is used; the only green exception is muted `+` diff-addition text paired with the literal `+`. Color is never the sole status signal: pair it with text, a glyph, or a shape.

### Type and spacing

- Use the terminal's fixed-width font; do not assume a particular font.
- Header and pane labels: compact, lowercase or sentence case; bold only for hierarchy.
- Body: normal terminal weight.
- Metadata: one step dimmer than body.
- Base spacing is one cell. Use one blank row only between major regions when height permits.
- Keep labels short: `todo`, `activity`, `approvals`, `budget`, `MCP`, `LSP`.
- Do not rely on Unicode glyphs without ASCII fallback. Preferred status glyphs are `[x]`, `[~]`, `[ ]`, `[!]`, `+`, `-`, and `>`.

## 5. Chrome

### Header

One row, for example:

```text
 session  refactor-auth  /  agent/main  SUPERVISED  connected  !1
```

It must show:

- session title or stable short identifier;
- foreground agent or `detached`;
- connection state;
- permission mode;
- attention count when non-zero.

Bypass is always explicit and persistent:

```text
 BYPASS  NO ACTION CONFIRMATION
```

The bypass label remains visible in wide, medium, narrow, stacked Operations, and approval views. It is not conveyed by coral alone.

### Footer/composer

The composer is a working area, not a card. It contains:

1. prompt line with `>` and current input;
2. compact attachment-chip rows;
3. mode, confirmed model/context/cost fields when available, and `Ctrl+K commands` hint.

The model must not invent a model name, token count, or cost. Unavailable model and numeric fields are omitted; `unknown` is reserved for an explicitly reported unavailable subsystem state.

## 6. Session stream

The stream is virtualized and bounded. It may retain a bounded history while the daemon remains the source of truth. A visible row has a source, body, and optional status/relationship to a daemon event. The default wide stream is a compact chronology of user request blocks, agent summaries, tool rows, background status, confirmed events, and occasional inline diff blocks. It should look active without requiring a diff on screen.

Normal rows are quiet. Speaker and agent metadata are compact and subdued. User requests are restrained blocks separated from the running chronology by spacing, not cards. The current foreground activity receives the warm amber treatment. Tool calls show tool name, agent, elapsed time when known, and confirmed result. Arguments and long output open in a detail view rather than expanding the entire stream. Never render private chain-of-thought. A safe activity summary may say `+ activity: validating authority receipts · 26ms`, `tool: fs.read · running`, or `background: test-runner · 04:12`.

Connection notices are distinct from daemon events:

```text
 local  disconnected; last confirmed event 10:42:18
```

On reconnect, show the replay boundary and reconcile from daemon state. Do not duplicate events merely because they were replayed.

## 7. Diffs and code

Diffs are first-class stream content. A diff entry includes path, unified or side-by-side preference, line numbers, line kind, and text.

- Header lines use muted blue/violet.
- Added lines use muted green only when paired with an actual `+` marker; no other green is permitted.
- Removed lines use restrained red or a `-` marker.
- Context lines remain quiet.
- Line numbers are muted and fixed-width.
- Long code wraps only when necessary; preserve line identity and show continuation indentation.
- Syntax emphasis is limited to readable token contrast. It must not turn the screen into a saturated editor.

The visible diff is evidence of confirmed daemon file events. A locally requested write is not shown as changed until confirmed.

## 8. Operations sidebar

The sidebar is a compact scrollable text surface with a title and summary, not a set of large cards. Its order is fixed: plan title/open-source hint, context usage, MCP/LSP bullets, Todo hierarchy, then a small agents/status footer. Avoid repeating boxed section headers.

### Summary

Show only confirmed context/token/cost data in one or two lines. Render each available field independently; omit a context field unless both its used and limit values are known:

```text
 context  18.4k  ·  $0.42  ·  04:12
 MCP  connected   LSP  connected
```

Do not show guessed values.

### Task graph

Use a tree with stable indentation and explicit state:

```text
 todo                              2/7
 [-] Release preparation
   [x] Inspect failing test
   [~] Reproduce failure
   [ ] Apply patch
   [!] Verify (blocked: approval)
```

The tree represents daemon task events. It must not imply that a hidden workflow engine exists merely because the UI has a hierarchy.

### Activity and background work

Foreground and durable background work are different:

```text
 foreground  agent/main       running
 background  test-runner      running  04:12
```

When detached, the sidebar must make durable work visible and must not imply that the foreground stream is still receiving live events.

### Approvals

Pending approvals are grouped and counted. The active approval is an inline bottom dock that replaces the composer without hiding conversation or Operations context. It shows position/count, action summary, and selectable options: Approve once, Deny with reason, Inspect exact scope, and Return to composer. Arrow keys move focus and Enter chooses; approval requires a second Enter in the same dock, denial opens an inline reason entry, and Esc restores the preserved draft while leaving approval pending. After submission, display `requesting confirmation result` until the daemon confirms allow/deny.

### Files and budget

Changed files show status and path. Budget shows confirmed spent/limit/percent and uses amber for a high threshold; red is reserved for an actual exceeded/error state.

## 9. Attachment chips

Chips render in the composer immediately after the prompt or on compact wrapped rows:

```text
[File] src/main.rs  42.3 KiB · 418 lines   [Image] diagram.png  81.0 KiB
```

The kind segment is colored and short. The source/metadata segment is muted. Supported kinds are `File`, `Image`, `Paste`, and `Path`.

- Text paste uses `Paste` and `clipboard`.
- File uses filename plus bytes and lines where known.
- Image uses filename or `image` plus bytes where known.
- Path uses the basename or path and no fabricated size.
- Multiple chips flow into rows based on terminal width.
- Focus uses a readable background inversion or strong outline without changing chip width.
- Click/Enter inspects; Delete removes the focused attachment; right-click opens a compact context menu where supported; retry is explicit for pending/error chips.
- A pointer action never removes an attachment immediately.
- Unsupported/error state says `error` or `unsupported` in addition to its status glyph/color.
- Large text renders only bounded metadata and preview; never the full payload.

## 10. Permission, budget, connectivity, and errors

Permission modes:

- `SUPERVISED  Actions require confirmation`
- `POLICY  Approved by policy`
- `AI-VERIFIED  Approved by verifier`
- `BYPASS  NO ACTION CONFIRMATION`

Policy/AI verification is not phrased as user confirmation. Bypass is never hidden in a menu.

Connection states:

- `connected`: live daemon event stream;
- `reconnecting`: local client attempting to resume;
- `detached`: no foreground attachment; durable work may continue;
- `offline`: no live connection and no claim of current state.

During reconnect:

- preserve the last confirmed content;
- show the last confirmed timestamp;
- stop presenting local requests as daemon results;
- show a concise retry/reconnect action;
- keep a compact persistent strip such as `SYNCING · events held · cursor … · r retry`;
- preserve the composer draft and approval queue, but disable send and decision controls until resync;
- reconcile after reconnect before marking work current.

Actual errors use a compact red marker, clear text, and a detail action. Routine pending work remains amber.

## 11. Keyboard, mouse, selection, and paste

Required behavior:

| Input | Result |
|---|---|
| `Ctrl+K` or `:` | command palette |
| `o` | focus Operations rail |
| `j/k`, arrows | move in the focused scroll surface; ordinary text input still accepts other characters |
| `Tab` / `Shift+Tab` | focus cycle |
| `Enter` | inspect, expand, submit, or confirm the focused action |
| `Esc` | back through child/workflow views, close picker, or restore composer draft |
| `a` / `n` | focus next approval/inline approval dock |
| `[` / `]` | move through approval queue |
| `w` / `5` | open workflow phase/agent view |
| `Delete` | remove focused attachment when applicable |
| mouse wheel | scroll focused surface |
| left click | focus/inspect at the hit target |
| drag | select text where TUI owns selection |
| Shift+drag | allow native terminal selection when supported |
| right click | compact context menu where supported; otherwise safe fallback |
| bracketed paste | inline small paste; bounded preview/blob flow above 32 KiB |

Copy uses OSC52 when available. Otherwise, retain native terminal selection and show a non-modal `select text and copy in terminal` hint; do not invoke an undocumented OS clipboard command. Copy-on-select never mutates daemon state.

### Model picker

The model picker is a compact dark rectangular picker anchored to the composer; it does not obscure the conversation or approval dock. It contains a search-focused first row, compact provider/model groups, one peach selection row, favorites, connection status, and a short keyboard footer. Names are provider-neutral and must be supplied by confirmed configuration events. `Esc` closes without changing the model; `Enter` requests selection and the composer changes only after confirmation.

## 12. Accessibility and terminal safety

- Every state has text or glyph redundancy in addition to color.
- Contrast must be readable on dark and light terminal themes where possible.
- Focus is visible without animation.
- Peach focus is paired with a visible marker or label; orange marks attention, coral marks danger, and blue/violet marks categories.
- No blinking or repeated attention sound.
- Respect terminal width and height; never print past the viewport.
- Truncation preserves the identifying prefix where possible and offers detail on focus.
- Do not assume mouse support; every mouse action has a keyboard path.
- OSC52 must be opt-in or safe for the terminal integration; never interpret clipboard content as a command.
- Bracketed paste content is data, not keystrokes.

## 13. Things that must never surprise the user

- No successful-looking state before a confirmed daemon event.
- No hidden bypass mode.
- No fabricated cost, token, model, task, agent, file, or connection state.
- No automatic approval caused by focus, hover, paste, or mouse release.
- No destructive action on a single ambiguous click.
- No loss of the last confirmed state during reconnect.
- No full rendering of large pasted content.
- No unsolicited layout jump when a chip gains focus or metadata arrives.
- No notification for every routine tool call.

## 14. Implementation acceptance checklist

### Layout and visual language

- [ ] Wide layout uses 78/22 main/sidebar proportions at 120+ columns.
- [ ] Medium layout remains readable at 90–119 columns.
- [ ] Below 820px the Operations rail stacks below the conversation; it never becomes an unreadable miniature or approval drawer.
- [ ] Header is one compact row with session, foreground/detached state, connection, permission, and attention.
- [ ] Background is near-black and low glare; dividers are one-cell dark gray.
- [ ] No oversized branding, cards, gradients, shadows, or filler copy.
- [ ] Default wide view is a continuous chronological transcript with no dashboard cards or repeated large section titles.
- [ ] The main surface is a user/agent conversation with safe summaries, tool results, diffs, and confirmed changes; private reasoning is absent.
- [ ] The transcript remains visibly active through concise activity, tool, background, confirmed-event, and occasional diff rows even when no diff is current.
- [ ] The Operations rail is a quiet text rail ordered plan/context/connectivity/todo/agent footer, without card panels.
- [ ] The composer is a thin dock integrated into the session, not a form.
- [ ] Focus is visible with more than color alone.

### Data truth and states

- [ ] UI state changes are driven by reducer/client events, not render-time guesses.
- [ ] Local requests are visibly distinct from confirmed daemon events.
- [ ] Foreground, detached, and durable background work are distinguishable.
- [ ] Reconnect preserves last confirmed state and reconciles replay safely.
- [ ] Bypass is persistent and says `BYPASS` plus `NO ACTION CONFIRMATION`.
- [ ] Budget and connectivity show unknown/empty states without fabricated values.

### Stream and Operations

- [ ] Transcript/history is virtualized or bounded.
- [ ] Diff entries render path, line numbers, kind, and unified/side-by-side data.
- [ ] Task tree preserves depth and explicit status glyphs.
- [ ] Approvals are counted, focusable, and remain pending until daemon confirmation.
- [ ] Inline approval dock replaces the composer without hiding transcript/rail; arrows select, Enter chooses, approval takes two Enter steps, denial takes an inline reason, and Esc restores the draft.
- [ ] Reconnect uses a compact non-blocking strip, preserves context/draft/queue, and disables sends/decisions until resync.
- [ ] Enter on an Activity replaces the main pane with a full chronological safe child transcript and Esc returns with focus preserved.
- [ ] Workflow shows a selected phase and its simultaneous variable 0..n owned-agent roster; switching phase updates the roster, Enter opens a child, and Esc unwinds the back stack.
- [ ] Tool calls, agents/jobs, changed files, and budget are available without opening unrelated screens.

### Composer and attachments

- [ ] Composer includes prompt, mode/status, command hint, and compact attachment rows.
- [ ] Chip kind is visually distinct from muted source/metadata.
- [ ] File, image, paste, and path chips have accurate metadata.
- [ ] Multiple chips wrap deterministically without reordering or width changes on focus.
- [ ] Pending, error, and unsupported chips are explicit and restrained.
- [ ] Large text shows bounded metadata/preview only.
- [ ] Inspect, remove, and retry have keyboard and mouse paths.

### Interaction and accessibility

- [ ] Ctrl+K palette works.
- [ ] Model picker is compact and non-blocking, search-focused, grouped by provider, and has one peach selection row plus status/hints.
- [ ] `j/k` navigation is reachable and ordinary text input remains usable.
- [ ] Tab/arrow focus, click focus, scrolling, resize, workflow back-stack, and narrow stacked rail work.
- [ ] Shift-drag passes through to native selection where supported.
- [ ] Copy-on-select and OSC52/fallback behavior are safe.
- [ ] Bracketed paste treats pasted content as data and handles >32 KiB safely.
- [ ] Every important status has text/glyph redundancy.
- [ ] No routine event causes notification spam or unexpected scrolling.

### Verification artifacts

- [ ] Deterministic tests cover breakpoints, reducer transitions, attention routing, paste threshold, permission banners, selection/copy, mouse mappings, and attachment chips.
- [ ] Snapshot or equivalent render tests cover `docs/tui-proposal-conversation-operations.html` and behavior assertions cover its `.md` companion.
- [ ] Tests assert that no action is presented as complete without a corresponding daemon event.

## 15. Resolved product defaults

1. Context displays as `context <used> / <limit>` only when both values are confirmed. Confirmed cost and elapsed time may appear alongside it; absent values are omitted.
2. `POLICY` and `AI-VERIFIED` use distinct text labels with blue/violet secondary category treatment. Green remains reserved for an actual confirmed `+` diff addition only.
3. Replay uses opaque daemon cursors and event identities only. The TUI never derives ordering or duplicate behavior from a cursor's text or numeric shape.
4. Right-click opens an attachment context menu; it never removes immediately. `Delete` is the explicit keyboard remove action.
5. OSC52 fallback is native terminal selection plus the `select text and copy in terminal` hint, not an undocumented platform command.
6. Narrow Operations stacks below the conversation. At less than 60 columns or 16 rows, render only compact connection/permission state, the current conversation/dock, and `terminal too small; resize to continue`.
