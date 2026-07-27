# Gorce — Conversation Operations

## Direction

The conversation is the main surface: a chronological exchange of user requests and agent responses, with concise safe activity summaries, tool results, diffs, and confirmed changes woven into the thread. It deliberately never exposes private chain-of-thought.

The right rail is persistent operational context, not a dashboard. Todos form a small task tree. Activities list durable runs and subagents with status and latest work; `Enter` opens that child run's full chronological transcript, with task, budget, latest confirmed activity, and attach/detach in compact context. The attention row remains present until its approval is resolved.

## Focus model

There is one visible active focus at a time, marked by a peach rail, rule, or outline plus a text/glyph label. When an approval is pending, focus lands in the inline approval dock at the bottom of the conversation; the transcript and right rail never dim or disappear. `Esc` restores the preserved composer draft and leaves the approval pending. Conversation focus lands in the composer otherwise; Operations focus lands on the selected activity. `Enter` on an Activity changes the main pane to that child run's conversation; it does not open a metric-card overlay. A workflow is an ordered phase list where every selected phase simultaneously owns a visible 0..n child-agent roster; focus moves between the phase list and that roster before opening one selected child detail. Cards are framed and compact, but the conversation owns the available width and visual rhythm.

## Keyboard grammar

- `c` focus composer; `Enter` send; `Shift+Enter` add a line; `⌘K` attach; `Ctrl+K` open model/mode picker.
- `o` focus Operations; `j` / `k` move through activities; `Enter` open the selected activity detail; `d` detach, `Enter` attach.
- `n` jump to the next attention; `a` focus the inline approval dock.
- In the dock, `↑`/`↓` (also `j`/`k`) select an option; `Enter` chooses. Options are **Approve once**, **Deny with reason**, **Inspect exact scope**, and **Return to composer**.
- Approve requires a second `Enter` in the same dock. Deny opens an inline reason field; `Enter` submits the reason. Submitted decisions are labelled local/pending until a confirmed daemon event arrives.
- `[` / `]` move through the approval queue (`1 / 2` is always visible). `Esc` backs out of confirmation/reason entry, or restores the composer draft while leaving approval pending.
- `Enter` on an Activity opens its child transcript in the main pane; `Esc` returns to the parent conversation with prior focus/scroll context. `d` detaches and `Enter` attaches from the child detail footer.
- `w` or `5` opens the workflow main view. Desktop shows the selected phase and its full heterogeneous roster at the same time: agents may be concurrent, queued, blocked, complete, retrying, or not-yet-created. `↑`/`↓` or `j/k` move within the focused phase or agent list; `Tab` switches phase ↔ agent focus; selecting another phase immediately replaces the owned roster. `Enter` on an agent opens its child transcript/detail. The selected child reports lifecycle, retry/error, elapsed, budget, attention, cursor, retention, and live-follow state.
- `4` enters non-blocking reconnect mode; `r` retries. `1`–`3` switch conversation, child activity, and approval dock states. `?` is the shortcut entry point.

Mouse clicks accelerate selection only; every route and action has a keyboard path.

## Truth and responsive behavior

Reconnect is non-blocking: a compact chrome strip says `SYNCING · events held · cursor … · r retry` while the current conversation, rail, draft, and approval queue remain readable. Send and decision controls are disabled until resync; no takeover, giant progress bar, optimistic approval, or lost draft is allowed. The model picker shows the selected model and mode.

The terminal surface prohibits hero blocks, marketing copy, oversized page titles, and decorative serif headings. Workstream/run identity must occupy at most one compact monospace row, for example `release / 2.4 · run r-018 · RUNNING`; the first conversation item begins immediately beneath that chrome. Dedicated detail, approval, reconnect, and workflow surfaces use compact terminal typography as well. Workflow ownership is data, not decoration: phases own agent rosters and do not duplicate child agents as top-level Activities.

Below 820px, the conversation stays first and the Operations rail stacks beneath it. The approval dock changes its four-column option row into a readable vertical list while keeping arrows, `Enter`, `Esc`, and queue navigation visible. Child transcript and workflow views remain the full main pane with the rail below; workflow shows one hierarchy level at a time instead of shrinking phases, agents, and detail into unreadable columns. Reconnect remains a compact strip. No information depends on hover or side-by-side width.

## View and back-stack semantics

The parent conversation is the root. Activity `Enter` pushes a child transcript onto the main-pane stack; `Esc` pops to the parent without changing the selected Activity. Workflow `w` pushes a workflow view; the phase and its owned agent roster are visible together. `Tab` changes list focus, `Enter` opens the selected agent transcript/detail, and `Esc` first returns to that same phase roster, then leaves the workflow to the conversation. Reconnect is a connection flag, not a view push, so it never discards the current location.

## Acceptance criteria

- Reconnect keeps conversation, Todos/Activities, draft, and approval queue visible; only sending and decisions are disabled.
- Activity detail is a chronological conversation with safe summaries, tool results, diffs, confirmed state, retention, and live-follow status—never private reasoning or an overlay of metric cards.
- Workflow ownership is explicit: every phase visibly has a variable 0..n roster; phase aggregates and per-agent role, lifecycle, latest confirmed event, retry, and attention are shown together. Switching phase immediately changes that roster, with at least one phase demonstrating concurrent heterogeneous agents and planned/not-yet-created work.
- Opening an agent and pressing `Esc` restores the same phase, agent roster, selected agent, and scroll/focus context; the next workflow `Esc` returns to the conversation.
- Every destructive or externally visible decision remains deliberate, local/pending until a daemon confirmation, and reachable through arrows, `Enter`, and `Esc`.

## Palette contract

The palette is self-contained and matches the approved HTML counterpart: `--ink:#0a1018` for the near-black page and frame, `--panel:#0f1822` for framed surfaces, `--panel-2:#121e2a` for raised rows, `--rule:#263746` for graphite dividers, `--paper:#e9e4d5` for warm primary text, and `--muted:#8594a1` for metadata. `--orange:#ffad5a` marks live safe activity, waiting attention, and approval. `--peach:#f0a08d` marks keyboard focus, selected rows, composer focus, and explicit picker/action selection. `--coral:#ff6f61` marks danger or denial. `--blue:#82aaff` and `--violet:#b8a1ea` identify provider/model groups and secondary categories. Connected and healthy states use subdued neutral text and glyphs. The only green allowed anywhere is the muted diff-addition color on an actual `+` addition; green is never a focus, health, panel, border, hint, or action color.

Exact role changes from the previous candidate: lime focus → peach `#f0a08d`; green-tinted selection and panel treatments → neutral blue-black `#20252d`; focus outlines, activity-detail borders, Enter/detach actions, and keyboard hints now use peach; live activity and approval remain orange `#ffad5a`; danger remains coral `#ff6f61`; provider/model grouping remains blue `#82aaff` and violet `#b8a1ea`; all framed-card rules use `#263746`. The terminal removes the conversation hero/title block, its subtitle, large serif treatment, and excess vertical spacing: compact identity chrome is followed directly by the conversation. Approval is now an inline bottom dock, not a blocking modal: it replaces the composer only while pending, preserves the draft, keeps transcript and rail visible, supports arrow selection, second-step approval, inline denial reasons, scope expansion, queue navigation, and daemon-confirmed pending truth.
