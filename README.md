# claude-watch
Claude agent shell monitoring for macOS.

`eslogger` can't filter by process tree, so filtering on the Claude binary alone would miss the zsh, git and rm processes it spawns. The script below follows Claude's whole process tree through fork/exec/exit events and prints only what Claude and its descendants run. It also flags anything matching your Claude Code deny rules.

## Run it
```
$ sudo python3 claude_watch.py [--log ~/claude-exec.jsonl]
```
- It auto-loads the `Bash(...)` deny rules from your `~/.claude/settings.json`. Add project rules with `--claude-settings path/.claude/settings.json`, or plain regexes with `--deny file.txt`.
- It picks up Claude sessions that are already running, and any you start afterwards.
- Output is indented by tree depth. Deny matches show in red, and commands that could escape the tree show in yellow.

## How it narrows the stream
A process becomes a "root" when its exec target looks like Claude Code: the native `~/.local/share/claude/versions/...` binary, a `claude` executable, or the `npm @anthropic-ai/claude-code` package. If your install differs, change this with `--match`.
Every fork from a tracked process adds the child to the tree, and every exit removes it. There's also a parent-PID fallback in case a spawn doesn't produce a fork event.
Lineage is recorded when the process is born, so a process that double-forks to get reparented to launchd is still attributed to Claude.
I tested it with simulated events: a `zsh -c "echo hi; rm -rf build"` and its `rm` child were both flagged, a `git push` from Claude was flagged, and the same `git push` from an unrelated process was ignored. I couldn't run it against real `eslogger` here, so check the first few lines of real output.

## What you will see
Claude's own housekeeping, such as `git status` and `rg` for searches. Not every line is a command the model chose.
MCP servers Claude launches (e.g. `npx ...`) and everything they run. You probably want this.
False positives: a deny pattern can match inside harmless text, like `grep "rm -rf" notes.md` or a commit message. Treat red lines as "look at this", not proof.
Escape routes, flagged yellow: `open`, `launchctl`, `osascript`, `at`, `crontab`, `tmux` and `screen` can start work that `launchd` runs outside Claude's tree, so it won't show up here. Watch for these in particular.

## License
MIT
