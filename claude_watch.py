#!/usr/bin/env python3
"""
claude_watch.py - log every process Claude Code (and its descendants) executes,
using macOS Endpoint Security via eslogger, and flag deny-list matches.

Usage:
  sudo python3 claude_watch.py                       # auto-loads your ~/.claude/settings.json deny rules
  sudo python3 claude_watch.py --deny my-deny.txt    # extra regexes, one per line
  sudo python3 claude_watch.py --log ~/claude-exec.jsonl
  sudo eslogger fork exec exit | python3 claude_watch.py --stdin   # alternative plumbing

Only stdlib. Requires root + Full Disk Access on the launching terminal.
"""
import argparse, json, os, re, shlex, subprocess, sys
from collections import defaultdict
from datetime import datetime

DEFAULT_MATCH = r"(^|/)claude$|/claude/versions/|@anthropic-ai/claude-code"
# Binaries that can launch work *outside* the process tree (reparented to launchd),
# i.e. the ways an agent could escape this monitor. Always flagged.
ESCAPE_BINS = {"open", "launchctl", "osascript", "at", "batch", "crontab", "screen", "tmux"}

TTY = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if TTY else s


def user_home():
    u = os.environ.get("SUDO_USER")
    return os.path.expanduser(f"~{u}") if u else os.path.expanduser("~")


def bash_rule_to_regex(rule):
    """Convert a Claude Code rule like Bash(rm -rf:*) or Bash(git push *) to a regex."""
    m = re.fullmatch(r"Bash\((.*)\)", rule.strip())
    if not m:
        return None
    body = m.group(1).strip()
    if body.endswith(":*"):
        body = body[:-2]
    parts = [re.escape(p) for p in body.split("*")]
    # Match at start of command or after a separator / path slash (catches /bin/rm, bash -c "...; rm").
    return r"(?:^|[\s;&|(`'\"/])" + ".*".join(parts)


def load_deny(args):
    pats = []
    settings = list(args.claude_settings or [])
    if not args.no_default_settings:
        settings.append(os.path.join(user_home(), ".claude", "settings.json"))
    for path in settings:
        try:
            with open(path) as f:
                rules = json.load(f).get("permissions", {}).get("deny", [])
        except (OSError, ValueError):
            continue
        for r in rules:
            rx = bash_rule_to_regex(r)
            if rx:
                pats.append((f"{os.path.basename(path)}: {r}", re.compile(rx)))
    for path in args.deny or []:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    pats.append((line, re.compile(line)))
    return pats


class Tracker:
    def __init__(self, match_rx, deny, log):
        self.match = re.compile(match_rx)
        self.deny = deny
        self.log = log
        self.tracked = {}  # pid -> {"root": pid, "depth": n}

    def is_claude(self, path, argv):
        return any(self.match.search(t or "") for t in [path, *argv[:3]])

    def add(self, pid, parent):
        p = self.tracked[parent]
        self.tracked[pid] = {"root": p["root"], "depth": p["depth"] + 1}

    def seed(self):
        """Pick up Claude sessions (and their children) already running."""
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,args="], capture_output=True, text=True).stdout
        kids, roots = defaultdict(list), []
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            pid, ppid, args = int(parts[0]), int(parts[1]), parts[2]
            kids[ppid].append(pid)
            if pid != os.getpid() and self.is_claude("", args.split()[:3]):
                roots.append(pid)
        stack = []
        for r in roots:
            self.tracked[r] = {"root": r, "depth": 0}
            stack.append(r)
        while stack:
            p = stack.pop()
            for k in kids[p]:
                if k not in self.tracked:
                    self.add(k, p)
                    stack.append(k)
        print(c("2", f"seeded {len(roots)} running Claude session(s), {len(self.tracked)} process(es)"))

    def handle(self, ev):
        e = ev.get("event", {})
        proc = ev.get("process", {})
        pid = proc.get("audit_token", {}).get("pid")
        ppid = proc.get("ppid")
        if pid is None:
            return

        if "fork" in e:
            child = e["fork"].get("child", {}).get("audit_token", {}).get("pid")
            if child is not None and pid in self.tracked:
                self.add(child, pid)
        elif "exit" in e:
            self.tracked.pop(pid, None)
        elif "exec" in e:
            ex = e["exec"]
            path = ex.get("target", {}).get("executable", {}).get("path", "")
            argv = ex.get("args") or [path]
            new_root = False
            # posix_spawn safety net: attribute by parent pid if we missed the fork.
            if pid not in self.tracked and ppid in self.tracked:
                self.add(pid, ppid)
            if pid not in self.tracked and self.is_claude(path, argv):
                self.tracked[pid] = {"root": pid, "depth": 0}
                new_root = True
            if pid in self.tracked:
                self.report(ev.get("time", ""), pid, ppid, path, argv, new_root)

    def report(self, ts, pid, ppid, path, argv, new_root):
        info = self.tracked[pid]
        cmd = shlex.join(argv)
        hits = [name for name, rx in self.deny if rx.search(cmd)]
        escape = os.path.basename(path) in ESCAPE_BINS
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
        except ValueError:
            t = ts[:19]
        indent = "  " * min(info["depth"], 8)
        line = f"{t} {pid:>6} {ppid or 0:>6} {indent}{cmd}"
        if new_root:
            print(c("1;36", f"── new Claude session (pid {pid}) ──"))
        if hits:
            print(c("1;31", f"{line}\n       !! DENY MATCH: {'; '.join(hits)}"))
        elif escape:
            print(c("1;33", f"{line}\n       ?? can spawn outside the tree"))
        else:
            print(line)
        sys.stdout.flush()
        if self.log:
            self.log.write(json.dumps({"time": ts, "pid": pid, "ppid": ppid, "root": info["root"],
                                       "path": path, "argv": argv, "deny_hits": hits,
                                       "escape": escape}) + "\n")
            self.log.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--deny", action="append", help="file of regexes (one per line) to flag")
    ap.add_argument("--claude-settings", action="append", help="extra settings.json to read deny rules from")
    ap.add_argument("--no-default-settings", action="store_true", help="don't auto-load ~/.claude/settings.json")
    ap.add_argument("--match", default=DEFAULT_MATCH, help="regex identifying the Claude Code binary")
    ap.add_argument("--log", help="append JSONL records to this file")
    ap.add_argument("--stdin", action="store_true", help="read eslogger JSON from stdin")
    ap.add_argument("--no-seed", action="store_true", help="don't scan already-running processes")
    args = ap.parse_args()

    deny = load_deny(args)
    print(c("2", f"loaded {len(deny)} deny pattern(s)"))
    log = open(os.path.expanduser(args.log), "a") if args.log else None
    tr = Tracker(args.match, deny, log)
    if not args.no_seed:
        tr.seed()

    if args.stdin:
        src = sys.stdin
    else:
        if os.geteuid() != 0:
            sys.exit("run with sudo (eslogger needs root)")
        proc = subprocess.Popen(["eslogger", "fork", "exec", "exit"],
                                stdout=subprocess.PIPE, text=True, bufsize=1)
        src = proc.stdout
    try:
        for raw in src:
            try:
                tr.handle(json.loads(raw))
            except (ValueError, KeyError, TypeError):
                continue
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
