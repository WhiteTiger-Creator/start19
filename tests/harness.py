"""Shared machinery for this task's verifier.

Paths, fixture loading, the unprivileged runner and the crafted-world
helpers live here so test_outputs.py carries assertions and nothing else.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import stat
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

APP = Path("/app")
DATA = APP / "data"
WORKFLOW_PATH = APP / "workflow" / "compile_policy.go"
# the three artifacts the contract names, in one place so the tests cannot drift
OUTPUT_FILES = ("compiled_policy.json", "exception_queue.jsonl", "summary.json")
ORIGINAL_WORKFLOW_PATH = APP / "workflow" / ".compile_policy.original.go"
SNAPSHOT_PATH = DATA / "rule_snapshot_pre_migration.json"
JOURNAL_PATH = DATA / "config_journal.json"
RULES_PATH = DATA / "policy_rules.json"
GROUPS_PATH = DATA / "object_groups.json"
POLICY_PATH = DATA / "firewall_policy.json"
SPEC_PATH = APP / "docs" / "policy_contract.json"
# The contract is golden metadata: the verifier reads it from its own image,
# never from the agent-writable copy under /app.
GOLDEN_CONTRACT_PATH = Path("/tests/fixtures/contract_golden.json")
LOG_PATH = APP / "incident" / "network_governance_log.md"
EXPECTED_FIXTURE = Path("/tests/fixtures/expected_report.json")
ALT_INPUT = Path("/tests/fixtures/alt_rules.json")

FIXTURE = json.loads(EXPECTED_FIXTURE.read_text())
SPEC = json.loads(GOLDEN_CONTRACT_PATH.read_text())

RULE_KEYS = set(SPEC["reconciled_inputs"]["policy_rules"]["record_fields"])
SUMMARY_KEYS = set(SPEC["outputs"]["summary"]["required_fields"])
COMPILED_KEYS = set(SPEC["outputs"]["compiled_policy"]["element_fields"])
QUEUE_KEYS = set(SPEC["outputs"]["exception_queue"]["element_fields"])
QUEUE_REASONS = set(SPEC["outputs"]["exception_queue"]["reasons"])

# Budget published by the contract and stated in instruction.md. Held as a literal
# so it cannot be relaxed by editing the environment, and cross-checked below.
RUNTIME_BUDGET_SEC = 90.0
# The contract's published budget IS the candidate timeout: an overrunning
# run is killed and the suite fails. No measured elapsed time is graded, so
# the verdict does not depend on how fast the grading host happens to be.
HARD_TIMEOUT_SEC = int(RUNTIME_BUDGET_SEC)

CANDIDATE_UID = 65534
_CWORK = Path("/candidate-work")
def _setpriv_prefix(base: list) -> list:
    """The strictest setpriv invocation this image actually supports.

    Dropping the uid is not the whole of it: a candidate that kept inheritable
    or bounding-set capabilities could regain privilege across an exec. The two
    flags are probed rather than assumed, because a util-linux without them
    would make every run fail on the flag rather than on the task.
    """
    strict = base + ["--inh-caps=-all", "--bounding-set=-all"]
    try:
        probe = subprocess.run(strict + ["/bin/true"], capture_output=True, timeout=30)
        if probe.returncode == 0:
            return strict
    except (OSError, subprocess.SubprocessError):
        pass
    return base


# Resource ceilings for anything run as the candidate. Deliberately not
# RLIMIT_AS or RLIMIT_DATA: a language runtime that reserves a large virtual
# arena at start-up dies under those, so they would kill a correct program
# rather than a runaway one. These bound the failure modes that actually escape
# a process group -- forking without end, filling the disk, dumping core.
_CANDIDATE_NPROC = 512
_CANDIDATE_FSIZE = 512 * 1024 * 1024
_CANDIDATE_NOFILE = 1024


def _apply_rlimits() -> None:
    """Run in the child between fork and exec: own session, plus ceilings."""
    import resource

    for what, limit in (
        (resource.RLIMIT_NPROC, _CANDIDATE_NPROC),
        (resource.RLIMIT_FSIZE, _CANDIDATE_FSIZE),
        (resource.RLIMIT_NOFILE, _CANDIDATE_NOFILE),
        (resource.RLIMIT_CORE, 0),
    ):
        try:
            _soft, hard = resource.getrlimit(what)
            ceiling = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
            resource.setrlimit(what, (ceiling, ceiling))
        except (ValueError, OSError):
            continue
    os.setsid()


def _pids_owned_by(uid: int) -> list:
    """Every live pid whose owner is `uid`, read from /proc."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.stat("/proc/" + entry).st_uid == uid:
                pids.append(int(entry))
        except OSError:
            continue
    return pids


def reap_candidate_uid(uid: int = CANDIDATE_UID) -> None:
    """Kill everything still running as the candidate, whatever group it is in.

    Killing the process group is not enough on its own: a submitted program can
    call setsid and leave its own group, and would then survive into later tests
    -- holding the staged inputs of the next run, or still writing into an
    output directory being read. Ownership is the property that cannot be
    escaped, so the sweep is by owner.
    """
    import signal as _signal
    import time as _time

    for _ in range(50):
        pids = _pids_owned_by(uid)
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                continue
        for pid in pids:
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                continue
        _time.sleep(0.02)


_SETPRIV = _setpriv_prefix(["setpriv", f"--reuid={CANDIDATE_UID}", f"--regid={CANDIDATE_UID}",
            "--clear-groups", "--no-new-privs"])
CHILD_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/candidate-work",
             "LANG": "C.UTF-8", "GOCACHE": "/candidate-work/gocache",
             "GO111MODULE": "off", "GOPATH": "/candidate-work/gopath"}
_BIN_CACHE: dict[str, str] = {}
_run_ctr = iter(range(1, 10_000))


def _digest(value) -> str:
    """Content digest of a decoded artifact, insensitive to free whitespace."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_jsonl(path):
    """Read a contracted JSONL artifact, taking every line as written.

    Skipping blank lines here softened a contract that says one compact object
    per line: a run that padded its output with empty lines read back the same
    as a clean one and scored full marks. A blank line is a malformed line and
    is read as one.
    """
    text = Path(path).read_text(encoding="utf-8")
    if not text:
        return []
    assert text.endswith("\n"), f"{Path(path).name} has no trailing newline"
    lines = text.split("\n")[:-1]
    for number, line in enumerate(lines, start=1):
        assert line.strip(), f"{Path(path).name} line {number} is blank"
    return [json.loads(line) for line in lines]


def _write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse_cidr(text: str):
    """Return (masked network base, prefix length) for a dotted-quad IPv4 prefix."""
    body, _, plen_text = text.partition("/")
    plen = int(plen_text)
    assert 0 <= plen <= 32, text
    octets = body.split(".")
    assert len(octets) == 4, text
    base = 0
    for o in octets:
        n = int(o)
        assert 0 <= n <= 255, text
        base = base << 8 | n
    mask = 0 if plen == 0 else (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
    return base & mask, plen


def _build(script_path: Path) -> str:
    """Compile the submitted single-file compiler, cached per source path.

    Compilation runs as root: it is the trusted verifier's own action. The source
    is copied to a temp dir as main.go first so the frozen snapshot and any
    sibling files in /app/workflow never join the build.
    """
    key = str(script_path)
    if key in _BIN_CACHE:
        return _BIN_CACHE[key]
    build_dir = tempfile.mkdtemp(prefix="gobuild_")
    os.chmod(build_dir, 0o755)
    src = Path(build_dir) / "main.go"
    shutil.copyfile(script_path, src)
    binary = Path(build_dir) / "compiler"
    result = subprocess.run(
        ["go", "build", "-o", str(binary), str(src)],
        capture_output=True, text=True,
        env={**os.environ, "GOCACHE": "/tmp/gocache", "GO111MODULE": "off", "GOPATH": "/tmp/gopath"},
        preexec_fn=_apply_rlimits,
    )
    reap_candidate_uid()
    assert result.returncode == 0, f"go build failed:\n{result.stderr}"
    os.chmod(binary, 0o755)
    _BIN_CACHE[key] = str(binary)
    return str(binary)


def _candidate_dir() -> Path:
    """A fresh work area for one run, created where nothing can pre-empt it.

    /candidate-work is world-writable, so a predictable name here was an opening:
    a submission could plant the next `run-N` as a symlink to the sealed fixtures
    and wait. The root-side mkdir(exist_ok=True) would succeed through the link
    and the chmod would follow it, since os.chmod resolves symlinks and Linux has
    no lchmod. mkdtemp closes both halves -- the name is unpredictable and the
    directory is created fresh or not at all.
    """
    d = Path(tempfile.mkdtemp(prefix=f"run-{next(_run_ctr)}-", dir=str(_CWORK)))
    assert not d.is_symlink(), d
    os.chmod(d, 0o777)
    return d


def _publish_inputs() -> None:
    """Open read access on the agent-produced inputs before privileges drop.

    Never follows a link out of the agent-owned tree: os.chmod resolves symlinks,
    so a link planted at /app/... -> /tests would otherwise open the sealed
    fixtures to the unprivileged candidate.
    """
    app_root = APP.resolve()
    for path in sorted(APP.rglob("*")):
        if path.is_symlink():
            continue
        try:
            if not path.resolve().is_relative_to(app_root):
                continue
        except OSError:
            continue
        try:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        except OSError:
            pass


def _reap_group(pgid: int) -> None:
    """Kill and reap everything left in the candidate's process group.

    start_new_session makes the candidate a session and group leader, so its pgid
    equals its pid and every process it spawns shares that group. The id is
    captured before the run: once the direct child has been waited on its pgid can
    no longer be looked up, and a leaked grandchild would survive to keep writing
    while the outputs are graded.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        return
    for _ in range(50):
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError, OSError):
            return
        time.sleep(0.02)


def _run_agent(argv, cwd: Path):
    """Run the submitted program unprivileged and in its own process group.

    Output goes to temporary files rather than pipes: communicate() returns when
    the pipes reach EOF, not when the program exits, so a child that called
    setsid and outlived its parent while holding the write end would stall the
    read out. And no inner deadline -- Harbor already bounds the verifier, and a
    second clock only adds a way for a correct but slow run to fail on a loaded
    grading machine.
    """
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as out_fh, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as err_fh:
        proc = subprocess.Popen(
            _SETPRIV + argv, cwd=str(cwd), env=dict(CHILD_ENV),
            stdout=out_fh, stderr=err_fh,
            preexec_fn=_apply_rlimits,
        )
        pgid = proc.pid      # session leader: pgid == pid, captured before the wait
        try:
            proc.wait()
        finally:
            _reap_group(pgid)
            reap_candidate_uid()
        out_fh.seek(0)
        err_fh.seek(0)
        result = subprocess.CompletedProcess(argv, proc.returncode, out_fh.read(), err_fh.read())
    return result


def _stage_input(src: Path, dst: Path) -> None:
    """Copy `src` to `dst` as a regular file, never through a link.

    The default input is the one path under /app/data the agent is told to
    replace, and staging runs as root. shutil.copyfile follows the source link, so
    a submission that left a symlink there instead of a rebuilt rule set pointed
    root at whatever it named -- the sealed fixtures under /tests included -- and
    had the contents laid down inside the candidate's own work area, where the
    graded program reads it. O_NOFOLLOW refuses the link at the final component
    and the fstat refuses anything that is not a regular file.
    """
    try:
        handle = os.open(str(src), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise AssertionError(
            f"{src} could not be staged as a regular file: {exc}") from exc
    try:
        info = os.fstat(handle)
        assert stat.S_ISREG(info.st_mode), (
            f"{src} is not a regular file, so it is not staged")
        payload = b""
        while True:
            chunk = os.read(handle, 1 << 20)
            if not chunk:
                break
            payload += chunk
    finally:
        os.close(handle)
    dst.write_bytes(payload)
    os.chmod(dst, 0o644)


def _run_pipeline(script_path: Path = WORKFLOW_PATH, input_path: Path = RULES_PATH):
    """Build and run the submitted compiler as an unprivileged subprocess."""
    binary = _build(script_path)
    _publish_inputs()
    work = _candidate_dir()
    out_dir = work / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o777)
    staged = work / "rules.json"
    _stage_input(Path(input_path), staged)
    os.chmod(staged, 0o644)
    result = _run_agent([binary, "--input", str(staged), "--output-dir", str(out_dir)], cwd=work)
    assert result.returncode == 0, f"compiler failed:\n{result.stdout}\n{result.stderr}"
    return (out_dir,
            _load_json(out_dir / "summary.json"),
            _load_json(out_dir / "compiled_policy.json"),
            _load_jsonl(out_dir / "exception_queue.jsonl"))


def _rule(rid, seq, *, action="permit", protocol="tcp", src=("10.0.0.0/8",),
          dst=("192.168.0.0/16",), lo=80, hi=80, enabled=True):
    return {"rule_id": rid, "sequence": seq, "action": action, "protocol": protocol,
            "source_cidrs": list(src), "destination_cidrs": list(dst),
            "port_low": lo, "port_high": hi, "enabled": enabled}


def _probe(rules, *, max_rules=1000, port_ceiling=65535, lookback=120, deny_seq=999000,
           omit=()):
    """Run the submitted compiler over a crafted rule base and return its artifacts.

    `omit` names policy fields to leave OUT of the file altogether, which is how
    #NET-9210's per-field baselines are exercised: every other caller writes all
    four, so a compiler that read the map directly and never fell back was never
    caught by anything here.
    """
    saved = POLICY_PATH.read_text(encoding="utf-8")
    staged = _CWORK / f"probe-{next(_run_ctr)}.json"
    try:
        default = {"max_rules": max_rules, "port_ceiling": port_ceiling,
                   "max_shadow_lookback": lookback, "default_deny_sequence": deny_seq}
        for field in omit:
            del default[field]
        _write_json(POLICY_PATH, {"default": default})
        _write_json(staged, rules)
        os.chmod(staged, 0o644)
        return _run_pipeline(input_path=staged)
    finally:
        POLICY_PATH.write_text(saved, encoding="utf-8")


# The probe the isolation test compiles and runs as the candidate uid: it reports
# its own uid, whether it could write the reward file, and whether it could read
# each sealed verifier asset.
ISOLATION_PROBE_SOURCE = (
        'package main\n\nimport ("fmt"; "os")\n\n'
        'func readable(p string) bool {\n'
        '\tf, err := os.Open(p)\n'
        '\tif err != nil {\n\t\treturn false\n\t}\n'
        '\tdefer f.Close()\n'
        '\tb := make([]byte, 1)\n'
        '\t_, err = f.Read(b)\n'
        '\treturn err == nil\n}\n\n'
        'func main() {\n\tfmt.Println(os.Getuid())\n'
        '\terr := os.WriteFile("/logs/verifier/reward.txt", []byte("1"), 0o644)\n'
        '\tfmt.Println(err != nil)\n'
        '\tfor _, p := range []string{\n'
        '\t\t"/logs/verifier/reward.txt",\n'
        '\t\t"/tests/fixtures/expected_report.json",\n'
        '\t\t"/tests/fixtures/contract_golden.json",\n'
        '\t\t"/tests/test_outputs.py",\n'
        '\t} {\n\t\tfmt.Println(p, readable(p))\n\t}\n}\n')


def replay_variant(by_seq: bool, restore_from_snapshot: bool, deep_groups: bool) -> str:
    """Re-derive the rule base under one reading of the recovery and digest it.

    The verifier's own reading, independent of the reference: `by_seq` replays in
    ascending seq rather than file order, `restore_from_snapshot` re-reads the
    snapshot on a restoration rather than returning the held state, and
    `deep_groups` expands an object group transitively rather than one level.
    Passing all three gives the governed reading; each of the others is a
    plausible misreading the graded digest must not match.
    """
    snapshot = {r["rule_id"]: r for r in _load_json(SNAPSHOT_PATH)}
    journal = _load_json(JOURNAL_PATH)
    catalogue = {g["group_id"]: g["members"] for g in _load_json(GROUPS_PATH)}

    def resolve(ref, deep):
        out = set()

        def walk(gid, seen):
            if gid in seen or gid not in catalogue:
                return
            seen.add(gid)
            for m in catalogue[gid]:
                if m.startswith("@"):
                    if deep:
                        walk(m[1:], seen)
                else:
                    b, p = _parse_cidr(m)
                    out.add("%d.%d.%d.%d/%d" % (b >> 24 & 255, b >> 16 & 255, b >> 8 & 255, b & 255, p))

        if ref.startswith("@"):
            walk(ref[1:], set())
        else:
            b, p = _parse_cidr(ref)
            out.add("%d.%d.%d.%d/%d" % (b >> 24 & 255, b >> 16 & 255, b >> 8 & 255, b & 255, p))
        return sorted(out, key=_parse_cidr)

    def replay(by_seq: bool, restore_from_snapshot: bool, deep_groups: bool):
        live = {k: dict(v) for k, v in snapshot.items()}
        held = {}
        for c in (sorted(journal, key=lambda x: x["seq"]) if by_seq else journal):
            k, kind = c["rule_id"], c["kind"]
            if kind == "amend" and k in live:
                live[k][c["field"]] = c["value"]
            elif kind == "retract" and k in live:
                held[k] = dict(live.pop(k))
            elif kind == "restore":
                if restore_from_snapshot:
                    if k in snapshot and k not in live:
                        live[k] = dict(snapshot[k])
                elif k in held:
                    live[k] = held.pop(k)
        rows = []
        for r in live.values():
            rows.append({
                "rule_id": r["rule_id"], "sequence": r["sequence"], "action": r["action"],
                "protocol": r["protocol"], "source_cidrs": resolve(r["source"], deep_groups),
                "destination_cidrs": resolve(r["destination"], deep_groups),
                "port_low": r["port_low"], "port_high": r["port_high"], "enabled": r["enabled"]})
        rows.sort(key=lambda r: (r["sequence"], r["rule_id"]))
        return _digest(rows)
    return replay(by_seq, restore_from_snapshot, deep_groups)


__all__ = [
    "GOLDEN_CONTRACT_PATH",
    "replay_variant",
    "ISOLATION_PROBE_SOURCE",
    "_rule",
    "_probe",
    "annotations",
    "hashlib",
    "json",
    "os",
    "shutil",
    "signal",
    "subprocess",
    "tempfile",
    "time",
    "ast",
    "OUTPUT_FILES",
    "Path",
    "pytest",
    "APP",
    "DATA",
    "WORKFLOW_PATH",
    "ORIGINAL_WORKFLOW_PATH",
    "SNAPSHOT_PATH",
    "JOURNAL_PATH",
    "RULES_PATH",
    "GROUPS_PATH",
    "POLICY_PATH",
    "SPEC_PATH",
    "LOG_PATH",
    "EXPECTED_FIXTURE",
    "ALT_INPUT",
    "FIXTURE",
    "SPEC",
    "RULE_KEYS",
    "SUMMARY_KEYS",
    "COMPILED_KEYS",
    "QUEUE_KEYS",
    "QUEUE_REASONS",
    "RUNTIME_BUDGET_SEC",
    "HARD_TIMEOUT_SEC",
    "CANDIDATE_UID",
    "_CWORK",
    "_SETPRIV",
    "CHILD_ENV",
    "_BIN_CACHE",
    "_run_ctr",
    "_digest",
    "_load_json",
    "_load_jsonl",
    "_write_json",
    "_parse_cidr",
    "_build",
    "_candidate_dir",
    "_publish_inputs",
    "_run_agent",
    "_stage_input",
    "_run_pipeline",
]
