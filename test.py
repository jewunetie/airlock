"""Regression checks and measurements for airlock; nothing runs on import.

Call test_packaging(), test_cli(), test_console(), test_round_guard(),
test_cross_round(), test_guard(), test_server(), test_doctor(), test_worker(),
test_tax(), or test_measurements().
Each returns Checks and raises AssertionError on failure or missing checks.
Unavailable prerequisites are recorded separately from passes.

Measurements: build_dataset(), load_ai4privacy(), load_nemotron(), load_gretel(),
load_tab(), measure_guard(), measure_reassembly_floor(), measure_reassembly_cost().
Corpus loaders explicitly fetch public data through the optional datasets package.
Tax fixtures need reportlab. Guard/worker checks need the corresponding models.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import base64
import contextlib
import io
import json
import os
import random
import re
import secrets
import statistics
import string
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import airlock

REPO = Path(__file__).resolve().parent
AIRLOCK = REPO / "airlock.py"
PYPROJECT = REPO / "pyproject.toml"
DEFAULT_SEED = 20260817
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "/+"
SSN = "912-84-7731"


@dataclass
class Checks:
    """One invocation's evidence; unavailable checks are never passes."""

    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unavailable: list[tuple[str, str]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list, repr=False)
    _resources: contextlib.ExitStack = field(
        default_factory=contextlib.ExitStack, repr=False
    )

    def check(self, name: str, ok: bool, detail: object = "") -> None:
        if ok:
            self.passed.append(name)
        else:
            self.failed.append(f"{name}: {detail}")

    def skip(self, name: str, why: str) -> None:
        self.unavailable.append((name, why))

    def directory(self, prefix: str = "airlock-test-") -> Path:
        return Path(
            self._resources.enter_context(tempfile.TemporaryDirectory(prefix=prefix))
        )

    def finish(self, expected: int) -> Checks:
        total = len(self.passed) + len(self.failed) + len(self.unavailable)
        assert total >= expected, (
            f"Only {total}/{expected} checks collected; failures: {self.failed}"
        )
        assert not self.failed, "\n".join(self.failed + self.diagnostics)
        return self


@contextlib.contextmanager
def _test_scope():
    """Restore application state and dispose only of this call's fixtures."""
    checks = Checks()
    with checks._resources as stack:
        stack.enter_context(patch.dict(os.environ))
        for name, value in (
            ("SESSIONS", {}),
            ("UI_CONFIG", {}),
            ("UI_PENDING", {}),
            ("UI_EVENTS", deque(maxlen=airlock.UI_EVENT_CAP)),
            ("TRACE_PATH", None),
        ):
            stack.enter_context(patch.object(airlock, name, value))
        yield checks


def _fake_credential(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    """A syntactically valid, entirely fake credential. See CLAUDE.md."""
    return prefix + "".join((secrets.choice(alphabet) for _ in range(length)))


def _stub_answers(answers):
    # Exhaustion must expose an unexpected extra worker call.
    it = iter(answers)
    return lambda *args, **kwargs: next(it)


def _run_jobs_with_answers(session, jobs, answers):
    with patch.object(airlock, "ollama_chat", _stub_answers(answers)):
        return airlock.run_jobs(session, jobs)


def _session_over(root: Path, allow_writes: bool = False):
    return airlock.Session(
        session_id="test",
        objective="x",
        worker_model="stub-worker",
        sandbox=airlock.Sandbox(root=root, allow_writes=allow_writes),
    )


def _server_args(root: Path, **overrides):
    return argparse.Namespace(
        **{**airlock.CLI_DEFAULTS, "root": root, "approve": "none", **overrides}
    )


# Packaging


def test_packaging() -> Checks:
    """Packaging; return evidence or raise on failure."""
    with _test_scope() as checks:
        pep723 = _read_pep723_metadata(AIRLOCK)
        pyproject = tomllib.loads(PYPROJECT.read_text())
        project = pyproject["project"]
        script_deps = pep723.get("dependencies", [])
        project_deps = project.get("dependencies", [])
        checks.check(
            "dependency lists agree exactly",
            sorted(script_deps) == sorted(project_deps),
            f"script={sorted(script_deps)} pyproject={sorted(project_deps)}",
        )
        checks.check(
            "no duplicate dependency entries in either list",
            len(script_deps) == len(set(script_deps))
            and len(project_deps) == len(set(project_deps)),
        )
        checks.check(
            "requires-python agrees",
            pep723.get("requires-python") == project.get("requires-python"),
            f"script={pep723.get('requires-python')!r} pyproject={project.get('requires-python')!r}",
        )
        checks.check(
            "console script points at airlock:main",
            project.get("scripts", {}).get("airlock") == "airlock:main",
        )
        return checks.finish(4)


def _read_pep723_metadata(script: Path) -> dict:
    text = script.read_text()
    match = re.search(
        "(?m)^# /// script\\s*$\\n(?P<body>(?:^#.*\\n)*?)^# ///\\s*$", text
    )
    if not match:
        raise ValueError(f"no PEP 723 script block found in {script}")
    lines = []
    for line in match.group("body").splitlines():
        if line == "#":
            lines.append("")
        elif line.startswith("# "):
            lines.append(line[2:])
        else:
            raise ValueError(f"malformed PEP 723 metadata line: {line!r}")
    return tomllib.loads("\n".join(lines))


# Cli


def test_cli() -> Checks:
    """CLI parsing, client config writes and settings, without models."""
    with _test_scope() as checks:
        original_home = Path.home()
        routes = {
            (): "cmd_connect",
            ("~/notes",): "cmd_connect",
            ("status",): "cmd_status",
            ("disconnect",): "cmd_disconnect",
            ("check", "hello"): "cmd_guard",
            ("chat",): "cmd_chat_or_ask",
            ("serve", "/tmp"): "cmd_serve",
        }
        for argv, func in routes.items():
            checks.check(
                f"{'airlock ' + ' '.join(argv):32} routes to {func}",
                _parse_cli(list(argv)).func.__name__ == func,
            )
        checks.check(
            "a bare folder becomes the workspace",
            str(_parse_cli(["~/notes"]).root) == "~/notes",
        )
        checks.check(
            "a folder named like a command is still the command",
            _parse_cli(["status"]).func.__name__ == "cmd_status",
        )
        checks.check(
            "a flag's value is not mistaken for the command",
            airlock.insert_default_command(["--ask", "always", "~/x"])
            == ["connect", "--ask", "always", "~/x"],
            str(airlock.insert_default_command(["--ask", "always", "~/x"])),
        )
        for passthrough in (["--help"], ["-h"], ["--version"], []):
            checks.check(
                f"{passthrough or ['(empty)']} is passed through untouched",
                airlock.insert_default_command(list(passthrough)) == passthrough,
            )
        checks.check(
            "COMMANDS matches the registered subparsers",
            set(airlock.COMMANDS)
            == set(airlock.build_parser()._subparsers._group_actions[0].choices),
        )
        for argv, expected in [
            ([], "hint-writes"),
            (["--write"], "gate-writes"),
            (["--ask", "always"], "gate-all"),
            (["--ask", "always", "--write"], "gate-all"),
            (["--ask", "never"], "none"),
            (["--ask", "never", "--write"], "none"),
            (["--ask", "writes"], "hint-writes"),
            (["--ask", "writes", "--write"], "gate-writes"),
        ]:
            got = _parse_cli(argv + ["~/x"]).approve
            checks.check(
                f"{' '.join(argv) or '(no flags)':28} -> approve {expected}",
                got == expected,
                got,
            )
        checks.check(
            "nothing but an explicit --ask never disables approval entirely",
            all(
                (
                    _parse_cli(a + ["~/x"]).approve != "none"
                    for a in ([], ["--write"], ["--ask", "always"], ["--ask", "writes"])
                )
            ),
        )
        parser = airlock.build_parser()
        workspace = Path(__file__).resolve().parent
        emitted = _cli_args(root=workspace)
        for client in airlock.MCP_CLIENTS:
            entry = airlock.airlock_launch_entry(workspace, emitted, client)
            tail = entry["args"][entry["args"].index("serve") :]
            try:
                parsed = parser.parse_args(tail)
                ok, why = (parsed.func.__name__ == "cmd_serve", parsed.func.__name__)
            except SystemExit as exc:
                ok, why = (False, f"SystemExit {exc.code}")
            checks.check(
                f"the config written for {client} parses back as a serve command",
                ok,
                f"{why}: {' '.join(tail)}",
            )
        for renderer, name in ((airlock.console_client_configs, "the web console"),):
            configs = renderer(emitted)
            for client, text in configs.items():
                if airlock.MCP_CLIENTS[client]["schema"] == "codex":
                    args_list = tomllib.loads(text)["mcp_servers"]["airlock"]["args"]
                else:
                    data = json.loads(text)
                    key = {"vscode": "servers", "zed": "context_servers"}.get(
                        airlock.MCP_CLIENTS[client]["schema"], "mcpServers"
                    )
                    args_list = data[key]["airlock"]["args"]
                tail = args_list[args_list.index("serve") :]
                try:
                    parsed = parser.parse_args(tail)
                    ok = parsed.func.__name__ == "cmd_serve"
                except SystemExit:
                    ok = False
                checks.check(
                    f"{name}'s config for {client} parses back as a serve command",
                    ok,
                    " ".join(tail),
                )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"HOME": tmp}),
        ):
            home = Path(tmp)
            root = home / "workspace"
            root.mkdir()
            args = _cli_args(root=root)
            checks.check(
                "an absent client has no config path",
                airlock.client_config_path("cursor") is None,
            )
            checks.check(
                "write_client_config on an absent client writes nothing",
                airlock.write_client_config("cursor", root, args).action == "absent",
            )
            checks.check("and it created no directory", not (home / ".cursor").exists())
            checks.check(
                "a dotfile in $HOME alone does not count as installed",
                airlock.client_config_path("claude-code") is None,
                str(airlock.client_config_path("claude-code")),
            )
            (home / ".claude.json").write_text("{}")
            checks.check(
                "but it does once the file itself exists",
                airlock.client_config_path("claude-code") == home / ".claude.json",
            )
            (home / ".claude.json").unlink()
            checks.check(
                "a client config directory does count as installed",
                (home / ".codex").mkdir()
                or airlock.client_config_path("codex") == home / ".codex/config.toml",
            )
            (home / ".codex").rmdir()
            desktop = home / "Library/Application Support/Claude"
            desktop.mkdir(parents=True)
            cfg = desktop / "claude_desktop_config.json"
            cfg.write_text(json.dumps({"preferences": {"theme": "dark"}}, indent=2))
            done = airlock.write_client_config("claude-desktop", root, args)
            after = json.loads(cfg.read_text())
            checks.check(
                "registering adds the mcpServers key when it is missing",
                "airlock" in after.get("mcpServers", {}),
            )
            checks.check(
                "registering leaves unrelated keys untouched",
                after.get("preferences") == {"theme": "dark"},
                str(after.get("preferences")),
            )
            checks.check(
                "registering backs the original up first",
                done.backup is not None and done.backup.exists(),
            )
            checks.check(
                "the backup is the original bytes",
                json.loads(done.backup.read_text())
                == {"preferences": {"theme": "dark"}},
            )
            checks.check(
                "no temporary file is left behind",
                not list(desktop.glob("*.airlock-tmp")),
            )
            entry = after["mcpServers"]["airlock"]
            checks.check(
                "the registered command serves the requested folder",
                str(root) in entry["args"],
                str(entry["args"]),
            )
            checks.check(
                "the registered command turns the console on by default",
                "--ui" in entry["args"],
                str(entry["args"]),
            )
            after["mcpServers"]["other"] = {"command": "x", "args": []}
            cfg.write_text(json.dumps(after, indent=2))
            airlock.write_client_config("claude-desktop", root, args)
            checks.check(
                "re-registering preserves other MCP servers",
                "other" in json.loads(cfg.read_text())["mcpServers"],
            )
            second = airlock.write_client_config("claude-desktop", root, args)
            checks.check(
                "registering twice with the same folder changes nothing",
                second.action == "unchanged",
                second.action,
            )
            airlock.write_client_config("claude-desktop", root, args, remove=True)
            final = json.loads(cfg.read_text())
            checks.check(
                "disconnecting removes only airlock",
                "airlock" not in final["mcpServers"] and "other" in final["mcpServers"],
            )
            checks.check(
                "disconnecting keeps unrelated keys",
                final.get("preferences") == {"theme": "dark"},
            )
            codex_dir = home / ".codex"
            codex_dir.mkdir()
            codex = codex_dir / "config.toml"
            codex.write_text(
                'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "x"\nargs = []\n'
            )
            airlock.write_client_config("codex", root, args)
            parsed = tomllib.loads(codex.read_text())
            checks.check(
                "codex: airlock is added under mcp_servers",
                "airlock" in parsed.get("mcp_servers", {}),
            )
            checks.check(
                "codex: the sibling server survives",
                "other" in parsed.get("mcp_servers", {}),
            )
            checks.check(
                "codex: top-level keys survive", parsed.get("model") == "gpt-5"
            )
            airlock.write_client_config(
                "codex", root, _cli_args(root=root, model="other-model")
            )
            parsed = tomllib.loads(codex.read_text())
            checks.check(
                "codex: re-registering replaces rather than duplicates",
                codex.read_text().count("[mcp_servers.airlock]") == 1,
                str(codex.read_text().count("[mcp_servers.airlock]")),
            )
            checks.check(
                "codex: the replacement took effect",
                "other-model" in parsed["mcp_servers"]["airlock"]["args"],
            )
            airlock.write_client_config("codex", root, args, remove=True)
            parsed = tomllib.loads(codex.read_text())
            checks.check(
                "codex: removal drops airlock and keeps the rest",
                "airlock" not in parsed.get("mcp_servers", {})
                and "other" in parsed.get("mcp_servers", {})
                and (parsed.get("model") == "gpt-5"),
            )
            vs_dir = home / "Library/Application Support/Code/User"
            vs_dir.mkdir(parents=True)
            (vs_dir / "mcp.json").write_text("")
            airlock.write_client_config("vscode", root, args)
            vs = json.loads((vs_dir / "mcp.json").read_text())
            checks.check(
                "vscode uses the servers key with an explicit stdio type",
                vs["servers"]["airlock"]["type"] == "stdio",
            )
            zed_dir = home / ".config/zed"
            zed_dir.mkdir(parents=True)
            airlock.write_client_config("zed", root, args)
            zed = json.loads((zed_dir / "settings.json").read_text())
            checks.check(
                "zed uses context_servers with source custom",
                zed["context_servers"]["airlock"]["source"] == "custom",
            )
            checks.check(
                "zed's config is created when only its directory existed",
                (zed_dir / "settings.json").exists(),
            )
            checks.check(
                "the configured folder is read back out of the client's own file",
                airlock._registered_root("zed") == str(root),
                str(airlock._registered_root("zed")),
            )
            airlock.write_client_config("zed", root, args, remove=True)
            checks.check(
                "and reads as absent once removed",
                airlock._registered_root("zed") is None,
            )
            cfg.write_text("{ this is not json")
            before = cfg.read_text()
            raised = False
            try:
                airlock.write_client_config("claude-desktop", root, args)
            except ValueError:
                raised = True
            checks.check(
                "a malformed config raises rather than being clobbered", raised
            )
            checks.check(
                "and the malformed file is left exactly as it was",
                cfg.read_text() == before,
            )
        checks.check(
            "temporary home ends before optional libraries load",
            Path.home() == original_home,
        )
        _cli_parser_constraints(checks)
        _cli_launch_configs(checks)
        _cli_check_formatting(checks)
        _cli_settings_screen(checks)
        _cli_doctor_version(checks)
        return checks.finish(129)


def _parse_cli(argv: list[str]) -> argparse.Namespace:
    """Parse exactly as main() does, shim and derivations included."""
    args = airlock.build_parser().parse_args(airlock.insert_default_command(list(argv)))
    for name, value in airlock.CLI_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    airlock.resolve_ask_mode(args)
    return args


def _cli_args(**over) -> argparse.Namespace:
    args = argparse.Namespace(**airlock.CLI_DEFAULTS)
    for key, value in over.items():
        setattr(args, key, value)
    airlock.resolve_ask_mode(args)
    return args


def _cli_parser_constraints(checks: Checks) -> None:
    """Reject removed flags and invalid thresholds; preserve valid settings."""
    parser = airlock.build_parser()
    for flag, value in (
        ("--no-presidio", None),
        ("--guard-model", "x"),
        ("--guardian-model", "x"),
        ("--spacy-model", "x"),
    ):
        argv = [flag] if value is None else [flag, value]
        raised = False
        with contextlib.redirect_stderr(sys.stdout):
            try:
                parser.parse_args(argv)
            except SystemExit:
                raised = True
        checks.check(f"removed flag rejected: {flag}", raised)
    args = parser.parse_args(["--linter-threshold", "0.42"])
    checks.check(
        "--linter-threshold parses",
        getattr(args, "linter_threshold", None) == 0.42,
        str(getattr(args, "linter_threshold", None)),
    )
    session = airlock.Session(
        session_id="cli-test",
        objective="x",
        sandbox=airlock.Sandbox(root=REPO),
        worker_model="stub",
        linter_threshold=args.linter_threshold,
    )
    checks.check(
        "--linter-threshold reaches the session",
        session.linter_threshold == 0.42,
        str(session.linter_threshold),
    )
    for bad in ("2", "-0.1", "1.0001", "not-a-number"):
        raised = False
        with contextlib.redirect_stderr(sys.stdout):
            try:
                parser.parse_args(["--linter-threshold", bad])
            except SystemExit:
                raised = True
        checks.check(
            f"--linter-threshold rejects out-of-range/non-numeric: {bad}", raised
        )
    for edge in ("0.0", "1.0"):
        args_edge = parser.parse_args(["--linter-threshold", edge])
        checks.check(
            f"--linter-threshold accepts boundary value: {edge}",
            args_edge.linter_threshold == float(edge),
            str(args_edge.linter_threshold),
        )
    stale = {"guard_model", "use_presidio", "spacy_model", "guardian_model"}
    present = stale & set(airlock.CLI_DEFAULTS)
    checks.check(
        "CLI_DEFAULTS has no stale keys",
        not present,
        ",".join(sorted(present)) or "clean",
    )
    mcp_args = argparse.Namespace(root=REPO, model=airlock.DEFAULT_MODEL)
    with airlock.console.capture() as capture:
        airlock.render_mcp_help(mcp_args)
    printed = capture.get()
    checks.check(
        "printed MCP config contains no removed flag",
        "--guard-model" not in printed,
        "found --guard-model in output" if "--guard-model" in printed else "clean",
    )


def _cli_launch_configs(checks: Checks) -> None:
    original_which = airlock.shutil.which

    def fake_which(stable_path):
        return lambda name: stable_path if name == "airlock" else None

    script_path = Path("/does/not/matter/airlock.py")
    try:
        airlock.shutil.which = fake_which("/opt/homebrew/bin/airlock")
        shell_form, gui_form, reason = airlock._airlock_launch_forms(script_path)
    finally:
        airlock.shutil.which = original_which
    checks.check(
        "shell form is the bare command for a stable install",
        shell_form["command"] == "airlock",
        shell_form["command"],
    )
    checks.check(
        "GUI form is an absolute path for a stable install",
        gui_form["command"] == "/opt/homebrew/bin/airlock",
        gui_form["command"],
    )
    checks.check(
        "stable install is not reported as a fallback",
        "falling back" not in reason,
        reason,
    )
    try:
        airlock.shutil.which = fake_which("/tmp/some-worktree/.venv/bin/airlock")
        eph_shell, eph_gui, eph_reason = airlock._airlock_launch_forms(script_path)
    finally:
        airlock.shutil.which = original_which
    expected_fallback = {"command": "uv", "args": ["run", "--script", str(script_path)]}
    checks.check(
        "ephemeral .venv resolution falls back for the shell form",
        eph_shell == expected_fallback,
        str(eph_shell),
    )
    checks.check(
        "ephemeral .venv resolution falls back for the GUI form",
        eph_gui == expected_fallback,
        str(eph_gui),
    )
    checks.check(
        "ephemeral resolution is reported as ephemeral",
        "ephemeral" in eph_reason,
        eph_reason,
    )
    try:
        airlock.shutil.which = lambda name: None
        none_shell, none_gui, _ = airlock._airlock_launch_forms(script_path)
    finally:
        airlock.shutil.which = original_which
    checks.check(
        "not-on-PATH falls back to uv run --script",
        none_shell["command"] == "uv" and none_gui["command"] == "uv",
        str((none_shell, none_gui)),
    )
    server_args = ["serve", "--root", "/private/workspace", "--model", "qwen3.5:0.8B"]
    codex_text = airlock.render_client_config("codex", shell_form, server_args)
    codex_toml = tomllib.loads(codex_text)
    checks.check(
        "codex emits TOML under mcp_servers",
        "mcp_servers" in codex_toml and "airlock" in codex_toml["mcp_servers"],
        codex_text,
    )
    checks.check(
        "codex's command/args match the shell form",
        codex_toml["mcp_servers"]["airlock"]["command"] == shell_form["command"]
        and codex_toml["mcp_servers"]["airlock"]["args"]
        == shell_form["args"] + server_args,
        str(codex_toml),
    )
    vscode_config = json.loads(
        airlock.render_client_config("vscode", gui_form, server_args)
    )
    checks.check(
        "vscode emits servers with type: stdio",
        vscode_config.get("servers", {}).get("airlock", {}).get("type") == "stdio",
        str(vscode_config),
    )
    zed_config = json.loads(airlock.render_client_config("zed", gui_form, server_args))
    checks.check(
        "zed emits context_servers with source: custom",
        zed_config.get("context_servers", {}).get("airlock", {}).get("source")
        == "custom",
        str(zed_config),
    )
    for client in ("claude-code", "claude-desktop", "cursor", "gemini-cli"):
        form = (
            gui_form if airlock.MCP_CLIENTS[client]["launch"] == "gui" else shell_form
        )
        config = json.loads(airlock.render_client_config(client, form, server_args))
        checks.check(
            f"{client} emits mcpServers",
            "mcpServers" in config and "airlock" in config["mcpServers"],
            str(config),
        )
    parser = airlock.build_parser()
    workspace = Path(__file__).resolve().parent
    try:
        airlock.shutil.which = fake_which("/opt/homebrew/bin/airlock")
        for client in airlock.MCP_CLIENTS:
            args = parser.parse_args(
                ["connect", str(workspace), "--client", client, "--print"]
            )
            for name, value in airlock.CLI_DEFAULTS.items():
                if not hasattr(args, name):
                    setattr(args, name, value)
            airlock.resolve_ask_mode(args)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = airlock.cmd_connect(args)
            output = buf.getvalue()
            checks.check(f"--print --client {client} exits 0", rc == 0, str(rc))
            if airlock.MCP_CLIENTS[client]["schema"] == "codex":
                try:
                    tomllib.loads(output)
                    parses = True
                except tomllib.TOMLDecodeError:
                    parses = False
            else:
                try:
                    json.loads(output)
                    parses = True
                except json.JSONDecodeError:
                    parses = False
            checks.check(
                f"--print --client {client} output parses cleanly", parses, output[:200]
            )
            checks.check(
                f"--print --client {client} output has no ANSI/decoration",
                "\x1b[" not in output and "airlock" != output.strip()[:7].strip("-"),
                output[:200],
            )
    finally:
        airlock.shutil.which = original_which
    args = parser.parse_args(["connect", str(workspace), "--print"])
    for name, value in airlock.CLI_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    airlock.resolve_ask_mode(args)
    args.client = "not-a-real-client"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = airlock.cmd_connect(args)
    checks.check("--print with an unknown client is rejected", rc != 0, str(rc))
    checks.check(
        "and it printed no config", buf.getvalue().strip() == "", buf.getvalue()[:120]
    )


def _cli_check_formatting(checks: Checks) -> None:
    with airlock.console.capture() as capture:
        airlock.check("probe", True, "note [with] brackets")
    printed = capture.get()
    checks.check(
        "check() reports the label and an ok mark",
        "probe" in printed and "ok" in printed,
        printed.strip(),
    )
    checks.check(
        "check() detail text is literal, not parsed as markup",
        "[with]" in printed,
        printed.strip(),
    )


def _cli_settings_screen(checks: Checks) -> None:
    tmp = Path(checks.directory(prefix="banner-config-smoke-"))
    (tmp / "note.txt").write_text("hello\n")
    session = airlock.Session(
        session_id="banner-config-test",
        objective="x",
        sandbox=airlock.Sandbox(root=tmp, allow_writes=False),
        worker_model="stub-worker",
        linter_threshold=0.42,
    )
    with airlock.console.capture() as capture:
        airlock.banner(session)
    printed = capture.get()
    checks.check(
        "banner runs against a Session with no guard_model field",
        "stub-worker" in printed,
        printed[:200],
    )
    checks.check(
        "banner describes the real four-layer guard",
        all(
            (
                name in printed
                for name in ("secrets", "pii-patterns", "pii-detector", "policy-linter")
            )
        ),
        printed[:200],
    )
    args = argparse.Namespace(
        **{**airlock.CLI_DEFAULTS, "root": tmp, "model": "stub-worker"}
    )
    notices: list[str] = []
    original_stdin = sys.stdin
    sys.stdin = io.StringIO("5\n0.55\n\n")
    try:
        airlock._config_loop(session, args, notices)
    finally:
        sys.stdin = original_stdin
    checks.check(
        "config screen's linter-threshold row changes the real Session field",
        session.linter_threshold == 0.55,
        str(session.linter_threshold),
    )
    checks.check(
        "config screen records a notice for the change",
        any(("linter threshold" in n for n in notices)),
        "; ".join(notices) or "no notices",
    )


def _cli_doctor_version(checks: Checks) -> None:
    real_pii = airlock._load_pii_detector
    real_policy = airlock._load_policy_linter
    real_ollama = airlock.ollama_models

    def fail_load(*_a: object, **_k: object) -> None:
        raise airlock.GuardModelUnavailable("stub: no real model load in this test")

    def fail_ollama() -> list[str]:
        raise RuntimeError("stub: no ollama in this test")

    airlock._load_pii_detector = fail_load
    airlock._load_policy_linter = fail_load
    airlock.ollama_models = fail_ollama
    try:
        with airlock.console.capture() as capture:
            code = airlock.cmd_doctor(_server_args(Path(".")))
        printed = capture.get()
        checks.check(
            "cmd_doctor prints the version",
            airlock.__version__ in printed,
            printed[:80],
        )
        checks.check(
            "cmd_doctor still fails closed when its stubs are unavailable",
            code == 1,
            str(code),
        )
    finally:
        airlock._load_pii_detector = real_pii
        airlock._load_policy_linter = real_policy
        airlock.ollama_models = real_ollama


# Console


def test_console() -> Checks:
    """Console; return evidence or raise on failure."""
    with _test_scope() as checks:
        http_server = airlock.ThreadingHTTPServer

        def owned_server(*args, **kwargs):
            server = http_server(*args, **kwargs)
            checks._resources.callback(server.server_close)
            checks._resources.callback(server.shutdown)
            return server

        checks._resources.enter_context(
            patch.object(airlock, "ThreadingHTTPServer", owned_server)
        )
        url, token = airlock.start_console(
            {"workspace": "/tmp/does-not-matter", "files": 0}
        )
        base = url.split("/?")[0]
        origin = base
        status, _ = _console_request(f"{base}/api/state", token=None)
        checks.check("state without a token is refused", status == 401, f"got {status}")
        status, _ = _console_request(f"{base}/api/state", token="not-the-token")
        checks.check(
            "state with a wrong token is refused", status == 401, f"got {status}"
        )
        status, payload = _console_request(f"{base}/api/state", token=token)
        checks.check(
            "state with the right token is served", status == 200, f"got {status}"
        )
        checks.check(
            "state carries the config, events and pending keys the page reads",
            isinstance(payload, dict)
            and {"config", "events", "pending", "sessions"} <= set(payload),
            str(sorted(payload))[:120]
            if isinstance(payload, dict)
            else str(payload)[:80],
        )
        status, _ = _console_request(
            f"{base}/api/state", token=token, origin="https://evil.example"
        )
        checks.check(
            "a cross-origin read is refused even with a valid token",
            status == 401,
            f"got {status}",
        )
        status, _ = _console_request(
            f"{base}/api/approve",
            token=token,
            method="POST",
            body={"id": "whatever", "granted": True},
            origin="https://evil.example",
        )
        checks.check(
            "a cross-origin approve is refused even with a valid token",
            status == 401,
            f"got {status}",
        )
        status, _ = _console_request(
            f"{base}/api/approve",
            token=None,
            method="POST",
            body={"id": "whatever", "granted": True},
        )
        checks.check(
            "approve without a token is refused", status == 401, f"got {status}"
        )
        status, _ = _console_request(f"{base}/api/nope", token=token)
        checks.check(
            "an unknown path is a 404, not a crash", status == 404, f"got {status}"
        )
        status, _ = _console_request(
            f"{base}/api/approve",
            token=token,
            method="POST",
            body={"id": 12, "granted": "yes"},
            origin=origin,
        )
        checks.check(
            "a malformed approve body is rejected", status == 400, f"got {status}"
        )
        status, _ = _console_request(
            f"{base}/api/approve",
            token=token,
            method="POST",
            body={"id": "no-such-call", "granted": True},
            origin=origin,
        )
        checks.check(
            "approving a call that is not waiting is a 409",
            status == 409,
            f"got {status}",
        )
        status, body = _console_request(f"{base}/", token=None)
        checks.check(
            "the page shell is served without a token", status == 200, f"got {status}"
        )
        checks.check(
            "the shell is the console page", isinstance(body, str) and "airlock" in body
        )
        granted: list[bool] = []
        waiter = threading.Thread(
            target=lambda: granted.append(
                airlock.confirm_in_browser("sess-1234", "write a file", True, timeout=5)
            ),
            daemon=True,
        )
        waiter.start()
        checks._resources.callback(waiter.join, 6)
        pending_id = None
        for _ in range(50):
            time.sleep(0.02)
            _, payload = _console_request(
                f"{base}/api/state", token=token, origin=origin
            )
            if isinstance(payload, dict) and payload.get("pending"):
                pending_id = payload["pending"]["id"]
                break
        checks.check(
            "a parked call appears in state as pending", pending_id is not None
        )
        if pending_id:
            status, _ = _console_request(
                f"{base}/api/approve",
                token=token,
                method="POST",
                body={"id": pending_id, "granted": True},
                origin=origin,
            )
            checks.check(
                "approving a waiting call succeeds", status == 200, f"got {status}"
            )
        waiter.join(timeout=6)
        checks.check(
            "the parked call unblocked with the operator's answer",
            granted == [True],
            str(granted),
        )
        denied: list[bool] = []
        waiter = threading.Thread(
            target=lambda: denied.append(
                airlock.confirm_in_browser("sess-1234", "write a file", True, timeout=5)
            ),
            daemon=True,
        )
        waiter.start()
        checks._resources.callback(waiter.join, 6)
        pending_id = None
        for _ in range(50):
            time.sleep(0.02)
            _, payload = _console_request(
                f"{base}/api/state", token=token, origin=origin
            )
            if isinstance(payload, dict) and payload.get("pending"):
                pending_id = payload["pending"]["id"]
                break
        if pending_id:
            _console_request(
                f"{base}/api/approve",
                token=token,
                method="POST",
                body={"id": pending_id, "granted": False},
                origin=origin,
            )
        waiter.join(timeout=6)
        checks.check(
            "denying a waiting call returns False", denied == [False], str(denied)
        )
        start = time.monotonic()
        timed_out = airlock.confirm_in_browser(
            "sess-1234", "write a file", True, timeout=0.3
        )
        elapsed = time.monotonic() - start
        checks.check(
            "an unanswered gate returns False, never True",
            timed_out is False,
            str(timed_out),
        )
        checks.check(
            "it returns by waiting, not immediately", elapsed >= 0.25, f"{elapsed:.2f}s"
        )
        checks.check(
            "an answered call is removed from pending",
            airlock.console_state()["pending"] is None,
        )
        on_disk = (REPO / "ui" / "index.html").read_text()
        checks.check(
            "CONSOLE_HTML matches ui/index.html exactly",
            airlock.CONSOLE_HTML == on_disk,
            "run tools/sync_console.py",
        )
        checks.check(
            "the console page loads nothing from the network",
            "googleapis" not in airlock.CONSOLE_HTML
            and "gstatic" not in airlock.CONSOLE_HTML
            and ("//cdn" not in airlock.CONSOLE_HTML),
        )
        return checks.finish(21)


def _console_request(
    url: str,
    token: str | None,
    method: str = "GET",
    body: dict | None = None,
    origin: str | None = None,
) -> tuple[int, dict | str]:
    """Return (status, parsed body). An HTTP error status is a result, not an
    exception: every rejection path here is something the test asserts on."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token is not None:
        req.add_header("X-Airlock-Token", token)
    if origin is not None:
        req.add_header("Origin", origin)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw, status = (exc.read().decode(), exc.code)
    try:
        return (status, json.loads(raw))
    except json.JSONDecodeError:
        return (status, raw)


# Round guard


def test_round_guard() -> Checks:
    """Round guard; return evidence or raise on failure."""
    with _test_scope() as checks:
        _round_labelled_ein(checks)
        _round_reassembly(checks)
        _round_jobs(checks)
        _round_large_workspace(checks)
        _round_unreadable_file(checks)
        _round_length_bound(checks)
        _round_secret_value(checks)
        _round_numeric_padding(checks)
        _round_order_independence(checks)
        _round_alphanumeric_padding(checks)
        return checks.finish(58)


def _ein_rules(text: str) -> set[str]:
    findings = airlock.scan_pii_patterns(text) + airlock.scan_secrets(text)
    return {f["rule"] for f in findings if "ein" in f["rule"]}


def _round_labelled_ein(checks: Checks) -> None:
    rules = _ein_rules("EIN 31 7729104")
    checks.check(
        "labelled space form matches",
        bool(rules),
        ",".join(sorted(rules)) or "no match",
    )
    rules = _ein_rules("Employer identification number: 31 7729104")
    checks.check(
        "labelled space form, longer label, matches",
        bool(rules),
        ",".join(sorted(rules)) or "no match",
    )
    rules = _ein_rules("EIN 31-7729104")
    checks.check(
        "intact hyphen form still matches",
        bool(rules),
        ",".join(sorted(rules)) or "no match",
    )
    rules = _ein_rules("we shipped 12 3456789 units")
    checks.check(
        "unlabelled pair does not match",
        not rules,
        ",".join(sorted(rules)) or "no match",
    )
    rules = _ein_rules("EIN" + " " * 40 + "31 7729104")
    checks.check(
        "label too far from the digits does not match",
        not rules,
        ",".join(sorted(rules)) or "no match",
    )


def _round_reassembly(checks: Checks) -> None:
    ssn_sources = {airlock.normalise_identifier("912-84-7731")}
    checks.check(
        "adjacent fragments caught",
        airlock.reassembles_identifier(["912", "84", "7731"], ssn_sources),
    )
    checks.check(
        "single job released it, not this check's business",
        not airlock.reassembles_identifier(["912-84-7731"], ssn_sources),
    )
    checks.check(
        "one job holds it among others",
        not airlock.reassembles_identifier(
            ["notes", "912-84-7731", "more"], ssn_sources
        ),
    )
    checks.check(
        "value absent from workspace",
        not airlock.reassembles_identifier(["555", "12", "3456"], ssn_sources),
    )
    checks.check("empty round", not airlock.reassembles_identifier([], ssn_sources))
    checks.check(
        "short identifiers ignored",
        not airlock.reassembles_identifier(["12", "34"], {"1234"}),
    )
    checks.check(
        "normalisation is separator-blind",
        airlock.reassembles_identifier(["912 84", "7731"], ssn_sources),
    )
    checks.check(
        "scattered fragments caught",
        airlock.reassembles_identifier(
            ["912", "notes", "84", "more", "7731"], ssn_sources
        ),
    )
    checks.check(
        "fragments padded with numeric job answers still caught",
        airlock.reassembles_identifier(
            ["912", "500", "84", "700", "7731"], ssn_sources
        ),
    )
    tmp = Path(checks.directory(prefix="airlock-round-guard-test-"))
    (tmp / "notes.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    sandbox = airlock.Sandbox(root=tmp, allow_writes=False)
    sources = airlock.source_identifiers(sandbox)
    checks.check(
        "source_identifiers finds an SSN in a file",
        "912847731" in sources,
        ",".join(sorted(sources)) or "empty",
    )
    checks.check(
        "source_identifiers returns normalised, never masked",
        not any(("*" in s for s in sources)),
        ",".join(sorted(sources)),
    )
    legitimate_round = [f"5{d}5" for d in sorted(ssn_sources)[0]] + [
        "203",
        "410",
        "999",
    ]
    checks.check(
        "legitimate round of twelve numeric answers is not blocked",
        not airlock.reassembles_identifier(legitimate_round, ssn_sources),
    )
    oversized_round = ["x"] * (airlock.MAX_JOBS_PER_ROUND + 1)
    checks.check(
        "more than MAX_JOBS_PER_ROUND values blocks even with no sources",
        airlock.reassembles_identifier(oversized_round, set()),
    )


def _round_jobs(checks: Checks) -> None:
    tmp = Path(checks.directory(prefix="airlock-round-guard-test3-"))
    (tmp / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    session = _session_over(tmp)
    jobs = [{"document": 0, "extract": f"question {i}"} for i in range(5)]
    answers = [
        "912",
        "some notes about the weather",
        "84",
        "another line of text",
        "7731",
    ]
    result = _run_jobs_with_answers(session, jobs, answers)
    payload = json.dumps(result)
    checks.check(
        "scattered SSN fragments: round is blocked",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    checks.check(
        "scattered SSN fragments: no fragment reaches the serialised payload",
        not any((fragment in payload for fragment in ("912", "84", "7731"))),
    )
    tmp2 = Path(checks.directory(prefix="airlock-round-guard-test3-"))
    (tmp2 / "doc0.txt").write_text("Just a benign note about scheduling.\n")
    secret_path = tmp2 / "doc1_secret.txt"
    secret_path.write_text("irrelevant content\n")
    os.chmod(secret_path, 0)
    try:
        session = _session_over(tmp2)
        jobs = [{"document": 0, "extract": "what does the note say"}]
        answers = ["A benign one-line answer."]
        result = _run_jobs_with_answers(session, jobs, answers)
        checks.check(
            "workspace unreadable during the check: round is blocked, not approved",
            result.get("status") == "blocked",
            str(result.get("status")),
        )
    finally:
        os.chmod(secret_path, 420)
    tmp5 = Path(checks.directory(prefix="airlock-round-guard-test3-"))
    (tmp5 / "record.txt").write_text("Notes\nssn: 912-84-7731\nFiled Monday.\n")
    session = _session_over(tmp5, allow_writes=True)
    jobs = [
        {"document": 0, "extract": "first three digits of the ssn field"},
        {"document": 0, "extract": "an unrelated note"},
        {"value": "redacted", "into": 0, "field": "ssn"},
        {"document": 0, "extract": "next two digits of the ssn field"},
        {"document": 0, "extract": "last four digits of the ssn field"},
    ]
    answers = ["912", "some unrelated note", "84", "7731"]
    result = _run_jobs_with_answers(session, jobs, answers)
    checks.check(
        "mid-round write cannot erase the evidence: round is still blocked",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    tmp3 = Path(checks.directory(prefix="airlock-round-guard-test3-"))
    (tmp3 / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    session = _session_over(tmp3)
    jobs = [{"document": 0, "extract": f"question {i}"} for i in range(5)]
    answers = ["912", "84", "7731", "some notes", "another line"]
    result = _run_jobs_with_answers(session, jobs, answers)
    checks.check(
        "adjacent SSN fragments: round is blocked",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    tmp4 = Path(checks.directory(prefix="airlock-round-guard-test3-"))
    (tmp4 / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    session = _session_over(tmp4)
    jobs = [{"document": 0, "extract": f"question {i}"} for i in range(12)]
    answers = [
        "forecast",
        "quarterly",
        "template",
        "summary",
        "agenda",
        "payroll",
        "spreadsheet",
        "vendor",
        "documentation",
        "kitchen",
        "invoice",
        "headcount",
    ]
    result = _run_jobs_with_answers(session, jobs, answers)
    checks.check(
        "twelve benign jobs over an untouched SSN: round is ok",
        result.get("status") == "ok",
        str(result.get("status")),
    )
    checks.check(
        "twelve benign jobs over an untouched SSN: all twelve results present",
        len(result.get("results", [])) == 12,
        str(len(result.get("results", []))),
    )


def _round_large_workspace(checks: Checks) -> None:
    """A workspace over MAX_LISTING_ENTRIES must not block every
    round. list_dir appends a literal "... truncated at 200" sentinel once a
    listing hits the cap; that string is not a file, and source_identifiers
    used to hand it straight to read_text, turning any large workspace's
    first round into an automatic block.
    """
    tmp = Path(checks.directory(prefix="airlock-round-guard-test-c1-"))
    for i in range(airlock.MAX_LISTING_ENTRIES + 5):
        (tmp / f"doc{i}.txt").write_text(f"benign note number {i}\n")
    sandbox = airlock.Sandbox(root=tmp, allow_writes=False)
    try:
        airlock.source_identifiers(sandbox)
        raised = None
    except Exception as exc:
        raised = exc
    checks.check(
        "source_identifiers returns normally over a >200-entry workspace",
        raised is None,
        f"{type(raised).__name__}: {raised}" if raised else "",
    )
    session = _session_over(tmp)
    jobs = [{"document": 0, "extract": "what does the note say"}]
    result = _run_jobs_with_answers(session, jobs, ["a benign one-line answer"])
    results = result.get("results", [])
    first_status = results[0].get("status") if results else None
    checks.check(
        "a round over the same large workspace succeeds, not just avoids block",
        result.get("status") == "ok" and first_status == "ok",
        f"round={result.get('status')} job0={first_status}",
    )


def _round_unreadable_file(checks: Checks) -> None:
    tmp = Path(checks.directory(prefix="airlock-round-guard-test-c2-"))
    (tmp / "doc0.txt").write_text("a benign note\n")
    distinctive = "unreadable_" + _fake_credential("", 12) + ".txt"
    secret_path = tmp / distinctive
    secret_path.write_text("irrelevant content\n")
    os.chmod(secret_path, 0)
    try:
        session = _session_over(tmp)
        jobs = [{"document": 0, "extract": "what does the note say"}]
        result = _run_jobs_with_answers(session, jobs, ["a benign one-line answer"])
        payload = json.dumps(result)
        checks.check(
            "unreadable file: round is blocked, not approved",
            result.get("status") == "blocked",
            str(result.get("status")),
        )
        checks.check(
            "unreadable file: serialised payload names no filename",
            distinctive not in payload,
        )
        checks.check(
            "unreadable file: serialised payload carries no absolute path",
            str(tmp) not in payload,
        )
    finally:
        os.chmod(secret_path, 420)


def _round_length_bound(checks: Checks) -> None:
    oversized = ["x" * (airlock.MAX_REASSEMBLY_LENGTH + 1)]
    checks.check(
        "total length over the bound blocks even with no sources",
        airlock.reassembles_identifier(oversized, set()),
    )
    legitimate_round = [f"line-shaped answer {i}" for i in range(12)]
    checks.check(
        "a realistic round of twelve short answers stays under the bound",
        sum((len(airlock.normalise_identifier(v)) for v in legitimate_round))
        <= airlock.MAX_REASSEMBLY_LENGTH,
    )
    checks.check(
        "that realistic round is not blocked by the length bound",
        not airlock.reassembles_identifier(legitimate_round, set()),
    )


def _round_secret_value(checks: Checks) -> None:
    """generic_secret_assignment must store the secret VALUE alone,
    not "label+value", so a caller splitting only the value across jobs is
    still caught. Credential generated at runtime, never a
    literal that looks like a live key; see CLAUDE.md.
    """
    value = _fake_credential("", 16)
    tmp = Path(checks.directory(prefix="airlock-round-guard-test-m4-"))
    (tmp / "creds.txt").write_text(f"password: {value}\n")
    sandbox = airlock.Sandbox(root=tmp, allow_writes=False)
    sources = airlock.source_identifiers(sandbox)
    normalised_value = airlock.normalise_identifier(value)
    checks.check(
        "the value alone is a source identifier",
        normalised_value in sources,
        ",".join(sorted(sources)) or "empty",
    )
    half = len(value) // 2
    fragments = [value[:half], value[half:]]
    checks.check(
        "a round splitting the value across jobs is caught",
        airlock.reassembles_identifier(fragments, sources),
    )


def _round_numeric_padding(checks: Checks) -> None:
    """Padding cannot hide a numeric fragment from the digits projection.

    A substring-only check is defeated by padding
    on any side of a fragment, because the padding sits between fragments in
    the concatenation and breaks the identifier's contiguous digit run.
    """
    sources = {airlock.normalise_identifier("912-84-7731")}
    checks.check(
        "suffix-padded fragments among benign jobs: blocked",
        airlock.reassembles_identifier(
            [
                "912 ok",
                "weather report filler",
                "84 ok",
                "another filler note",
                "7731 ok",
            ],
            sources,
        ),
    )
    checks.check(
        "prefix-padded fragments: blocked",
        airlock.reassembles_identifier(
            [
                "value 912",
                "weather report filler",
                "value 84",
                "another filler note",
                "value 7731",
            ],
            sources,
        ),
    )
    checks.check(
        "fragments padded on both sides: blocked",
        airlock.reassembles_identifier(
            [
                "the 912 confirmed",
                "weather report filler",
                "the 84 confirmed",
                "another filler note",
                "the 7731 confirmed",
            ],
            sources,
        ),
    )
    checks.check(
        "fragments wrapped in prose: blocked",
        airlock.reassembles_identifier(
            [
                "The figure recorded here is 912",
                "weather report filler",
                "The next figure noted is 84",
                "another filler note",
                "The final figure recorded is 7731",
            ],
            sources,
        ),
    )
    legitimate_round = [f"5{d}5" for d in sorted(sources)[0]] + ["203", "410", "999"]
    checks.check(
        "legitimate numeric round of twelve is not blocked",
        not airlock.reassembles_identifier(legitimate_round, sources),
    )
    sixteen_digit_source = {"9" * 16}
    twelve_16digit_values = [f"{i:016d}" for i in range(12)]
    checks.check(
        "twelve 16-digit values, none reconstructing a source: not blocked",
        not airlock.reassembles_identifier(twelve_16digit_values, sixteen_digit_source),
    )
    api_key = "k" + _fake_credential("", 19)
    key_source = {airlock.normalise_identifier(api_key)}
    third = len(api_key) // 3
    checks.check(
        "a generated API key split across jobs: still blocked via the raw pass",
        airlock.reassembles_identifier(
            [
                api_key[:third],
                "unrelated filler note",
                api_key[third : 2 * third],
                "another filler note",
                api_key[2 * third :],
            ],
            key_source,
        ),
    )
    letters_only_filler = "".join(
        (secrets.choice(string.ascii_letters) for _ in range(13))
    )
    embedded_digit_key = "k482910" + letters_only_filler
    alnum_only_source = {airlock.normalise_identifier(embedded_digit_key)}
    checks.check(
        "round with only alphanumeric sources: projection does not run, not blocked",
        not airlock.reassembles_identifier(
            ["482", "unrelated filler note", "910"], alnum_only_source
        ),
    )
    digit_dense_round = [
        "invoice amount is 48",
        "filed under box 29",
        "reference 10 pending",
    ]
    six_digit_sources = {"482910", "119955", "203040", "556677", "334455"}
    checks.check(
        "digit-dense round against many six-digit sources: blocked",
        airlock.reassembles_identifier(digit_dense_round, six_digit_sources),
    )
    eight_digit_sources = {s + "00" for s in six_digit_sources}
    checks.check(
        "same digit-dense round against eight-digit sources: not blocked",
        not airlock.reassembles_identifier(digit_dense_round, eight_digit_sources),
    )


def _round_order_independence(checks: Checks) -> None:
    ssn_sources = {airlock.normalise_identifier("912-84-7731")}
    checks.check(
        "in order: blocked (unchanged)",
        airlock.reassembles_identifier(["912", "84", "7731"], ssn_sources),
    )
    checks.check(
        "reversed: blocked",
        airlock.reassembles_identifier(["7731", "84", "912"], ssn_sources),
    )
    checks.check(
        "shuffled: blocked",
        airlock.reassembles_identifier(["84", "7731", "912"], ssn_sources),
    )
    checks.check(
        "scattered, in order: blocked",
        airlock.reassembles_identifier(
            ["912", "notes", "84", "more", "7731"], ssn_sources
        ),
    )
    checks.check(
        "scattered, reversed: blocked",
        airlock.reassembles_identifier(
            ["7731", "notes", "84", "more", "912"], ssn_sources
        ),
    )
    legitimate_round = [f"5{d}5" for d in sorted(ssn_sources)[0]] + [
        "203",
        "410",
        "999",
    ]
    random.Random(0).shuffle(legitimate_round)
    checks.check(
        "legitimate shuffled numeric round is not blocked",
        not airlock.reassembles_identifier(legitimate_round, ssn_sources),
    )
    ssn = sorted(ssn_sources)[0]
    over_bound_pieces = list(reversed([ssn[i] for i in range(len(ssn))]))
    checks.check(
        "reversed split into more pieces than the bound: not caught by this pass",
        not airlock.reassembles_identifier(over_bound_pieces, ssn_sources),
        f"{len(over_bound_pieces)} pieces > REASSEMBLY_PIECE_BOUND={airlock.REASSEMBLY_PIECE_BOUND}",
    )


def _round_alphanumeric_padding(checks: Checks) -> None:
    api_key = "k" + _fake_credential("", 19)
    key_source = {airlock.normalise_identifier(api_key)}
    third = len(api_key) // 3
    p1, p2, p3 = (api_key[:third], api_key[third : 2 * third], api_key[2 * third :])
    checks.check(
        "bare split, three ways: blocked (already true via the raw pass)",
        airlock.reassembles_identifier([p1, p2, p3], key_source),
    )
    checks.check(
        "suffix padded on every fragment: blocked",
        airlock.reassembles_identifier(
            [f"{p1} zzqx", f"{p2} wwrt", f"{p3} vvbn"], key_source
        ),
    )
    checks.check(
        "prose wrapped, every fragment: blocked",
        airlock.reassembles_identifier(
            [
                f"The first part of the code is {p1} today",
                f"The next part of the code is {p2} today",
                f"The final part of the code is {p3} today",
            ],
            key_source,
        ),
    )
    checks.check(
        "prefix and suffix padded, scattered among filler: blocked",
        airlock.reassembles_identifier(
            [
                f"pre {p1} post",
                "weather report filler",
                f"pre {p2} post",
                "another filler note",
                f"pre {p3} post",
            ],
            key_source,
        ),
    )
    prose_round = [
        "forecast quarterly template summary agenda payroll",
        "contract vendor documentation kitchen invoice headcount",
    ]
    checks.check(
        "legitimate prose round is not blocked",
        not airlock.reassembles_identifier(prose_round, key_source),
    )
    all_digit_source = {"482910337"}
    checks.check(
        "all-digit source: letter-padded fragments still caught via digits projection",
        airlock.reassembles_identifier(
            ["k482 filler", "unrelated filler note", "910337 more"], all_digit_source
        ),
    )


# Cross round


def test_cross_round() -> Checks:
    """Cross round; return evidence or raise on failure."""
    with _test_scope() as checks:
        _cross_natural_order(checks)
        _cross_reverse_order(checks)
        _cross_middle_first_order(checks)
        _cross_many_pieces_no_block(checks)
        _cross_long_benign_session(checks)
        _cross_generator_spread(checks)
        _cross_interleaved_benign_rounds(checks)
        _cross_unrelated_benign_values(checks)
        _cross_bounded_work(checks)
        _cross_digits_projection(checks)
        _cross_whole_value_first_round_not_combined(checks)
        _cross_wiring_natural_order(checks)
        _cross_wiring_reverse_order(checks)
        _cross_wiring_interleaved_benign_rounds(checks)
        _cross_wiring_unrelated_benign_session(checks)
        _cross_wiring_whole_identifier_one_round(checks)
        _cross_wiring_fail_closed(checks)
        _cross_wiring_blocked_round_does_not_poison_state(checks)
        return checks.finish(49)


def _cross_ssn_workspace(checks: Checks) -> Path:
    tmp = Path(checks.directory(prefix="airlock-cross-round-test-"))
    (tmp / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    return tmp


def _cross_one_job(i: int) -> list[dict]:
    return [{"document": 0, "extract": f"question {i}"}]


def _cross_natural_order(checks: Checks) -> None:
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    r1 = airlock.advance_reassembly_state(state, ["912"], sources)
    r2 = airlock.advance_reassembly_state(state, ["84"], sources)
    r3 = airlock.advance_reassembly_state(state, ["7731"], sources)
    checks.check("first round alone does not complete it", not r1)
    checks.check("second round still does not complete it", not r2)
    checks.check("third round completes the reconstruction", r3)


def _cross_reverse_order(checks: Checks) -> None:
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    r1 = airlock.advance_reassembly_state(state, ["7731"], sources)
    r2 = airlock.advance_reassembly_state(state, ["84"], sources)
    r3 = airlock.advance_reassembly_state(state, ["912"], sources)
    checks.check("first round (last fragment) alone does not complete it", not r1)
    checks.check("second round still does not complete it", not r2)
    checks.check("third round completes it: order independence, per the docstring", r3)


def _cross_middle_first_order(checks: Checks) -> None:
    """Third distinct ordering (fix round 1: "in all three orderings"),
    completing natural (unit_natural_order_case) and reverse
    (unit_reverse_order_case) above: the middle fragment first, then the
    last, then the first.
    """
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    r1 = airlock.advance_reassembly_state(state, ["84"], sources)
    r2 = airlock.advance_reassembly_state(state, ["7731"], sources)
    r3 = airlock.advance_reassembly_state(state, ["912"], sources)
    checks.check("first round (middle fragment) alone does not complete it", not r1)
    checks.check("second round still does not complete it", not r2)
    checks.check("third round completes it: a third distinct ordering", r3)


def _cross_many_pieces_no_block(checks: Checks) -> None:
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    source = next(iter(sources))
    blocked = False
    for ch in source:
        if airlock.advance_reassembly_state(state, [ch], sources):
            blocked = True
    checks.check(
        "nine single-character pieces do not block: minimum pieces (9) exceeds the bound (5)",
        not blocked,
    )


BENIGN_WORDS = [
    "forecast",
    "quarterly",
    "template",
    "summary",
    "agenda",
    "payroll",
    "contract",
    "vendor",
    "documentation",
    "kitchen",
    "invoice",
    "headcount",
]


def benign_value_freeform(rng: random.Random) -> str:
    if rng.random() < 0.4:
        length = rng.choices(
            [1, 2, 3, 4, 5, 6, 7, 8], weights=[3, 4, 4, 3, 2, 2, 1, 1]
        )[0]
        lo = 0 if length == 1 else 10 ** (length - 1)
        hi = 10**length - 1
        return str(rng.randint(lo, hi))
    return rng.choice(BENIGN_WORDS)


def benign_value_shaped(rng: random.Random) -> str:
    kind = rng.choices(["wage", "count", "year", "amount"], weights=[4, 1, 4, 4])[0]
    if kind == "wage":
        return str(rng.randint(20000, 250000))
    if kind == "count":
        return str(rng.randint(0, 99))
    if kind == "year":
        return str(rng.randint(1990, 2030))
    dollars = rng.randint(100, 99999)
    cents = rng.randint(0, 99)
    return f"{dollars}.{cents:02d}"


def _cross_long_benign_session(checks: Checks) -> None:
    rng = random.Random(0)
    source_len = rng.choice([6, 7, 8, 9])
    source = "".join((str(rng.randint(0, 9)) for _ in range(source_len)))
    sources = {source}
    values = [benign_value_shaped(rng) for _ in range(240)]
    state: dict[str, set[int]] = {}
    blocked_round = None
    for r in range(20):
        chunk = values[r * 12 : (r + 1) * 12]
        if airlock.advance_reassembly_state(state, chunk, sources):
            blocked_round = r + 1
            break
    checks.check(
        "240 released values across 20 rounds: no false block",
        blocked_round is None,
        f"blocked at round {blocked_round}" if blocked_round else "clean",
    )


def _cross_generator_spread(checks: Checks) -> None:

    def sessions_blocked(generator, seed_base: int, trials: int) -> int:
        hits = 0
        for t in range(trials):
            rng = random.Random(seed_base + t)
            source_len = rng.choice([6, 7, 8, 9])
            source = "".join((str(rng.randint(0, 9)) for _ in range(source_len)))
            sources = {source}
            state: dict[str, set[int]] = {}
            for _ in range(240):
                v = generator(rng)
                if airlock.advance_reassembly_state(state, [v], sources):
                    hits += 1
                    break
        return hits

    trials = 60
    freeform_hits = sessions_blocked(benign_value_freeform, 30000, trials)
    shaped_hits = sessions_blocked(benign_value_shaped, 40000, trials)
    checks.check(
        f"freeform false-blocks materially more often than shaped at 240 released values ({freeform_hits}/{trials} vs {shaped_hits}/{trials})",
        freeform_hits > shaped_hits,
        f"freeform={freeform_hits}/{trials} shaped={shaped_hits}/{trials}",
    )


def _cross_interleaved_benign_rounds(checks: Checks) -> None:
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    r1 = airlock.advance_reassembly_state(state, ["912"], sources)
    r2 = airlock.advance_reassembly_state(state, ["forecast", "quarterly"], sources)
    r3 = airlock.advance_reassembly_state(state, ["84"], sources)
    r4 = airlock.advance_reassembly_state(state, ["invoice", "headcount"], sources)
    r5 = airlock.advance_reassembly_state(state, ["7731"], sources)
    checks.check(
        "no round before the final fragment completes it",
        not any([r1, r2, r3, r4]),
        str([r1, r2, r3, r4]),
    )
    checks.check("the round with the final fragment completes it", r5)


def _cross_unrelated_benign_values(checks: Checks) -> None:
    """Positive control (CLAUDE.md: an absence claim needs one). Many rounds
    of ordinary words over a workspace containing an untouched SSN must
    never complete a reconstruction, or this check is blocking everything
    rather than reassembly specifically.
    """
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    rounds = [
        ["forecast", "quarterly"],
        ["template", "summary"],
        ["agenda", "payroll"],
        ["contract", "vendor"],
        ["documentation", "kitchen"],
        ["invoice", "headcount"],
    ]
    results = [airlock.advance_reassembly_state(state, r, sources) for r in rounds]
    checks.check(
        "none of the unrelated rounds ever complete a reconstruction",
        not any(results),
        str(results),
    )


def _cross_bounded_work(checks: Checks) -> None:
    original = airlock._fold_source_edges
    calls = {"n": 0}

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    airlock._fold_source_edges = counting
    try:
        state: dict[str, set[int]] = {}
        sources = {airlock.normalise_identifier(SSN)}
        n = 60
        for i in range(n):
            airlock.advance_reassembly_state(state, [f"filler-{i}-noise"], sources)
    finally:
        airlock._fold_source_edges = original
    checks.check(
        "folding primitive is called a fixed number of times per round (linear, not exponential)",
        calls["n"] == 2 * n,
        f"{calls['n']} calls for {n} rounds",
    )
    source = next(iter(sources))
    state2: dict[str, set[int]] = {}
    for ch in source * 20:
        airlock.advance_reassembly_state(state2, [ch], sources)
    stored = state2.get(source, set())
    checks.check(
        "edge set for one source stays bounded by its own geometry, not round count",
        len(stored) == len(source),
        f"{len(stored)} edges stored for a {len(source)}-char source after 180 rounds",
    )


def _cross_digits_projection(checks: Checks) -> None:
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    r1 = airlock.advance_reassembly_state(state, ["value is 912 confirmed"], sources)
    r2 = airlock.advance_reassembly_state(state, ["the 84 recorded"], sources)
    r3 = airlock.advance_reassembly_state(state, ["figure 7731 noted"], sources)
    checks.check(
        "padded fragments across rounds: not complete after two", not r1 and (not r2)
    )
    checks.check(
        "padded fragments across rounds: digits projection catches the third", r3
    )


def _cross_whole_value_first_round_not_combined(checks: Checks) -> None:
    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    result = airlock.advance_reassembly_state(state, [SSN], sources)
    checks.check(
        "a lone value equal to the source on round 1 does not read as reassembly",
        not result,
        str(result),
    )


def _cross_wiring_natural_order(checks: Checks) -> None:
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    r1 = _run_jobs_with_answers(session, _cross_one_job(1), ["912"])
    r2 = _run_jobs_with_answers(session, _cross_one_job(2), ["84"])
    r3 = _run_jobs_with_answers(session, _cross_one_job(3), ["7731"])
    checks.check("round 1 of 3 is ok", r1.get("status") == "ok", str(r1.get("status")))
    checks.check("round 2 of 3 is ok", r2.get("status") == "ok", str(r2.get("status")))
    checks.check(
        "round 3 of 3 blocks: completes a reassembly begun in earlier rounds",
        r3.get("status") == "blocked",
        str(r3.get("status")),
    )
    for label, result in (("round 1", r1), ("round 2", r2), ("round 3", r3)):
        payload = json.dumps(result)
        checks.check(
            f"{label}: serialised payload never carries the raw session reassembly state",
            "reassembly_state" not in payload,
            payload[:200],
        )
    payload3 = json.dumps(r3)
    checks.check(
        "round 3 (blocked): payload carries no SSN fragment or the full value",
        not any(
            (fragment in payload3 for fragment in ("912", "84", "7731", "912-84-7731"))
        ),
        payload3[:200],
    )
    checks.check(
        "the blocking round's message names no identifier, document, or job",
        "record.txt" not in payload3 and "912-84-7731" not in payload3,
        payload3[:200],
    )


def _cross_wiring_reverse_order(checks: Checks) -> None:
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    r1 = _run_jobs_with_answers(session, _cross_one_job(1), ["7731"])
    r2 = _run_jobs_with_answers(session, _cross_one_job(2), ["84"])
    r3 = _run_jobs_with_answers(session, _cross_one_job(3), ["912"])
    checks.check(
        "round 1 of 3 (reverse) is ok", r1.get("status") == "ok", str(r1.get("status"))
    )
    checks.check(
        "round 2 of 3 (reverse) is ok", r2.get("status") == "ok", str(r2.get("status"))
    )
    checks.check(
        "round 3 of 3 (reverse) blocks: order independence",
        r3.get("status") == "blocked",
        str(r3.get("status")),
    )
    for label, result in (("round 1", r1), ("round 2", r2), ("round 3", r3)):
        payload = json.dumps(result)
        checks.check(
            f"reverse order {label}: serialised payload never carries the raw session reassembly state",
            "reassembly_state" not in payload,
            payload[:200],
        )
    payload3 = json.dumps(r3)
    checks.check(
        "reverse order round 3 (blocked): payload carries no SSN fragment or the full value",
        not any(
            (fragment in payload3 for fragment in ("912", "84", "7731", "912-84-7731"))
        ),
        payload3[:200],
    )


def _cross_wiring_interleaved_benign_rounds(checks: Checks) -> None:
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    r1 = _run_jobs_with_answers(session, _cross_one_job(1), ["912"])
    r2 = _run_jobs_with_answers(session, _cross_one_job(2), ["forecast"])
    r3 = _run_jobs_with_answers(session, _cross_one_job(3), ["84"])
    r4 = _run_jobs_with_answers(session, _cross_one_job(4), ["quarterly"])
    r5 = _run_jobs_with_answers(session, _cross_one_job(5), ["7731"])
    checks.check(
        "no round before the final fragment blocks",
        all((r.get("status") == "ok" for r in (r1, r2, r3, r4))),
        str([r.get("status") for r in (r1, r2, r3, r4)]),
    )
    checks.check(
        "the round with the final fragment blocks",
        r5.get("status") == "blocked",
        str(r5.get("status")),
    )


def _cross_wiring_unrelated_benign_session(checks: Checks) -> None:
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    words = [
        "forecast",
        "quarterly",
        "template",
        "summary",
        "agenda",
        "payroll",
        "contract",
        "vendor",
        "documentation",
        "kitchen",
        "invoice",
        "headcount",
    ]
    results = [
        _run_jobs_with_answers(session, _cross_one_job(i), [w])
        for i, w in enumerate(words)
    ]
    checks.check(
        "none of the twelve unrelated rounds block",
        all((r.get("status") == "ok" for r in results)),
        str([r.get("status") for r in results]),
    )


def _cross_wiring_whole_identifier_one_round(checks: Checks) -> None:
    verdict = airlock.evaluate(SSN)
    checks.check(
        "evaluate() itself rejects the intact SSN (establishes the premise)",
        not verdict.approved,
        f"{verdict.decision} via {verdict.layers_run}",
    )
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    result = _run_jobs_with_answers(session, _cross_one_job(1), [SSN])
    results = result.get("results") or []
    job = results[0] if results else {}
    checks.check(
        "the round is not blocked outright",
        result.get("status") == "ok",
        str(result.get("status")),
    )
    checks.check(
        "the one job in it is withheld, not released",
        job.get("status") == "withheld",
        str(job),
    )
    checks.check("the withheld job carries no value", "value" not in job, str(job))


def _cross_wiring_fail_closed(checks: Checks) -> None:
    """CLAUDE.md invariant: the guard fails closed. If
    advance_reassembly_state itself raises, run_jobs must block, not approve
    or crash the caller with an uncaught exception.
    """
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    original = airlock.advance_reassembly_state
    airlock.advance_reassembly_state = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom")
    )
    try:
        result = _run_jobs_with_answers(
            session, _cross_one_job(1), ["a benign one-line answer"]
        )
    finally:
        airlock.advance_reassembly_state = original
    checks.check(
        "round is blocked when cross-round tracking errors",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    checks.check(
        "the failure carries no exception detail outbound",
        "boom" not in json.dumps(result),
        json.dumps(result)[:200],
    )


def _cross_wiring_blocked_round_does_not_poison_state(checks: Checks) -> None:
    tmp = _cross_ssn_workspace(checks)
    session = _session_over(tmp)
    r1 = _run_jobs_with_answers(session, _cross_one_job(1), ["912"])
    r2 = _run_jobs_with_answers(session, _cross_one_job(2), ["84"])
    r3 = _run_jobs_with_answers(session, _cross_one_job(3), ["7731"])
    r4 = _run_jobs_with_answers(session, _cross_one_job(4), ["forecast"])
    r5 = _run_jobs_with_answers(session, _cross_one_job(5), ["7731"])
    checks.check(
        "round 1 releases its fragment", r1.get("status") == "ok", str(r1.get("status"))
    )
    checks.check(
        "round 2 releases its fragment", r2.get("status") == "ok", str(r2.get("status"))
    )
    checks.check(
        "round 3 blocks: completes the reassembly",
        r3.get("status") == "blocked",
        str(r3.get("status")),
    )
    checks.check(
        "round 4, an unrelated benign value, is not blocked by round 3's never-released fragment",
        r4.get("status") == "ok",
        str(r4.get("status")),
    )
    checks.check(
        "round 5 re-releasing round 3's fragment blocks again: rounds 1 and 2's legitimately released fragments are still tracked",
        r5.get("status") == "blocked",
        str(r5.get("status")),
    )


# Server


def test_server() -> Checks:
    """Server; return evidence or raise on failure."""
    with _test_scope() as checks:
        root = _workspace(checks)
        asyncio.run(_server_mcp_surface(checks, root))
        asyncio.run(_server_cross_round(checks, root))
        _server_sandbox_and_patterns(checks, root)
        _worker_empty_answer_recovery(checks)
        _round_adjacent_fragment_patterns(checks)
        _worker_loop_recovery(checks)
        _server_session_eviction(checks)
        _server_warmup(checks)
        _worker_malformed_step(checks)
        _worker_grounding(checks, root)
        asyncio.run(_worker_prerequisite_accounting(checks, root))
        _worker_step_exhaustion(checks)
        _jobs_empty_answer(checks)
        return checks.finish(94)


CREDENTIAL_SHAPES: list[tuple[str, str, int, str]] = [
    ("stripe", "sk_live_", 24, ALNUM),
    ("stripe", "sk_test_", 24, ALNUM),
    ("stripe", "rk_live_", 24, ALNUM),
    ("stripe", "pk_test_", 24, ALNUM),
    ("github", "ghp_", 36, ALNUM),
    ("github", "gho_", 36, ALNUM),
    ("github", "ghs_", 36, ALNUM),
    ("gitlab", "glpat-", 20, ALNUM),
    ("aws key id", "AKIA", 16, string.ascii_uppercase + string.digits),
    ("aws key id", "ASIA", 16, string.ascii_uppercase + string.digits),
    ("google", "AIza", 35, ALNUM + "_-"),
    ("slack", "xoxb-", 24, string.digits + string.ascii_letters + "-"),
    ("npm", "npm_", 36, ALNUM),
    ("digitalocean", "dop_v1_", 64, string.hexdigits[:16].lower()),
    ("twilio", "SK", 32, string.hexdigits[:16].lower()),
]


def _worker_failed(payload: dict) -> bool:
    concerns = payload.get("guard", {}).get("concerns", []) or payload.get(
        "guard_concerns", []
    )
    return any(("local model" in str(c) or "no answer" in str(c) for c in concerns))


def _workspace(checks: Checks) -> Path:
    """A throwaway workspace with a decoy secret outside it."""
    tmp = Path(checks.directory(prefix="airlock-test-"))
    root = tmp / "vault"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "plan.md").write_text(
        "# Plan\nTwelve planning documents about budget forecasting.\n"
    )
    (root / "notes" / "people.txt").write_text(
        "Contact jane.doe@example-corp.com or 555-555-0100. SSN 123-45-6789.\n"
    )
    outside = tmp / "outside_secret.txt"
    outside.write_text("SHOULD-NEVER-BE-READABLE\n")
    (root / "notes" / "link.txt").symlink_to(outside)
    return root


async def _server_mcp_surface(checks: Checks, root: Path) -> None:
    try:
        from mcp import Client
    except ImportError as exc:
        checks.check("import Client from mcp", False, str(exc))
        return
    checks.check("import Client from mcp", True)
    try:
        server = airlock.build_server(_server_args(root))
    except Exception as exc:
        checks.check("build_server constructs", False, f"{type(exc).__name__}: {exc}")
        return
    checks.check("build_server constructs", True, "MCPServer + mcp_types import OK")
    async with Client(server) as client:
        listed = await client.list_tools()
        tools = {t.name: t for t in listed.tools}
        expected = {
            "airlock_open",
            "airlock_ask",
            "airlock_close",
            "airlock_extract",
            "airlock_guard_check",
        }
        checks.check(
            "five tools registered", set(tools) == expected, ",".join(sorted(tools))
        )
        server_version = getattr(client.server_info, "version", None)
        checks.check(
            "MCP server identifies itself with airlock's own version",
            server_version == airlock.__version__,
            server_version,
        )
        ask = tools.get("airlock_ask")
        if ask is None:
            checks.check("airlock_ask present", False)
            return
        ann = getattr(ask, "annotations", None)
        checks.check("airlock_ask carries annotations", ann is not None)
        if ann is not None:
            ro = getattr(ann, "read_only_hint", None)
            checks.check(
                "read_only_hint true when writes are off", ro is True, f"{ro!r}"
            )
            if hasattr(ann, "model_dump"):
                dumped = ann.model_dump(by_alias=True, exclude_none=True)
                checks.check(
                    "serialises to camelCase wire names",
                    "readOnlyHint" in dumped,
                    ",".join(sorted(dumped)),
                )
            else:
                checks.check(
                    "annotations are a pydantic model", False, type(ann).__name__
                )
        required = set(ask.input_schema.get("required", []))
        checks.check(
            "disclosure_request is optional",
            required == {"session", "question"},
            ",".join(sorted(required)),
        )
        checks.check(
            "disclosure_request is in the schema",
            "disclosure_request" in ask.input_schema.get("properties", {}),
        )
    server_w = airlock.build_server(
        _server_args(root, allow_writes=True, approve="none")
    )
    async with Client(server_w) as client:
        ask = {t.name: t for t in (await client.list_tools()).tools}["airlock_ask"]
        ann = getattr(ask, "annotations", None)
        checks.check(
            "read_only_hint flips to false with --allow-writes",
            getattr(ann, "read_only_hint", None) is False,
        )
        checks.check(
            "destructive_hint flips to true with --allow-writes",
            getattr(ann, "destructive_hint", None) is True,
        )
    real_cap = airlock.SESSION_CAP
    airlock.SESSION_CAP = 2
    airlock.SESSIONS.clear()
    try:
        server_evict = airlock.build_server(_server_args(root))
        async with Client(server_evict) as client:
            opened_ids = []
            for _ in range(3):
                opened = await client.call_tool("airlock_open", {"objective": "x"})
                opened_ids.append((opened.structured_content or {}).get("session"))
                await asyncio.sleep(0.01)
            checks.check(
                "all three opens returned a session", all(opened_ids), str(opened_ids)
            )
            checks.check(
                "the cap is enforced: at most SESSION_CAP sessions live",
                len(airlock.SESSIONS) <= airlock.SESSION_CAP,
                f"{len(airlock.SESSIONS)} live",
            )
            oldest, newest = (opened_ids[0], opened_ids[-1])
            res = await client.call_tool(
                "airlock_ask", {"session": oldest, "question": "x"}
            )
            payload = res.structured_content or {}
            checks.check(
                "an evicted session id fails closed: a clear refusal, not a silent new session or a crash",
                payload.get("status") == "error",
                str(payload),
            )
            checks.check(
                "positive control: the newest session, under the cap, is not evicted",
                newest in airlock.SESSIONS,
                sorted(airlock.SESSIONS),
            )
    finally:
        airlock.SESSION_CAP = real_cap
        airlock.SESSIONS.clear()


def _repeating_answers(values: list[str]):
    """A stub ollama_chat that returns each value in order, then repeats the
    last one if over-called. Used when switching answer sequences mid-session.
    """
    it = iter(values)
    last = values[-1] if values else ""

    def stub(*_args: object, **_kwargs: object) -> str:
        return next(it, last)

    return stub


async def _server_cross_round(checks: Checks, root: Path) -> None:
    try:
        from mcp import Client
    except ImportError as exc:
        checks.check("A2: import Client from mcp", False, str(exc))
        return
    tmp = Path(checks.directory(prefix="airlock-crossround-tool-test-"))
    (tmp / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    real_ollama = airlock.ollama_chat
    try:
        server = airlock.build_server(_server_args(tmp))
        async with Client(server) as client:
            opened = await client.call_tool("airlock_open", {"objective": "x"})
            session = (opened.structured_content or {}).get("session")
            checks.check(
                "A2: airlock_open returns a session",
                bool(session),
                str(opened.structured_content),
            )
            if not session:
                return

            def one_job(i: int) -> dict:
                return {
                    "session": session,
                    "jobs": [{"document": 0, "extract": f"q{i}"}],
                }

            airlock.ollama_chat = _repeating_answers(["912", "84", "7731"])
            round_results = []
            for i in range(3):
                res = await client.call_tool("airlock_extract", one_job(i))
                round_results.append(res.structured_content or {})
            checks.check(
                "A2: round 1 of 3 is ok, through the real tool",
                round_results[0].get("status") == "ok",
                str(round_results[0]),
            )
            checks.check(
                "A2: round 2 of 3 is ok, through the real tool",
                round_results[1].get("status") == "ok",
                str(round_results[1]),
            )
            checks.check(
                "A2: round 3 blocks through the real tool: completes cross-round reassembly",
                round_results[2].get("status") == "blocked",
                str(round_results[2]),
            )
            payload3 = json.dumps(round_results[2])
            checks.check(
                "A2: the blocked round's payload carries no SSN fragment or the full value",
                not any((f in payload3 for f in ("912", "84", "7731", "912-84-7731"))),
                payload3[:200],
            )
            words = ["forecast", "quarterly", "template", "summary", "agenda"]
            airlock.ollama_chat = _repeating_answers(words)
            benign_results = []
            for i, _word in enumerate(words, start=10):
                res = await client.call_tool("airlock_extract", one_job(i))
                benign_results.append((res.structured_content or {}).get("status"))
            checks.check(
                "A2: a benign multi-round session over the same session id stays ok, through the real tool (positive control)",
                all((status == "ok" for status in benign_results)),
                str(benign_results),
            )
    finally:
        airlock.ollama_chat = real_ollama


def _server_sandbox_and_patterns(checks: Checks, root: Path) -> None:
    sb = airlock.Sandbox(root=root, allow_writes=False)
    for attack in [
        "../outside_secret.txt",
        "../../etc/passwd",
        "/etc/passwd",
        "notes/../../outside_secret.txt",
        "notes/link.txt",
    ]:
        blocked = False
        try:
            sb.read_text(attack)
        except airlock.SandboxError:
            blocked = True
        except Exception:
            blocked = True
        checks.check(f"blocked: {attack}", blocked)
    body = sb.read_text("notes/plan.md")
    checks.check("legitimate read still works", "budget forecasting" in body)
    wrote = True
    try:
        sb.write_text("notes/x.md", "x")
    except airlock.SandboxError:
        wrote = False
    checks.check("writes refused by default", not wrote)
    aws = _fake_credential("", 40, B64)
    for label, text, want in [
        ("aws secret in prose", f"the AWS secret key is {aws}", True),
        ("aws secret in env form", f"AWS_SECRET_ACCESS_KEY={aws}", True),
        ("aws secret in yaml", f"  aws_secret_access_key: {aws}", True),
        ("aws secret after bare 'key'", f"key is {aws}", True),
        ("clean prose", "Twelve planning documents about budget forecasting.", False),
        ("key findings", "Key findings: revenue rose, headcount fell.", False),
        (
            "the key to",
            "The key to good documentation is worked examples that run.",
            False,
        ),
        (
            "key considerations",
            "key considerations: responsibilities and governance",
            False,
        ),
        ("laws and flaws", "The laws and flaws of the proposal were discussed.", False),
        ("secret to good writing", "The secret to good writing is revision.", False),
        (
            "access credentials prose",
            "Access credentials are issued by reception.",
            False,
        ),
        ("a url", "See https://example.com/documentation/getting-started", False),
    ]:
        got = bool(airlock.scan_secrets(text))
        checks.check(f"secrets, {label}", got == want, f"detected={got}")
    missed = []
    for vendor, prefix, length, alphabet in CREDENTIAL_SHAPES:
        for _ in range(8):
            sample = _fake_credential(prefix, length, alphabet)
            if not airlock.scan_secrets(sample):
                missed.append(f"{vendor} {prefix}")
                break
    checks.check(
        f"detects all {len(CREDENTIAL_SHAPES)} credential shapes, 8 samples each",
        not missed,
        ", ".join(sorted(set(missed))) or "all caught",
    )
    for label, text, want in [
        ("email", "write to jane.doe@example-corp.com", True),
        ("ssn", "ssn 123-45-6789", True),
        ("ordinary sentence", "The team meets on Tuesday to review scope.", False),
    ]:
        got = bool(airlock.scan_pii_patterns(text))
        checks.check(f"pii, {label}", got == want, f"detected={got}")
    for label, leaky in [
        ("email", "the message reveals the email jane.doe@example-corp.com"),
        ("credential", f"found {_fake_credential('sk_live_', 24)} in the draft"),
        ("ssn", "contains the SSN 123-45-6789"),
    ]:
        cleaned = airlock.sanitise_concerns([leaky])
        checks.check(
            f"guard explanation cannot quote a blocked {label}", cleaned != [leaky]
        )
    safe = ["personal identifier detected: email", "described health circumstances"]
    checks.check(
        "safe explanations survive sanitising", airlock.sanitise_concerns(safe) == safe
    )


def _round_adjacent_fragment_patterns(checks: Checks) -> None:
    fragments = ["912", "84", "7731"]
    for f in fragments:
        checks.check(
            f"fragment {f!r} is harmless alone", not airlock.scan_pii_patterns(f)
        )
    joined = " ".join(fragments)
    checks.check(
        "but the round reassembles into an identifier",
        bool(airlock.scan_pii_patterns(joined)),
        ",".join(sorted({x["rule"] for x in airlock.scan_pii_patterns(joined)})),
    )
    checks.check(
        "MAX_JOBS_PER_ROUND caps fishing",
        airlock.MAX_JOBS_PER_ROUND <= 20,
        str(airlock.MAX_JOBS_PER_ROUND),
    )


def _worker_empty_answer_recovery(checks: Checks) -> None:
    """Worker-loop recovery, with the model stubbed so no Ollama is needed."""
    session = airlock.Session(
        session_id="test",
        objective="x",
        sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
        worker_model="stub",
    )
    real = airlock.ollama_chat
    try:
        replies = [
            {"action": "answer"},
            {"action": "answer", "answer": "Two planning files, no personal data."},
            {"verdict": "approve", "concerns": [], "instruction": ""},
        ]

        def scripted(*_a, **_k):
            return replies.pop(0) if replies else {"action": "answer", "answer": "x"}

        airlock.ollama_chat = scripted
        out = airlock.run_worker(session, "what is here?")
        checks.check(
            "empty answer is retried, not fatal",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )

        def always_empty(*_a, **_k):
            return {"action": "answer"}

        airlock.ollama_chat = always_empty
        out = airlock.run_worker(session, "what is here?")
        checks.check(
            "a permanently empty worker still fails closed",
            out.get("status") in ("blocked",) and (not out.get("message")),
            f"{out.get('status')}",
        )
    finally:
        airlock.ollama_chat = real


def _worker_loop_recovery(checks: Checks) -> None:

    def make_session() -> airlock.Session:
        return airlock.Session(
            session_id="test-b4",
            objective="x",
            sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
            worker_model="stub",
        )

    real = airlock.ollama_chat
    try:
        prompts: list[str] = []
        loop_replies = [
            {"action": "list", "path": "."},
            {"action": "list", "path": "."},
            {"action": "answer", "answer": "Two planning files, no personal data."},
        ]

        def scripted_loop(_model: str, prompt: str, _schema: dict) -> dict:
            prompts.append(prompt)
            return (
                loop_replies.pop(0) if loop_replies else {"action": "list", "path": "."}
            )

        airlock.ollama_chat = scripted_loop
        out = airlock.run_worker(make_session(), "how many files are here, roughly?")
        checks.check(
            "a repeated action still reaches an answer, not step exhaustion",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )
        checks.check(
            "the repeat is fed back to the model before its next turn",
            len(prompts) >= 3
            and any((w in prompts[2].lower() for w in ("already", "repeat"))),
            prompts[2][-300:] if len(prompts) >= 3 else f"only {len(prompts)} prompts",
        )

        def scripted_immediate(_model: str, _prompt: str, _schema: dict) -> dict:
            return {
                "action": "answer",
                "answer": "Two planning files, no personal data.",
            }

        airlock.ollama_chat = scripted_immediate
        out = airlock.run_worker(make_session(), "what is here?")
        checks.check(
            "a worker that answers immediately is unaffected",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )
        secret = _fake_credential("sk_live_", 24)

        def scripted_unrevisable(_model: str, _prompt: str, _schema: dict) -> dict:
            return {"action": "answer", "answer": secret}

        airlock.ollama_chat = scripted_unrevisable
        session = make_session()
        out = airlock.run_worker(session, "what is the vendor key?")
        checks.check(
            "identical repeated guard rejections stop before all revisions are spent",
            out.get("status") == "blocked"
            and session.revisions < airlock.MAX_REVISIONS,
            f"status={out.get('status')} revisions={session.revisions}",
        )
        blob = json.dumps(out)
        checks.check(
            "the stop-early concern names neither the file, path, nor the withheld content",
            secret not in blob and str(Path(".").resolve()) not in blob,
            blob[:200],
        )
        checks.check(
            "no concern text contains a path separator",
            not any(("/" in c for c in out.get("guard_concerns", []))),
            str(out.get("guard_concerns")),
        )
        revise_replies = [
            {"action": "answer", "answer": secret},
            {"action": "answer", "answer": "It is a general business document."},
        ]

        def scripted_revisable(_model: str, _prompt: str, _schema: dict) -> dict:
            return (
                revise_replies.pop(0)
                if revise_replies
                else {
                    "action": "answer",
                    "answer": "It is a general business document.",
                }
            )

        airlock.ollama_chat = scripted_revisable
        session = make_session()
        out = airlock.run_worker(session, "what is the vendor key?")
        checks.check(
            "a rejection that is then successfully revised still approves",
            out.get("status") == "approved" and session.revisions == 1,
            f"status={out.get('status')} revisions={session.revisions}",
        )
    finally:
        airlock.ollama_chat = real


def _server_session_eviction(checks: Checks) -> None:

    def fresh_session(sid: str, idle_seconds: float) -> airlock.Session:
        s = airlock.Session(
            session_id=sid,
            objective="x",
            sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
            worker_model="stub",
        )
        s.last_active = (datetime.now() - timedelta(seconds=idle_seconds)).isoformat()
        return s

    real_cap, real_ttl = (airlock.SESSION_CAP, airlock.SESSION_IDLE_SECONDS)
    airlock.SESSIONS.clear()
    try:
        airlock.SESSION_CAP = 3
        airlock.SESSION_IDLE_SECONDS = 99999
        airlock.SESSIONS["old"] = fresh_session("old", 30)
        airlock.SESSIONS["mid"] = fresh_session("mid", 20)
        airlock.SESSIONS["new"] = fresh_session("new", 10)
        airlock.evict_stale_sessions()
        checks.check(
            "positive control: three sessions under the cap are not evicted",
            set(airlock.SESSIONS) == {"old", "mid", "new"},
            sorted(airlock.SESSIONS),
        )
        airlock.SESSIONS["newer"] = fresh_session("newer", 0)
        airlock.evict_stale_sessions()
        checks.check(
            "cap enforced once a fourth session arrives",
            len(airlock.SESSIONS) <= airlock.SESSION_CAP,
            f"{len(airlock.SESSIONS)} live: {sorted(airlock.SESSIONS)}",
        )
        checks.check(
            "oldest-idle session evicted first",
            "old" not in airlock.SESSIONS,
            sorted(airlock.SESSIONS),
        )
        checks.check(
            "positive control: the newest session is not evicted",
            "newer" in airlock.SESSIONS,
            sorted(airlock.SESSIONS),
        )
        airlock.SESSIONS.clear()
        airlock.SESSION_CAP = 200
        airlock.SESSION_IDLE_SECONDS = 60
        airlock.SESSIONS["stale"] = fresh_session("stale", 120)
        airlock.SESSIONS["active"] = fresh_session("active", 5)
        airlock.evict_stale_sessions()
        checks.check(
            "a session idle past the TTL is evicted", "stale" not in airlock.SESSIONS
        )
        checks.check(
            "positive control: a session under the TTL is not evicted",
            "active" in airlock.SESSIONS,
        )
        checks.check(
            "an evicted id looks exactly like an unknown one to the caller",
            airlock.SESSIONS.get("stale") is None,
        )
    finally:
        airlock.SESSION_CAP, airlock.SESSION_IDLE_SECONDS = (real_cap, real_ttl)
        airlock.SESSIONS.clear()


def _server_warmup(checks: Checks) -> None:
    real_build = airlock.build_server
    real_pii, real_policy = (airlock._load_pii_detector, airlock._load_policy_linter)
    calls: list[str] = []

    class StubServer:
        def run(self) -> None:
            calls.append("mcp.run")

    def stub_build(_args: object) -> StubServer:
        calls.append("build_server")
        return StubServer()

    def stub_pii(*_a: object, **_k: object) -> None:
        calls.append("load_pii")

    def stub_policy(*_a: object, **_k: object) -> None:
        calls.append("load_policy")

    airlock.build_server = stub_build
    airlock._load_pii_detector = stub_pii
    airlock._load_policy_linter = stub_policy
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = airlock.cmd_serve(_server_args(Path(".")))
        checks.check("serve reaches readiness and runs the transport", rc == 0, str(rc))
        checks.check(
            "both encoders load, in order, before mcp.run",
            calls == ["build_server", "load_pii", "load_policy", "mcp.run"],
            str(calls),
        )
        checks.check(
            "serve prints nothing to stdout during warm-up (CLAUDE.md: stdout is the JSON-RPC channel)",
            buf.getvalue() == "",
            repr(buf.getvalue()[:120]),
        )
    finally:
        airlock.build_server = real_build
        airlock._load_pii_detector = real_pii
        airlock._load_policy_linter = real_policy
    calls.clear()
    airlock.build_server = stub_build

    def failing_pii(*_a: object, **_k: object) -> None:
        calls.append("load_pii")
        raise airlock.GuardModelUnavailable("stub load failure")

    airlock._load_pii_detector = failing_pii
    airlock._load_policy_linter = stub_policy
    try:
        rc = airlock.cmd_serve(_server_args(Path(".")))
        checks.check(
            "a warm-up load failure is a startup failure, not success", rc != 0, str(rc)
        )
        checks.check(
            "mcp.run is never reached when warm-up fails",
            "mcp.run" not in calls,
            str(calls),
        )
    finally:
        airlock.build_server = real_build
        airlock._load_pii_detector = real_pii
        airlock._load_policy_linter = real_policy


def _worker_malformed_step(checks: Checks) -> None:

    def make_session() -> airlock.Session:
        return airlock.Session(
            session_id="test-b8",
            objective="x",
            sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
            worker_model="stub",
        )

    real = airlock.ollama_chat
    try:
        for bad in ({"nested": "dict"}, ["a", "list"]):

            def scripted_bad(
                _model: str, _prompt: str, _schema: dict, _bad: object = bad
            ) -> dict:
                return {"action": "list", "path": _bad}

            airlock.ollama_chat = scripted_bad
            raised: Exception | None = None
            out: dict | None = None
            try:
                out = airlock.run_worker(make_session(), "what is here?")
            except Exception as exc:
                raised = exc
            checks.check(
                f"path={type(bad).__name__} does not escape run_worker as an exception",
                raised is None,
                f"{type(raised).__name__}: {raised}" if raised else "no exception",
            )
            checks.check(
                f"path={type(bad).__name__} blocks rather than approving",
                out is not None and out.get("status") == "blocked",
                str(out),
            )
    finally:
        airlock.ollama_chat = real
    try:

        def scripted_ok(_model: str, _prompt: str, _schema: dict) -> dict:
            return {
                "action": "answer",
                "answer": "Two planning files, no personal data.",
            }

        airlock.ollama_chat = scripted_ok
        out = airlock.run_worker(make_session(), "what is here?")
        checks.check(
            "a normal string-path/answer step still approves (positive control)",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )
    finally:
        airlock.ollama_chat = real


def _worker_grounding(checks: Checks, root: Path) -> None:

    def make_session() -> airlock.Session:
        return airlock.Session(
            session_id="test-b9",
            objective="x",
            sandbox=airlock.Sandbox(root=root, allow_writes=False),
            worker_model="stub",
        )

    real = airlock.ollama_chat
    try:
        grounded_replies = [
            {"action": "read", "path": "notes/plan.md"},
            {"action": "answer", "answer": "Two planning files, no personal data."},
        ]

        def scripted_grounded(*_a, **_k):
            return (
                grounded_replies.pop(0)
                if grounded_replies
                else {"action": "answer", "answer": "x"}
            )

        airlock.ollama_chat = scripted_grounded
        out = airlock.run_worker(make_session(), "what is here?")
        checks.check(
            "a worker that reads successfully before answering is grounded",
            out.get("status") == "approved" and out.get("grounded") is True,
            f"status={out.get('status')} grounded={out.get('grounded')!r}",
        )

        def scripted_no_read(_model: str, _prompt: str, _schema: dict) -> dict:
            return {
                "action": "answer",
                "answer": "Two planning files, no personal data.",
            }

        airlock.ollama_chat = scripted_no_read
        out = airlock.run_worker(make_session(), "what is here?")
        checks.check(
            "a worker that answers with zero reads is not grounded",
            out.get("status") == "approved" and out.get("grounded") is False,
            f"status={out.get('status')} grounded={out.get('grounded')!r}",
        )
        fabricated_replies = [
            {"action": "read", "path": "does-not-exist.txt"},
            {"action": "answer", "answer": "the file does not exist"},
        ]

        def scripted_fabricated(*_a, **_k):
            return (
                fabricated_replies.pop(0)
                if fabricated_replies
                else {"action": "answer", "answer": "x"}
            )

        airlock.ollama_chat = scripted_fabricated
        out = airlock.run_worker(make_session(), "what does the file say?")
        checks.check(
            "a failed read followed by a fabricated answer is not grounded",
            out.get("grounded") is False,
            f"status={out.get('status')} grounded={out.get('grounded')!r}",
        )
    finally:
        airlock.ollama_chat = real
    session = make_session()
    approved = airlock.envelope(session, "approved", "fine", [])
    note = approved.get("note", "").lower()
    checks.check(
        "envelope's note states passing the guard is not an accuracy guarantee",
        "accura" in note or "correct" in note,
        approved.get("note", ""),
    )
    result_grounded = {
        "session": "x",
        "status": "approved",
        "grounded": True,
        "withheld": False,
        "guard_concerns": [],
    }
    rcpt = airlock.receipt(result_grounded, ["read", "approved"])
    checks.check(
        "receipt reports grounded as a top-level operation fact",
        rcpt.get("grounded") is True,
        str(rcpt),
    )
    checks.check(
        "receipt carries no file name even though grounded is reported",
        "plan.md" not in json.dumps(rcpt) and "notes" not in json.dumps(rcpt),
        str(rcpt),
    )
    result_ungrounded = {
        "session": "x",
        "status": "approved",
        "grounded": False,
        "withheld": False,
        "guard_concerns": [],
    }
    rcpt2 = airlock.receipt(result_ungrounded, ["answer"])
    checks.check(
        "receipt reports grounded=False when nothing was successfully read (positive control)",
        rcpt2.get("grounded") is False,
        str(rcpt2),
    )


WORKER_CHECKS = [
    "airlock_open returns a session",
    "receipt withholds content",
    "receipt says work was performed",
    "receipt has no message field",
    "disclosure_request returns an envelope",
    "guard still blocks identifiers on disclosure",
    "an approved reply actually carried content",
]


def _skip_worker_checks(checks: Checks, done: int, reason: str) -> None:
    """skip() every GROUP_C_CHECKS entry from index `done` onward."""
    for name in WORKER_CHECKS[done:]:
        checks.skip(name, reason)


async def _worker_disclosure(checks: Checks, root: Path) -> None:
    try:
        from mcp import Client
    except ImportError as exc:
        _skip_worker_checks(checks, 0, f"no MCP SDK: {exc}"[:60])
        return
    try:
        airlock.ollama_models()
    except RuntimeError as exc:
        _skip_worker_checks(checks, 0, str(exc)[:60])
        return
    server = airlock.build_server(_server_args(root))
    async with Client(server) as client:
        opened = await client.call_tool(
            "airlock_open", {"objective": "Describe this folder."}
        )
        session = (opened.structured_content or {}).get("session")
        checks.check(WORKER_CHECKS[0], bool(session))
        if not session:
            _skip_worker_checks(checks, 1, "airlock_open returned no session")
            return
        res = await client.call_tool(
            "airlock_ask",
            {"session": session, "question": "What personal details are in the notes?"},
        )
        payload = res.structured_content or {}
        if _worker_failed(payload):
            why = "; ".join(payload.get("guard", {}).get("concerns", []))[:80]
            reason = f"INCONCLUSIVE, worker never ran: {why}"
            _skip_worker_checks(checks, 1, reason)
            return
        blob = json.dumps(payload)
        leaks = [
            s
            for s in ("jane.doe", "123-45-6789", "555-555-0100", "people.txt")
            if s in blob
        ]
        checks.check("receipt withholds content", not leaks, ",".join(leaks) or "clean")
        checks.check(
            "receipt says work was performed", payload.get("performed") is True
        )
        checks.check("receipt has no message field", "message" not in payload)
        res2 = await client.call_tool(
            "airlock_ask",
            {
                "session": session,
                "question": "How many files are here, roughly?",
                "disclosure_request": "a one line summary, to decide whether to read more",
            },
        )
        payload2 = res2.structured_content or {}
        checks.check(WORKER_CHECKS[4], "status" in payload2)
        if _worker_failed(payload2):
            _skip_worker_checks(checks, 5, "INCONCLUSIVE, worker never ran")
            return
        blob2 = json.dumps(payload2)
        hard_leaks = [
            s for s in ("123-45-6789", "jane.doe@example-corp.com") if s in blob2
        ]
        checks.check(
            "guard still blocks identifiers on disclosure",
            not hard_leaks,
            ",".join(hard_leaks) or "clean",
        )
        checks.check(
            "an approved reply actually carried content",
            bool(str(payload2.get("message", "")).strip()),
            f"{len(str(payload2.get('message', '')))} chars",
        )


async def _worker_prerequisite_accounting(checks: Checks, root: Path) -> None:
    """Every worker prerequisite guard must skip exactly what a completed
    run would have checked, not fewer. Drives the worker checks three times under
    synthetic failures (SDK missing, Ollama unreachable, session absent) so
    the invariant is asserted behaviourally, not just read off the source.
    """

    async def run_and_count() -> int:
        before = (len(checks.passed), len(checks.failed), len(checks.unavailable))
        await _worker_disclosure(checks, root)
        after = (len(checks.passed), len(checks.failed), len(checks.unavailable))
        total = sum((a - b for a, b in zip(after, before)))
        del checks.passed[before[0] :]
        del checks.failed[before[1] :]
        del checks.unavailable[before[2] :]
        return total

    had_mcp = "mcp" in sys.modules
    real_mcp = sys.modules.get("mcp")
    sys.modules["mcp"] = None
    try:
        n = await run_and_count()
        checks.check(
            "missing-SDK path accounts for every check",
            n == len(WORKER_CHECKS),
            f"{n} of {len(WORKER_CHECKS)}",
        )
    finally:
        if had_mcp:
            sys.modules["mcp"] = real_mcp
        else:
            del sys.modules["mcp"]
    real_ollama_models = airlock.ollama_models
    airlock.ollama_models = lambda: (_ for _ in ()).throw(RuntimeError("no ollama"))
    try:
        n = await run_and_count()
        checks.check(
            "unreachable-Ollama path accounts for every check",
            n == len(WORKER_CHECKS),
            f"{n} of {len(WORKER_CHECKS)}",
        )
    finally:
        airlock.ollama_models = real_ollama_models
    try:
        from mcp import Client as real_client_class
    except ImportError:
        checks.skip(
            "absent-session path accounts for every check",
            "no MCP SDK to drive this with",
        )
        return

    class _FakeResult:
        structured_content = {}

    class _NoSessionClient:
        def __init__(self, _server: object) -> None:
            pass

        async def __aenter__(self) -> "_NoSessionClient":
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def call_tool(self, _name: str, _args: dict) -> _FakeResult:
            return _FakeResult()

    real_client = real_client_class
    real_ollama_models = airlock.ollama_models
    airlock.ollama_models = lambda: ["stub-model"]
    sys.modules["mcp"].Client = _NoSessionClient
    try:
        n = await run_and_count()
        checks.check(
            "absent-session path accounts for every check",
            n == len(WORKER_CHECKS),
            f"{n} of {len(WORKER_CHECKS)}",
        )
    finally:
        sys.modules["mcp"].Client = real_client
        airlock.ollama_models = real_ollama_models


def _worker_step_exhaustion(checks: Checks) -> None:
    session = airlock.Session(
        session_id="exhaustion-test",
        objective="x",
        sandbox=airlock.Sandbox(root=REPO, allow_writes=False),
        worker_model="stub-worker",
    )
    original = airlock.ollama_chat
    airlock.ollama_chat = lambda model, prompt, schema=None: {
        "action": "list",
        "path": ".",
    }
    try:
        result = airlock.run_worker(session, "what is here?")
    finally:
        airlock.ollama_chat = original
    checks.check(
        "step exhaustion is reported blocked, not approved",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    checks.check(
        "step exhaustion carries no message content",
        not result.get("message"),
        repr(result.get("message")),
    )
    checks.check(
        "step exhaustion names the cause, distinct from the empty-answer path",
        any(("step" in c.lower() for c in result.get("guard_concerns", []))),
        ",".join(result.get("guard_concerns", [])) or "no concerns",
    )


def _jobs_empty_answer(checks: Checks) -> None:
    tmp = Path(checks.directory(prefix="jobs-empty-answer-"))
    (tmp / "doc0.txt").write_text("irrelevant content\n")
    session = airlock.Session(
        session_id="jobs-empty",
        objective="x",
        sandbox=airlock.Sandbox(root=tmp, allow_writes=False),
        worker_model="stub-worker",
    )
    original = airlock.ollama_chat
    airlock.ollama_chat = lambda model, prompt, schema=None: ""
    try:
        result = airlock.run_jobs(
            session, [{"document": 0, "extract": "the value in box 1"}]
        )
    finally:
        airlock.ollama_chat = original
    results = result.get("results") or []
    job = results[0] if results else {}
    checks.check(
        "an empty answer is reported not_found, not ok",
        job.get("status") == "not_found",
        str(job),
    )
    checks.check(
        "an empty answer never carries a released value", "value" not in job, str(job)
    )


# Guard encoders and failure handling


def test_guard() -> Checks:
    """Guard encoders and failure handling; return evidence or raise on failure."""
    with _test_scope() as checks:
        unavailable = _guard_models_available()
        _guard_pii_detector(checks, unavailable)
        _guard_containment_positive_control(checks)
        _guard_policy_linter(checks, unavailable)
        _guard_rule5_bare_words(checks, unavailable)
        _guard_pii_entity_threshold(checks, unavailable)
        _guard_postal_code_letter_gate(checks, unavailable)
        _guard_chunking(checks, unavailable)
        _guard_prefix_derivation(checks)
        _guard_fail_closed(checks)
        _guard_layer_order(checks, unavailable)
        _guard_evaluate_fail_closed(checks)
        _guard_evaluate_default_threshold(checks)
        _guard_chunk_text_step_guard(checks)
        _guard_dense_non_ascii_truncation(checks, unavailable)
        return checks.finish(41)


SSN_TEXT = "My social security number is 912-84-7731."

EMAIL_TEXT = "Reach me at jane.doe@example.com for details."

CLEAN_PII_TEXT = "The quarterly report was filed on time and everyone was pleased."

MEDICAL_TEXT = "I was recently diagnosed with stage 2 breast cancer and started chemotherapy last week."

ACQUISITION_TEXT = "Just so you know, we are about to be acquired by a larger competitor but it hasn't been announced yet."

CLEAN_POLICY_TEXT = "The README describes how to set up the development environment and run the test suite."

BORDERLINE_FINANCIAL_TEXT = (
    "Money has been a bit tight lately with all the bills piling up."
)

PII_POSTAL_FALSE_POSITIVE_TEXT = "94250.0"

PII_POSTAL_TRUE_POSITIVE_TEXT = (
    "Please mail the refund check to zip code 94250, care of the Franchise Tax Board."
)

PII_POSTAL_HIGH_SCORING_BARE_NUMBER = "43044"

PII_POSTAL_MIDSCORE_ADDRESS_TEXT = "Deliver to warehouse bay 94105 by Friday."

BARE_BUSINESS_WORDS = [
    "shipment",
    "inventory",
    "ledger",
    "invoice",
    "backlog",
    "vendor",
    "forecast",
    "revenue",
]

PII_OVERFLOW_FILLER = (
    "The quarterly report was filed on time and everyone was pleased with the outcome. "
    * 40
)

PII_OVERFLOW_TEXT = PII_OVERFLOW_FILLER + SSN_TEXT

POLICY_OVERFLOW_FILLER = (
    "The README describes how to set up the development environment and run the test suite. "
    * 120
)

POLICY_OVERFLOW_TEXT = POLICY_OVERFLOW_FILLER + MEDICAL_TEXT

RARE_KANJI_UNIT = "鬱鬱蔥蔥薔薇鑫燚龘齉爨龗蠿豔驫麤龖钃鱻虋鼺齾靐飝饗饕"

DENSE_NON_ASCII_PII_FILLER = (RARE_KANJI_UNIT * (900 // len(RARE_KANJI_UNIT) + 2))[:900]

DENSE_NON_ASCII_PII_TEXT = DENSE_NON_ASCII_PII_FILLER + SSN_TEXT

DENSE_NON_ASCII_POLICY_FILLER = (RARE_KANJI_UNIT * (2500 // len(RARE_KANJI_UNIT) + 2))[
    :2500
]

DENSE_NON_ASCII_POLICY_TEXT = DENSE_NON_ASCII_POLICY_FILLER + MEDICAL_TEXT


def _guard_models_available() -> str:
    """Try a real call through both guards. Empty string if both work,
    otherwise the failure reason to skip every case with.
    """
    try:
        airlock.scan_pii_model("probe")
        airlock.scan_policy("probe")
    except airlock.GuardModelUnavailable as exc:
        return str(exc)
    return ""


def _guard_pii_detector(checks: Checks, unavailable: str) -> None:
    if unavailable:
        for name in (
            "detector finds an SSN",
            "detector finds an email",
            "detector is clean on ordinary prose",
            "detector findings never carry the raw span",
        ):
            checks.skip(name, unavailable)
        return
    findings = airlock.scan_pii_model(SSN_TEXT)
    rules = {f["rule"] for f in findings}
    checks.check(
        "detector finds an SSN",
        any((r.split(".")[0] == "identity" for r in rules)),
        ",".join(sorted(rules)) or "no findings",
    )
    findings = airlock.scan_pii_model(EMAIL_TEXT)
    rules = {f["rule"] for f in findings}
    checks.check(
        "detector finds an email",
        any((r.split(".")[0] == "contact" for r in rules)),
        ",".join(sorted(rules)) or "no findings",
    )
    findings = airlock.scan_pii_model(CLEAN_PII_TEXT)
    checks.check("detector is clean on ordinary prose", findings == [], str(findings))
    findings = airlock.scan_pii_model(SSN_TEXT) + airlock.scan_pii_model(EMAIL_TEXT)
    leaked = [
        v
        for f in findings
        for v in f.values()
        if v in (SSN_TEXT, EMAIL_TEXT, "912-84-7731", "jane.doe@example.com")
    ]
    checks.check(
        "detector findings never carry the raw span", leaked == [], ",".join(leaked)
    )


def _guard_containment_positive_control(checks: Checks) -> None:
    poisoned = [{"rule": "identity.ssn", "masked": "912-84-7731", "layer": "pii:model"}]
    poisoned_leaked = [
        v
        for f in poisoned
        for v in f.values()
        if v in (SSN_TEXT, EMAIL_TEXT, "912-84-7731", "jane.doe@example.com")
    ]
    checks.check(
        "positive control: a hand-built span-carrying finding is caught by the same check",
        poisoned_leaked != [],
        ",".join(poisoned_leaked) or "not caught",
    )


def _guard_policy_linter(checks: Checks, unavailable: str) -> None:
    if unavailable:
        for name in (
            "linter flags a medical disclosure",
            "linter flags an unannounced acquisition",
            "linter is clean on a benign file description",
            "per-rule threshold override: silent at 0.98",
            "per-rule threshold override: fires at 0.50",
        ):
            checks.skip(name, unavailable)
        return
    findings = airlock.scan_policy(MEDICAL_TEXT)
    rules = {f["rule"] for f in findings}
    checks.check(
        "linter flags a medical disclosure",
        "rule0" in rules,
        ",".join(sorted(rules)) or "none",
    )
    findings = airlock.scan_policy(ACQUISITION_TEXT)
    rules = {f["rule"] for f in findings}
    checks.check(
        "linter flags an unannounced acquisition",
        "rule5" in rules,
        ",".join(sorted(rules)) or "none",
    )
    findings = airlock.scan_policy(CLEAN_POLICY_TEXT)
    checks.check(
        "linter is clean on a benign file description", findings == [], str(findings)
    )
    original = airlock.POLICY_LINTER_RULE_THRESHOLDS
    try:
        airlock.POLICY_LINTER_RULE_THRESHOLDS = {1: 0.98}
        rules = {f["rule"] for f in airlock.scan_policy(BORDERLINE_FINANCIAL_TEXT)}
        checks.check(
            "per-rule threshold override: silent at 0.98",
            "rule1" not in rules,
            ",".join(sorted(rules)),
        )
        airlock.POLICY_LINTER_RULE_THRESHOLDS = {1: 0.5}
        rules = {f["rule"] for f in airlock.scan_policy(BORDERLINE_FINANCIAL_TEXT)}
        checks.check(
            "per-rule threshold override: fires at 0.50",
            "rule1" in rules,
            ",".join(sorted(rules)),
        )
    finally:
        airlock.POLICY_LINTER_RULE_THRESHOLDS = original


def _guard_rule5_bare_words(checks: Checks, unavailable: str) -> None:
    if unavailable:
        for word in BARE_BUSINESS_WORDS:
            checks.skip(f"rule5 silent on bare word: {word!r}", unavailable)
        return
    for word in BARE_BUSINESS_WORDS:
        rules = {f["rule"] for f in airlock.scan_policy(word)}
        checks.check(
            f"rule5 silent on bare word: {word!r}",
            "rule5" not in rules,
            ",".join(sorted(rules)) or "none",
        )


def _guard_pii_entity_threshold(checks: Checks, unavailable: str) -> None:
    if unavailable:
        for name in (
            "bare number false positive: silent at the shipped threshold",
            "postal code in context: still fires at the shipped threshold",
            "override mechanism: raising the threshold silences a real postal code",
            "override mechanism: lowering the threshold reproduces a finding",
        ):
            checks.skip(name, unavailable)
        return
    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_FALSE_POSITIVE_TEXT)}
    checks.check(
        "bare number false positive: silent at the shipped threshold",
        "contact.postal_code" not in rules,
        ",".join(sorted(rules)) or "none",
    )
    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_TRUE_POSITIVE_TEXT)}
    checks.check(
        "postal code in context: still fires at the shipped threshold",
        "contact.postal_code" in rules,
        ",".join(sorted(rules)) or "none",
    )
    original = airlock.PII_DETECTOR_ENTITY_THRESHOLDS
    try:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = {"contact.postal_code": 0.98}
        rules = {
            f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_TRUE_POSITIVE_TEXT)
        }
        checks.check(
            "override mechanism: raising the threshold silences a real postal code",
            "contact.postal_code" not in rules,
            ",".join(sorted(rules)),
        )
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = {"contact.postal_code": 0.5}
        rules = {
            f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_MIDSCORE_ADDRESS_TEXT)
        }
        checks.check(
            "override mechanism: lowering the threshold reproduces a finding",
            "contact.postal_code" in rules,
            ",".join(sorted(rules)),
        )
    finally:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = original


def _guard_postal_code_letter_gate(checks: Checks, unavailable: str) -> None:
    if unavailable:
        for name in (
            "high-scoring bare number: not blocked as a postal code",
            "real postal code: still blocked in an address",
            "letter gate is independent of the threshold: still silent at a near-zero threshold",
        ):
            checks.skip(name, unavailable)
        return
    rules = {
        f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_HIGH_SCORING_BARE_NUMBER)
    }
    checks.check(
        "high-scoring bare number: not blocked as a postal code",
        "contact.postal_code" not in rules,
        ",".join(sorted(rules)) or "none",
    )
    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_TRUE_POSITIVE_TEXT)}
    checks.check(
        "real postal code: still blocked in an address",
        "contact.postal_code" in rules,
        ",".join(sorted(rules)) or "none",
    )
    original = airlock.PII_DETECTOR_ENTITY_THRESHOLDS
    try:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = {"contact.postal_code": 0.01}
        rules = {
            f["rule"]
            for f in airlock.scan_pii_model(PII_POSTAL_HIGH_SCORING_BARE_NUMBER)
        }
        checks.check(
            "letter gate is independent of the threshold: still silent at a near-zero threshold",
            "contact.postal_code" not in rules,
            ",".join(sorted(rules)) or "none",
        )
    finally:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = original


def _guard_chunking(checks: Checks, unavailable: str) -> None:
    if unavailable:
        for name in (
            "PII detector: an SSN past a single window is still found",
            "policy linter: a disclosure past a single window is still found",
        ):
            checks.skip(name, unavailable)
        return
    rules = {f["rule"] for f in airlock.scan_pii_model(PII_OVERFLOW_TEXT)}
    checks.check(
        "PII detector: an SSN past a single window is still found",
        any((r.split(".")[0] == "identity" for r in rules)),
        ",".join(sorted(rules)) or "no findings, truncated away",
    )
    rules = {f["rule"] for f in airlock.scan_policy(POLICY_OVERFLOW_TEXT)}
    checks.check(
        "policy linter: a disclosure past a single window is still found",
        "rule0" in rules,
        ",".join(sorted(rules)) or "no findings, truncated away",
    )


def _guard_prefix_derivation(checks: Checks) -> None:
    original = airlock.CONTEXTUAL_RULES
    try:
        first = airlock._policy_prefix()
        checks.check(
            "prefix reflects the current CONTEXTUAL_RULES",
            "medical condition" in first,
            first[:60],
        )
        airlock.CONTEXTUAL_RULES = ["Flag disclosure of a favourite colour."]
        second = airlock._policy_prefix()
        checks.check(
            "prefix rebuilds immediately after CONTEXTUAL_RULES changes",
            "favourite colour" in second and "medical condition" not in second,
            second[:60],
        )
    finally:
        airlock.CONTEXTUAL_RULES = original


def _guard_fail_closed(checks: Checks) -> None:
    original_model = airlock.PII_DETECTOR_MODEL
    airlock.PII_DETECTOR_MODEL = "LiquidAI/does-not-exist-airlock-test-xyz"
    airlock._load_pii_detector.cache_clear()
    try:
        raised = None
        try:
            airlock.scan_pii_model("anything")
        except airlock.GuardModelUnavailable as exc:
            raised = exc
        checks.check(
            "a loader failure raises GuardModelUnavailable, not an empty list",
            raised is not None,
            str(raised) if raised else "no exception raised",
        )
    finally:
        airlock.PII_DETECTOR_MODEL = original_model
        airlock._load_pii_detector.cache_clear()


def _guard_layer_order(checks: Checks, unavailable: str) -> None:
    credential = "sk-" + "".join((secrets.choice(ALNUM) for _ in range(24)))
    verdict = airlock.evaluate(f"here is a key: {credential}")
    checks.check(
        "a credential still blocks via secrets",
        verdict.decision == "revise" and verdict.layers_run == ["secrets"],
        f"{verdict.decision} via {verdict.layers_run}",
    )
    verdict = airlock.evaluate(SSN_TEXT)
    checks.check(
        "a bare SSN blocks via pii-patterns before any model layer",
        verdict.decision == "revise"
        and "pii-patterns" in verdict.layers_run
        and ("pii-detector" not in verdict.layers_run)
        and ("policy-linter" not in verdict.layers_run),
        f"{verdict.decision} via {verdict.layers_run}",
    )
    if unavailable:
        checks.skip(
            "a contextual disclosure with no identifier blocks via policy-linter",
            unavailable,
        )
        checks.skip(
            "ordinary file description approves, all four layers ran", unavailable
        )
        return
    verdict = airlock.evaluate(ACQUISITION_TEXT)
    checks.check(
        "a contextual disclosure with no identifier blocks via policy-linter",
        verdict.decision == "revise" and "policy-linter" in verdict.layers_run,
        f"{verdict.decision} via {verdict.layers_run}",
    )
    verdict = airlock.evaluate(CLEAN_POLICY_TEXT)
    checks.check(
        "ordinary file description approves, all four layers ran",
        verdict.decision == "approve"
        and verdict.layers_run
        == ["secrets", "pii-patterns", "pii-detector", "policy-linter"],
        f"{verdict.decision} via {verdict.layers_run}",
    )


def _guard_evaluate_fail_closed(checks: Checks) -> None:
    original_pii_model = airlock.PII_DETECTOR_MODEL
    airlock.PII_DETECTOR_MODEL = "LiquidAI/does-not-exist-airlock-test-xyz"
    airlock._load_pii_detector.cache_clear()
    try:
        verdict = airlock.evaluate(CLEAN_PII_TEXT)
        checks.check(
            "detector unavailable blocks",
            verdict.decision == "block",
            f"{verdict.decision}: {'; '.join(verdict.concerns)}",
        )
    finally:
        airlock.PII_DETECTOR_MODEL = original_pii_model
        airlock._load_pii_detector.cache_clear()
    original_scan_pii_model = airlock.scan_pii_model
    original_linter_model = airlock.POLICY_LINTER_MODEL
    airlock.scan_pii_model = lambda text: []
    airlock.POLICY_LINTER_MODEL = "LiquidAI/does-not-exist-airlock-test-xyz"
    airlock._load_policy_linter.cache_clear()
    try:
        verdict = airlock.evaluate(CLEAN_POLICY_TEXT)
        checks.check(
            "linter unavailable blocks",
            verdict.decision == "block",
            f"{verdict.decision}: {'; '.join(verdict.concerns)}",
        )
    finally:
        airlock.scan_pii_model = original_scan_pii_model
        airlock.POLICY_LINTER_MODEL = original_linter_model
        airlock._load_policy_linter.cache_clear()


def _guard_evaluate_default_threshold(checks: Checks) -> None:
    original_scan_pii_model = airlock.scan_pii_model
    original_scan_policy = airlock.scan_policy
    original_threshold = airlock.POLICY_LINTER_THRESHOLD
    seen: dict[str, object] = {}
    airlock.scan_pii_model = lambda text: []
    airlock.scan_policy = lambda text, threshold=None: (
        seen.__setitem__("threshold", threshold),
        [],
    )[1]
    airlock.POLICY_LINTER_THRESHOLD = 0.13579
    try:
        airlock.evaluate(CLEAN_POLICY_TEXT)
        checks.check(
            "bare call passes the threshold current at call time",
            seen.get("threshold") == 0.13579,
            f"scan_policy received {seen.get('threshold')!r}",
        )
    finally:
        airlock.scan_pii_model = original_scan_pii_model
        airlock.scan_policy = original_scan_policy
        airlock.POLICY_LINTER_THRESHOLD = original_threshold


def _guard_chunk_text_step_guard(checks: Checks) -> None:
    """The one-line guard the re-reviewer flagged (fix round 1): _chunk_text
    never asserted step > 0. Current constants (500-200, 1800-400) are safe,
    but a future edit setting overlap >= window would make pos stop
    advancing (overlap == window) or walk backward (overlap > window),
    hanging or looping forever rather than raising. No model needed.
    """
    raised = False
    try:
        airlock._chunk_text("x" * 10, window=5, overlap=5)
    except AssertionError:
        raised = True
    checks.check("overlap == window raises, does not hang", raised)
    raised = False
    try:
        airlock._chunk_text("x" * 10, window=5, overlap=8)
    except AssertionError:
        raised = True
    checks.check("overlap > window raises, does not hang", raised)


def _guard_dense_non_ascii_truncation(checks: Checks, unavailable: str) -> None:
    if unavailable:
        checks.skip(
            "PII detector: a value past a single dense-CJK window is still found",
            unavailable,
        )
        checks.skip(
            "policy linter: a disclosure past a single dense-CJK window is still found",
            unavailable,
        )
        return
    rules = {f["rule"] for f in airlock.scan_pii_model(DENSE_NON_ASCII_PII_TEXT)}
    checks.check(
        "PII detector: a value past a single dense-CJK window is still found",
        any((r.split(".")[0] == "identity" for r in rules)),
        ",".join(sorted(rules)) or "no findings, truncated away",
    )
    rules = {f["rule"] for f in airlock.scan_policy(DENSE_NON_ASCII_POLICY_TEXT)}
    checks.check(
        "policy linter: a disclosure past a single dense-CJK window is still found",
        "rule0" in rules,
        ",".join(sorted(rules)) or "no findings, truncated away",
    )


# Doctor with real encoders and Ollama


def test_doctor() -> Checks:
    """Check real encoder probes and worker readiness in doctor output."""
    with _test_scope() as checks:
        _doctor_encoders(checks, _guard_models_available())
        return checks.finish(7)


def _doctor_encoders(checks: Checks, unavailable: str) -> None:
    try:
        airlock.ollama_models()
        ollama_unavailable = ""
    except RuntimeError as exc:
        ollama_unavailable = str(exc)
    reason = unavailable or ollama_unavailable
    labels = (
        "torch/transformers importable",
        "device",
        "PII detector loadable",
        "policy linter loadable",
        "PII detector probe",
        "policy linter probe",
    )
    if reason:
        checks.skip(
            "cmd_doctor returns 0 with the real worker and encoders available", reason
        )
        for label in labels:
            checks.skip(f"cmd_doctor prints '{label}'", reason)
        return
    tmp = Path(checks.directory(prefix="doctor-smoke-"))
    (tmp / "note.txt").write_text("hello\n")
    args = argparse.Namespace(**{**airlock.CLI_DEFAULTS, "root": tmp})
    with airlock.console.capture() as capture:
        code = airlock.cmd_doctor(args)
    printed = capture.get()
    checks.check(
        "cmd_doctor returns 0 with the real worker and encoders available",
        code == 0,
        str(code),
    )
    for label in labels:
        checks.check(
            f"cmd_doctor prints '{label}'",
            label in printed,
            "missing" if label not in printed else "present",
        )


# Real-worker PDF workflow


def test_tax() -> Checks:
    """Real-worker PDF workflow; return evidence or raise on failure."""
    with _test_scope() as checks:
        root = checks.directory(prefix="airlock-tax-") / "tax"
        _tax_build_docs(root)
        reason = _tax_worker_unavailable_reason(airlock.CLI_DEFAULTS["model"])
        if reason:
            _tax_skip_remaining(checks, 0, reason)
        else:
            asyncio.run(_tax_run(checks, root))
        return checks.finish(8)


def _tax_args(root: Path):
    return _server_args(root, allow_writes=True)


IDENTIFIERS = {
    "SSN": SSN,
    "SSN unformatted": "912847731",
    "taxpayer surname": "Whitfield",
    "home address": "1820 Larkspur Lane",
    "employer EIN": "47-6183920",
    "payer TIN": "31-0854434",
    "bank account": "4419-882301",
}

WAGES = 94250.0 + 8400.0

INTEREST = 317.42

TOTAL_INCOME = WAGES + INTEREST

WITHHELD = 11910.0 + 612.0

TAX_E2E_CHECKS = [
    "airlock_open discloses no filename",
    f"line 1a = {WAGES:,.2f}",
    f"line 2b = {INTEREST:,.2f}",
    f"line 9 = {TOTAL_INCOME:,.2f}",
    f"line 25a = {WITHHELD:,.2f}",
    "the form carries the taxpayer SSN",
    "the form carries the taxpayer name",
    "no identifier reached the caller",
]


def _tax_skip_remaining(checks: Checks, done: int, reason: str) -> None:
    """skip() every TAX_E2E_CHECKS entry from index `done` onward."""
    for name in TAX_E2E_CHECKS[done:]:
        checks.skip(name, reason)


def _tax_has_model(installed: list[str], tag: str) -> bool:
    """Same case/':latest'-insensitive match as cmd_doctor's own has()
    (airlock.py), reimplemented rather than imported: that one prints
    through Rich's console, this needs a plain bool.
    """
    names = {m.lower() for m in installed}
    want = tag.lower()
    return (
        want in names
        or f"{want}:latest" in names
        or want.removesuffix(":latest") in names
    )


def _tax_worker_unavailable_reason(model: str) -> str:
    try:
        installed = airlock.ollama_models()
    except RuntimeError as exc:
        return str(exc)
    if not _tax_has_model(installed, model):
        return f"{model} not installed"
    try:
        probe = airlock.ollama_chat(
            model,
            "Reply with the action 'answer' and a one word answer.",
            airlock.WORKER_SCHEMA,
        )
    except RuntimeError as exc:
        return f"worker probe failed: {exc}"
    if not (isinstance(probe, dict) and "action" in probe):
        return f"{model} does not honour the JSON schema"
    return ""


def _tax_build_docs(root: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    def page(path: Path, title: str, rows: list[tuple[str, str]]) -> None:
        c = canvas.Canvas(str(path), pagesize=letter)
        c.setFont("Helvetica-Bold", 13)
        c.drawString(72, 720, title)
        c.setFont("Helvetica", 10)
        y = 694
        for label, value in rows:
            c.drawString(72, y, label)
            c.drawString(320, y, value)
            y -= 17
        c.showPage()
        c.save()

    root.mkdir(parents=True, exist_ok=True)
    (root / "0_1040.md").write_text(
        "# Form 1040 (2025)\n\nName: \nSSN: \nAddress: \n\n1a: \n2b: \n9: \n25a: \n"
    )
    page(
        root / "1_W2_Acme.pdf",
        "Form W-2  2025",
        [
            ("a Employee SSN", SSN),
            ("b Employer EIN", "47-6183920"),
            ("e Employee name", "Dana R. Whitfield"),
            ("f Employee address", "1820 Larkspur Lane, Apt 6C, Dayton OH 45409"),
            ("1 Wages, tips, other compensation", "94250.00"),
            ("2 Federal income tax withheld", "11910.00"),
        ],
    )
    page(
        root / "2_W2_Northwind.pdf",
        "Form W-2  2025",
        [
            ("a Employee SSN", SSN),
            ("e Employee name", "Dana R. Whitfield"),
            ("1 Wages, tips, other compensation", "8400.00"),
            ("2 Federal income tax withheld", "612.00"),
        ],
    )
    page(
        root / "3_1099-INT.pdf",
        "Form 1099-INT  2025",
        [
            ("Recipient SSN", SSN),
            ("Payer TIN", "31-0854434"),
            ("Account number", "4419-882301"),
            ("1 Interest income", "317.42"),
        ],
    )


def _tax_num(text: str) -> float | None:
    import re as _re

    candidates = _re.findall(
        "-?[\\d,]*\\.\\d+|-?[\\d,]*\\d", str(text).replace("$", "")
    )
    if not candidates:
        return None
    decimals = [c for c in candidates if "." in c]
    pick = (decimals or candidates)[-1]
    try:
        return float(pick.replace(",", ""))
    except ValueError:
        return None


async def _tax_run(checks: Checks, root: Path) -> None:
    from mcp import Client

    server = airlock.build_server(_tax_args(root))
    transcript: list[str] = []
    raw: list[tuple[str, str]] = []

    def record(result) -> dict:
        body = result.structured_content or {}
        transcript.append(json.dumps(body))
        return body

    async with Client(server) as client:

        async def extract(label: str, jobs: list[dict]) -> dict:
            body = record(
                await client.call_tool(
                    "airlock_extract", {"session": session, "jobs": jobs}
                )
            )
            for r in body.get("results", []):
                shown = r.get("value", r.get("field", r.get("detail", "")))
                raw.append(
                    (
                        f"{label[:22]} job {r.get('job')}",
                        f"{r.get('status')}: {str(shown)[:60]}",
                    )
                )
            return body

        opened = record(
            await client.call_tool(
                "airlock_open",
                {"objective": "Complete a 2025 Form 1040 from these documents."},
            )
        )
        session = opened.get("session")
        checks.check(
            "airlock_open discloses no filename",
            not any((n in json.dumps(opened) for n in ("W2", "1099", "1040"))),
            "names leaked"
            if any((n in json.dumps(opened) for n in ("W2", "1099")))
            else "clean",
        )
        got = await extract(
            "wages, withholding and interest",
            [
                {"document": 1, "extract": "wages in box 1", "as": "number"},
                {"document": 2, "extract": "wages in box 1", "as": "number"},
                {
                    "document": 1,
                    "extract": "federal income tax withheld in box 2",
                    "as": "number",
                },
                {
                    "document": 2,
                    "extract": "federal income tax withheld in box 2",
                    "as": "number",
                },
                {
                    "document": 3,
                    "extract": "the interest income amount",
                    "as": "number",
                },
            ],
        )
        values = {
            r["job"]: _tax_num(r.get("value"))
            for r in got.get("results", [])
            if r.get("status") == "ok"
        }
        wages = sum((v for j, v in values.items() if j in (0, 1) and v is not None))
        withheld = sum((v for j, v in values.items() if j in (2, 3) and v is not None))
        interest = values.get(4) or 0.0
        await extract(
            "identifying fields, values never returned",
            [
                {
                    "document": 1,
                    "extract": "the employee name",
                    "as": "line",
                    "into": 0,
                    "field": "Name",
                },
                {
                    "document": 1,
                    "extract": "the nine digit employee social security number, digits and hyphens only",
                    "as": "digits",
                    "into": 0,
                    "field": "SSN",
                },
                {
                    "document": 1,
                    "extract": "the employee street address",
                    "as": "line",
                    "into": 0,
                    "field": "Address",
                },
            ],
        )
        await extract(
            "computed lines",
            [
                {"into": 0, "field": "1a", "value": f"{wages:.2f}"},
                {"into": 0, "field": "2b", "value": f"{interest:.2f}"},
                {"into": 0, "field": "9", "value": f"{wages + interest:.2f}"},
                {"into": 0, "field": "25a", "value": f"{withheld:.2f}"},
            ],
        )
    filled = (root / "0_1040.md").read_text()
    for label, want in [
        ("1a", WAGES),
        ("2b", INTEREST),
        ("9", TOTAL_INCOME),
        ("25a", WITHHELD),
    ]:
        line = next(
            (ln for ln in filled.splitlines() if ln.strip().startswith(f"{label}:")), ""
        )
        checks.check(
            f"line {label} = {want:,.2f}",
            _tax_num(line.split(":", 1)[-1]) == want,
            line.strip() or "missing",
        )
    checks.check(
        "the form carries the taxpayer SSN",
        SSN in filled,
        "a return without it is useless",
    )
    checks.check("the form carries the taxpayer name", "Whitfield" in filled)
    checks.diagnostics.append("what the worker actually returned:")
    for name, value in raw:
        checks.diagnostics.append(f"    {name:34} {value}")
    checks.diagnostics.append("the form as written:")
    for line in filled.splitlines():
        if line.strip():
            checks.diagnostics.append(f"    {line}")
    blob = " ".join(transcript)
    leaked = [k for k, v in IDENTIFIERS.items() if v in blob]
    filled_any = SSN in filled
    if not filled_any:
        checks.skip(
            "no identifier reached the caller",
            "the form was never filled, so this proves nothing",
        )
        checks.diagnostics.append(
            "the worker never filled the form; containment is unproven"
        )
    else:
        checks.check(
            "no identifier reached the caller", not leaked, ", ".join(leaked) or "clean"
        )
    checks.diagnostics.append(blob)


def test_worker() -> Checks:
    """Real Ollama disclosure checks; unavailable prerequisites remain explicit."""
    with _test_scope() as checks:
        asyncio.run(_worker_disclosure(checks, _workspace(checks)))
        return checks.finish(len(WORKER_CHECKS))


# Public corpus records and label policies


@dataclass
class Record:
    corpus: str
    record_id: str
    text: str
    gold: str  # "block" or "approve"
    blocking: list[dict[str, str]] = field(default_factory=list)  # [{"label","value"}]
    all_labels: set[str] = field(default_factory=set)
    notes: str = ""


@dataclass
class Decision:
    record: Record
    predicted: str
    layer: str
    latency_ms: float
    error: str = ""


def _check_coverage(
    corpus: str, seen: set[str], block: dict[str, str], exclude: dict[str, str]
) -> None:
    """Every label the sample actually contains must have a mapping decision.

    A label with no entry is neither obviously safe to ignore nor obviously
    identifying, so silently treating it as "approve" would understate
    recall without anyone deciding that on purpose.
    """
    unknown = seen - set(block) - set(exclude)
    assert not unknown, (
        f"{corpus}: unmapped labels {sorted(unknown)}. Add each to its BLOCK "
        "or EXCLUDE dict with a one-line reason before running."
    )


AI4PRIVACY_BLOCK: dict[str, str] = {
    "EMAIL": "email address, direct identifier",
    "TEL": "phone number, direct identifier",
    "SOCIALNUMBER": "national id",
    "IDCARD": "national id",
    "PASSPORT": "national id / travel document",
    "DRIVERLICENSE": "national id",
    "BOD": "date of birth, kept unlike generic dates",
    "GIVENNAME1": "person name",
    "GIVENNAME2": "person name",
    "LASTNAME1": "person name",
    "LASTNAME2": "person name",
    "LASTNAME3": "person name",
    "STREET": "address component",
    "BUILDING": "address component",
    "SECADDRESS": "address component",
    "POSTCODE": "address component",
    "PASS": "password, a credential",
    "IP": "network identifier, akin to an account number for a device",
    "GEOCOORD": "precise geocoordinate, address-equivalent identifier",
}


AI4PRIVACY_EXCLUDE: dict[str, str] = {
    "TIME": "generic time of day; blocking a bare timestamp would be wrong",
    "DATE": "generic date, not a date of birth",
    "USERNAME": "handle/alias, not a real-world direct identifier",
    "STATE": "generic geography, too coarse alone to identify",
    "CITY": "generic geography, too coarse alone to identify",
    "COUNTRY": "generic geography, too coarse alone to identify",
    "SEX": "generic demographic attribute, not a direct identifier",
    "TITLE": "honorific (Mr./Dr.), not identifying",
    "CARDISSUER": "card brand name (e.g. Visa), not an account number",
}


def load_ai4privacy(sample_n: int = 250, seed: int = DEFAULT_SEED) -> list[Record]:
    if sample_n <= 0:
        raise ValueError("sample_n must be positive")
    from datasets import load_dataset

    ds = load_dataset("ai4privacy/pii-masking-300k", split="validation")
    ds = ds.filter(lambda r: r["language"] == "English")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    seen_labels: set[str] = set()
    for i, row in enumerate(ds):
        spans = row["privacy_mask"]
        labels = {m["label"] for m in spans}
        seen_labels |= labels
        blocking = [
            {"label": m["label"], "value": m["value"]}
            for m in spans
            if m["label"] in AI4PRIVACY_BLOCK
        ]
        records.append(
            Record(
                corpus="ai4privacy",
                record_id=row.get("id") or f"ai4privacy-{i}",
                text=row["source_text"],
                gold="block" if blocking else "approve",
                blocking=blocking,
                all_labels=labels,
            )
        )
    _check_coverage("ai4privacy", seen_labels, AI4PRIVACY_BLOCK, AI4PRIVACY_EXCLUDE)
    return records


NEMOTRON_BLOCK: dict[str, str] = {
    "account_number": "account/card number",
    "api_key": "credential",
    "bank_routing_number": "account/card number",
    "biometric_identifier": "direct identifier",
    "blood_type": "medical",
    "certificate_license_number": "national id / license",
    "coordinate": "precise geocoordinate, address-equivalent identifier",
    "credit_debit_card": "account/card number",
    "customer_id": "direct identifier",
    "cvv": "account/card number",
    "date_of_birth": "date of birth, kept unlike generic dates",
    "device_identifier": "direct identifier",
    "email": "email address, direct identifier",
    "employee_id": "direct identifier",
    "fax_number": "phone number, direct identifier",
    "first_name": "person name",
    "health_plan_beneficiary_number": "medical",
    "http_cookie": "session credential",
    "ipv4": "network identifier",
    "ipv6": "network identifier",
    "last_name": "person name",
    "license_plate": "vehicle identifier",
    "mac_address": "device identifier",
    "medical_record_number": "medical",
    "national_id": "national id",
    "password": "credential",
    "phone_number": "phone number, direct identifier",
    "pin": "credential",
    "postcode": "address component",
    "ssn": "national id",
    "street_address": "address component",
    "swift_bic": "account/card number",
    "tax_id": "national id",
    "unique_id": "direct identifier",
    "vehicle_identifier": "vehicle identifier",
}


NEMOTRON_EXCLUDE: dict[str, str] = {
    "age": "generic demographic attribute, not a direct identifier",
    "city": "generic geography, too coarse alone to identify",
    "company_name": "generic organisation name",
    "country": "generic geography, too coarse alone to identify",
    "county": "generic geography, too coarse alone to identify",
    "date": "generic date, not a date of birth",
    "date_time": "generic timestamp",
    "education_level": "generic attribute, not identifying alone",
    "employment_status": "generic attribute, not identifying alone",
    "gender": "sensitive demographic attribute expressed as a bare word; excluded for the same reason as ai4privacy's SEX",
    "language": "generic attribute (spoken language), not identifying",
    "occupation": "generic attribute, not identifying alone",
    "political_view": "sensitive attribute expressed as a bare word; not in airlock's PII scope (identifiers + medical), excluded for consistency with gender",
    "race_ethnicity": "sensitive attribute expressed as a bare word; same reasoning as political_view",
    "religious_belief": "sensitive attribute expressed as a bare word; same reasoning as political_view",
    "sexuality": "sensitive attribute expressed as a bare word; same reasoning as political_view",
    "state": "generic geography, too coarse alone to identify",
    "time": "generic time of day; blocking a bare timestamp would be wrong",
    "url": "generic URL",
    "user_name": "handle/alias, not a real-world direct identifier",
}


def load_nemotron(sample_n: int = 250, seed: int = DEFAULT_SEED) -> list[Record]:
    if sample_n <= 0:
        raise ValueError("sample_n must be positive")
    from datasets import load_dataset

    ds = load_dataset("nvidia/Nemotron-PII", split="test")
    ds = ds.filter(lambda r: r["locale"] == "us")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    seen_labels: set[str] = set()
    for i, row in enumerate(ds):
        spans = ast.literal_eval(row["spans"])
        labels = {s["label"] for s in spans}
        seen_labels |= labels
        blocking = [
            {"label": s["label"], "value": s["text"]}
            for s in spans
            if s["label"] in NEMOTRON_BLOCK
        ]
        records.append(
            Record(
                corpus="nemotron",
                record_id=row.get("uid") or f"nemotron-{i}",
                text=row["text"],
                gold="block" if blocking else "approve",
                blocking=blocking,
                all_labels=labels,
            )
        )
    _check_coverage("nemotron", seen_labels, NEMOTRON_BLOCK, NEMOTRON_EXCLUDE)
    return records


GRETEL_BLOCK: dict[str, str] = {
    "account_pin": "credential",
    "api_key": "credential",
    "bank_routing_number": "account/card number",
    "bban": "account/card number",
    "credit_card_number": "account/card number",
    "credit_card_security_code": "account/card number",
    "customer_id": "direct identifier",
    "date_of_birth": "date of birth, kept unlike generic dates",
    "driver_license_number": "national id",
    "email": "email address, direct identifier",
    "employee_id": "direct identifier",
    "first_name": "person name",
    "iban": "account/card number",
    "ipv4": "network identifier",
    "ipv6": "network identifier",
    "last_name": "person name",
    "local_latlng": "precise geocoordinate, address-equivalent identifier",
    "name": "person name",
    "passport_number": "national id",
    "password": "credential",
    "phone_number": "phone number, direct identifier",
    "ssn": "national id",
    "street_address": "address component",
    "swift_bic_code": "account/card number",
}


GRETEL_EXCLUDE: dict[str, str] = {
    "company": "generic organisation name",
    "date": "generic date, not a date of birth",
    "date_time": "generic timestamp",
    "time": "generic time of day; blocking a bare timestamp would be wrong",
    "user_name": "handle/alias, not a real-world direct identifier",
}


def load_gretel(sample_n: int = 250, seed: int = DEFAULT_SEED) -> list[Record]:
    if sample_n <= 0:
        raise ValueError("sample_n must be positive")
    from datasets import load_dataset

    ds = load_dataset("gretelai/synthetic_pii_finance_multilingual", split="test")
    ds = ds.filter(lambda r: r["language"] == "English")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    seen_labels: set[str] = set()
    for i, row in enumerate(ds):
        text = row["generated_text"]
        spans = json.loads(row["pii_spans"])
        labels = {s["label"] for s in spans}
        seen_labels |= labels
        blocking = [
            {"label": s["label"], "value": text[s["start"] : s["end"]]}
            for s in spans
            if s["label"] in GRETEL_BLOCK
        ]
        records.append(
            Record(
                corpus="gretel",
                record_id=f"gretel-{row.get('index', i)}",
                text=text,
                gold="block" if blocking else "approve",
                blocking=blocking,
                all_labels=labels,
            )
        )
    _check_coverage("gretel", seen_labels, GRETEL_BLOCK, GRETEL_EXCLUDE)
    return records


def load_tab(sample_n: int = 250, seed: int = DEFAULT_SEED) -> list[Record]:
    if sample_n <= 0:
        raise ValueError("sample_n must be positive")
    from datasets import load_dataset

    ds = load_dataset("mattmdjaga/text-anonymization-benchmark-val-test", split="test")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    for row in ds:
        blocking: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        for annotator in row["quality_checked"]:
            for e in row["annotations"][annotator]["entity_mentions"]:
                if e["identifier_type"] != "DIRECT":
                    continue
                if e["entity_mention_id"] in seen_ids:
                    continue
                seen_ids.add(e["entity_mention_id"])
                blocking.append({"label": "direct_identifier", "value": e["span_text"]})
        records.append(
            Record(
                corpus="tab",
                record_id=row["doc_id"],
                text=row["text"],
                gold="block" if blocking else "approve",
                blocking=blocking,
            )
        )
    return records


def test_measurements() -> Checks:
    """Check metric accounting, seeded fixtures and failure handling without models."""
    assertions = TestCase()
    with _test_scope() as checks:
        first = build_dataset()
        checks.check("synthetic generation is repeatable", first == build_dataset())
        checks.check(
            "another seed changes generated credentials",
            first != build_dataset(DEFAULT_SEED + 1),
        )
        checks.check(
            "synthetic examples retain their label context",
            all(r.notes and (r.all_labels or r.gold == "approve") for r in first),
        )
        positive = Record("control", "positive", "SSN 912-84-7731", "block")
        negative = Record("control", "negative", "ordinary prose", "approve")
        decisions = [
            Decision(positive, "block", "pii-patterns", 1),
            Decision(negative, "block", "pii-detector", 1),
            Decision(positive, "approve", "policy-linter", 1),
            Decision(negative, "approve", "policy-linter", 1),
        ]
        summary = summarize_decisions(decisions)
        checks.check(
            "confusion matrix preserves all four outcomes",
            all(summary[k] == 1 for k in ("tp", "fp", "fn", "tn")),
        )
        checks.check(
            "precision, recall, f1 and false blocking use the right denominators",
            all(
                summary[k] == 0.5
                for k in ("precision", "recall", "f1", "false_block_rate")
            ),
        )
        checks.check(
            "only true detections contribute to layer attribution",
            summary["layer_counts"] == {"pii-patterns": 1},
        )
        for failure in (RuntimeError("unavailable"), RuntimeError()):
            with patch.object(airlock, "evaluate", side_effect=failure):
                errors = measure_guard([positive])
            summary = summarize_decisions(errors)
            checks.check(
                "a guard exception earns no detection credit",
                summary["errors"] == 1
                and summary["tp"] == 0
                and summary["recall"] is None,
            )
        with patch.object(
            airlock,
            "scan_pii_model",
            side_effect=airlock.GuardModelUnavailable("test loader failure"),
        ):
            errors = measure_guard([negative])
        checks.check(
            "a fail-closed verdict is an error, not a false detection",
            errors[0].error and summarize_decisions(errors)["fp"] == 0,
        )
        real = measure_guard([positive])[0]
        checks.check(
            "real deterministic detection has its source, layer and latency",
            real.record is positive
            and real.predicted == "block"
            and real.layer == "pii-patterns"
            and real.latency_ms >= 0
            and not real.error,
        )
        checks.check(
            "no negative examples means no measured false-block rate",
            summarize_decisions([real])["false_block_rate"] is None,
        )
        for fn in (measure_guard, summarize_decisions):
            with assertions.assertRaises(ValueError):
                fn([])
            checks.check(f"{fn.__name__} rejects empty evidence", True)
        with assertions.assertRaises(ValueError):
            measure_guard([Record("control", "invalid", "text", "unknown")])
        checks.check("unknown gold labels cannot silently become safe", True)
        for name, block, exclude in (
            ("ai4privacy", AI4PRIVACY_BLOCK, AI4PRIVACY_EXCLUDE),
            ("nemotron", NEMOTRON_BLOCK, NEMOTRON_EXCLUDE),
            ("gretel", GRETEL_BLOCK, GRETEL_EXCLUDE),
        ):
            checks.check(
                f"{name} label decisions are unambiguous",
                not block.keys() & exclude.keys(),
            )
            with assertions.assertRaises(AssertionError):
                _check_coverage(name, {"unmapped"}, block, exclude)
            checks.check(f"{name} refuses unmapped labels", True)
        for fn, kwargs in (
            (measure_reassembly_floor, {"trials": 0}),
            (measure_reassembly_cost, {"reps": 0}),
            (load_ai4privacy, {"sample_n": 0}),
            (load_nemotron, {"sample_n": 0}),
            (load_gretel, {"sample_n": 0}),
            (load_tab, {"sample_n": 0}),
        ):
            with assertions.assertRaises(ValueError):
                fn(**kwargs)
            checks.check(f"{fn.__name__} rejects an empty sample", True)
        with assertions.assertRaises(ValueError):
            random_digit_sources(random.Random(0), 1, 11)
        checks.check("an impossible source count is refused instead of looping", True)
        with assertions.assertRaises(AssertionError):
            Checks().finish(1)
        checks.check("missing test collection cannot pass", True)
        failed = Checks()
        failed.check("deliberate failure", False, "control")
        with assertions.assertRaises(AssertionError):
            failed.finish(1)
        checks.check("a failed assertion cannot return a passing result", True)
        return checks.finish(29)


def measure_guard(records: list[Record]) -> list[Decision]:
    """Score the real guard; retain source text, labels, timing and errors locally.

    Invalid gold labels raise ValueError. Guard failures are recorded as errors,
    separately from detections, even though both prevent disclosure.
    """
    if not records or any(r.gold not in {"block", "approve"} for r in records):
        raise ValueError("records must be nonempty and labelled block or approve")
    decisions = []
    for record in records:
        started = time.perf_counter()
        try:
            verdict = airlock.evaluate(record.text)
        except Exception as exc:
            predicted, layer, error = "block", "error", f"{type(exc).__name__}: {exc}"
        else:
            predicted = "approve" if verdict.approved else "block"
            layer = verdict.layers_run[-1] if verdict.layers_run else "none"
            error = "; ".join(verdict.concerns) if verdict.decision == "block" else ""
            if verdict.decision == "block" and not error:
                error = "guard could not evaluate"
        decisions.append(
            Decision(
                record, predicted, layer, (time.perf_counter() - started) * 1000, error
            )
        )
    return decisions


def summarize_decisions(decisions: list[Decision]) -> dict:
    """Per-record confusion counts; unavailable evaluations do not earn credit.

    Rates with no supporting denominator are None. Report per corpus first:
    a sample with no safe records cannot measure false blocking.
    """
    if not decisions:
        raise ValueError("decisions must be nonempty")
    if any(
        d.record.gold not in {"block", "approve"}
        or d.predicted not in {"block", "approve"}
        for d in decisions
    ):
        raise ValueError("gold and predicted labels must be block or approve")
    scored = [d for d in decisions if not d.error]
    counts = Counter((d.record.gold, d.predicted) for d in scored)
    tp, fp = counts["block", "block"], counts["approve", "block"]
    fn, tn = counts["block", "approve"], counts["approve", "approve"]
    return {
        "n": len(decisions),
        "errors": len(decisions) - len(scored),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "false_block_rate": fp / (fp + tn) if fp + tn else None,
        "weak_negatives": tn + fp < 20,
        "layer_counts": dict(
            Counter(d.layer for d in scored if d.record.gold == d.predicted == "block")
        ),
    }


# Synthetic data: examples are deliberately easier than the public corpora.


def build_dataset(seed: int = DEFAULT_SEED) -> list[Record]:
    """Generate 320 labelled examples, including credentials, without writing them."""
    categories = _synthetic_categories(random.Random(seed))
    records = [
        Record(
            f"synthetic:{category}",
            f"{category}-{gold}-{i:02d}",
            text,
            gold,
            all_labels=set(findings),
            notes=notes,
        )
        for category, groups in categories.items()
        for gold, items in groups.items()
        for i, (text, findings, notes) in enumerate(items, 1)
    ]
    assert len(records) == 320
    assert len({r.record_id for r in records}) == 320, "duplicate ids"
    assert len({r.text for r in records}) == 320, "duplicate texts"
    for category in categories:
        for gold in ("block", "approve"):
            assert (
                sum(
                    r.corpus == f"synthetic:{category}" and r.gold == gold
                    for r in records
                )
                == 20
            )
    return records


HEXLOWER = string.digits + "abcdef"
SYNTHETIC_BASE64 = ALNUM + "+/"


def _shaped(rng: random.Random, prefix: str, length: int, alphabet: str = ALNUM) -> str:
    """A syntactically valid, entirely fake credential. Seeded so measurements can be repeated."""
    return prefix + "".join(rng.choice(alphabet) for _ in range(length))


def _password(rng: random.Random, length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _jwt(rng: random.Random) -> str:
    """Three base64url-shaped segments. Does not need to decode: the guard
    layers under test match shape, not JWT validity."""
    return ".".join(_shaped(rng, "", n, SYNTHETIC_BASE64) for n in (36, 32, 24))


def _basic_auth(rng: random.Random) -> str:
    return base64.b64encode(f"admin:{_password(rng, 12)}".encode()).decode()


def _pem_header(kind: str) -> str:
    """Assembled from two literals, neither of which alone spells out a
    complete PEM private-key header, so no single string in this source file
    matches that shape. The GENERATED record (this function's return value,
    concatenated with a random body at the call site) still contains the
    real header at runtime, which is what scan_secrets's private_key_block
    pattern needs to see. Same reasoning as the generated credentials
    elsewhere in this file: a fixed literal close
    enough to a real secret shape is what got this repo's push rejected by
    GitHub secret scanning once (see CLAUDE.md)."""
    return "-----BEGIN " + kind + " PRIVATE KEY-----"


def _slack_webhook(rng: random.Random) -> str:
    host = "hooks.slack.com"
    team = _shaped(rng, "T", 8, string.ascii_uppercase + string.digits)
    bot = _shaped(rng, "B", 8, string.ascii_uppercase + string.digits)
    token = _shaped(rng, "", 24, string.ascii_uppercase + string.digits)
    return f"https://{host}/services/{team}/{bot}/{token}"


def _credentials_block(rng: random.Random) -> list[tuple[str, list[str], str]]:
    return [
        (
            f"Use the key {_shaped(rng, 'sk-proj-', 32)} for the staging call.",
            ["secret"],
            "openai-style key",
        ),
        # AWS's own published documentation pair, both halves. Allowlisted by
        # scanners precisely because it is public and inert. See CLAUDE.md.
        (
            f"AWS creds are AKIAIOSFODNN7EXAMPLE and {_shaped(random.Random(0), '', 40, SYNTHETIC_BASE64)}.",
            ["secret"],
            "aws pair",
        ),
        (
            f"The database password is {_password(rng, 14)} and the user is svc_reporting.",
            ["secret"],
            "password in prose",
        ),
        (
            f"{_pem_header('RSA')}{_shaped(rng, '', 28, SYNTHETIC_BASE64)}",
            ["secret"],
            "private key header",
        ),
        (
            f"Set GITHUB_TOKEN={_shaped(rng, 'ghp_', 36)} before running.",
            ["secret"],
            "github pat",
        ),
        (f"Slack webhook: {_slack_webhook(rng)}", ["secret", "url"], "webhook url"),
        (
            f"The admin login is root with password {_password(rng, 15)}.",
            ["secret"],
            "credential pair",
        ),
        (
            f"Stripe secret key {_shaped(rng, 'sk_live_', 24)}.",
            ["secret"],
            "stripe live key",
        ),
        (f"Bearer {_jwt(rng)}", ["secret"], "jwt"),
        (
            f"SSH into the box with the key at ~/.ssh/id_rsa, passphrase {_shaped(rng, '', 16)}.",
            ["secret"],
            "passphrase",
        ),
        (
            f"Connection string: postgres://admin:{_password(rng, 12)}@db.example.net:5432/prod",
            ["secret"],
            "dsn with password",
        ),
        (
            f"The shared account uses password {_password(rng, 20)} across all three environments.",
            ["secret"],
            "shared password",
        ),
        (
            f"Twilio auth token {_shaped(rng, '', 32, HEXLOWER)}.",
            ["secret"],
            "hex token",
        ),
        (
            f"Set the env var API_SECRET={_shaped(rng, '', 32)}.",
            ["secret"],
            "generic secret",
        ),
        (
            f"Google service account private_key_id {_shaped(rng, '', 32, HEXLOWER)}.",
            ["secret"],
            "gcp key id",
        ),
        (
            f"Rotate this one manually: npm token {_shaped(rng, 'npm_', 36)}.",
            ["secret"],
            "npm token",
        ),
        (
            f"The signing secret is {_shaped(rng, 'whsec_', 28)}.",
            ["secret"],
            "webhook signing secret",
        ),
        (
            f"Basic auth header uses {_basic_auth(rng)} for the internal API.",
            ["secret"],
            "base64 basic auth",
        ),
        (f"Vault token {_shaped(rng, 'hvs.', 40)}.", ["secret"], "vault token"),
        (
            f"Encryption key for the backups is {_shaped(rng, '', 32, HEXLOWER)}.",
            ["secret"],
            "encryption key",
        ),
    ]


def _benign_business_block(rng: random.Random) -> list[tuple[str, list[str], str]]:
    return [
        (
            "Great call today. Looping in our champion, Dale Kirchner, dale.kirchner@example.com.",
            ["person", "email"],
            "sales prose hiding contact",
        ),
        (
            f"Status is green. One blocker: the test account password is {_password(rng, 13)}.",
            ["secret"],
            "status update hiding credential",
        ),
        (
            "Renewal looks good. Their AP contact is 555-0192 if billing has questions.",
            ["phone"],
            "renewal note hiding phone",
        ),
        (
            "Pipeline update attached. Ship the swag to 412 Marlowe Street, Austin TX 78704.",
            ["address"],
            "pipeline note hiding address",
        ),
        (
            "Standard quarterly review. Wire the rebate to account 7719204483.",
            ["account_number"],
            "review hiding account",
        ),
        (
            f"Nothing blocking. FYI the staging key is {_shaped(rng, 'sk-proj-', 22)}.",
            ["secret"],
            "buried key",
        ),
        (
            "Customer is happy. Their CTO Ravi Balasubramanian gave us the reference.",
            ["person"],
            "reference hiding name",
        ),
        (
            "Onboarding is on track. Send the contract to legal@example.org and cc 555-0128.",
            ["email", "phone"],
            "two identifiers",
        ),
        (
            "Routine check-in. The billing admin is Marta Kowalczyk, mkowalczyk@example.net.",
            ["person", "email"],
            "check-in hiding contact",
        ),
        (
            "All good on delivery. Invoice goes to EIN 52-8830471 for their entity.",
            ["tax_id"],
            "delivery note hiding EIN",
        ),
        (
            f"Weekly summary. The demo environment uses admin / {_password(rng, 13)}.",
            ["secret"],
            "summary hiding credential",
        ),
        (
            "Deal is progressing. Their procurement lead lives at 88 Rosewood Drive, Denver.",
            ["address"],
            "deal note hiding address",
        ),
        (
            "Support ticket resolved. Customer callback number is 555-0141.",
            ["phone"],
            "ticket hiding phone",
        ),
        (
            "Quarterly numbers look fine. Reimburse to routing 084106768 account 2290117.",
            ["account_number"],
            "numbers hiding banking",
        ),
        (
            "Handoff complete. The new owner is Beatrice Lindqvist, b.lindqvist@example.com.",
            ["person", "email"],
            "handoff hiding contact",
        ),
        (
            f"Nothing urgent. The API token for their sandbox is {_shaped(rng, 'ghp_', 36)}.",
            ["secret"],
            "buried token",
        ),
        (
            "Contract signed. Countersigned by Dr. Elias Mwangi on behalf of the clinic.",
            ["person"],
            "signature hiding name",
        ),
        (
            "Positive meeting. Follow up with their CFO at 555-0175 before Friday.",
            ["phone"],
            "follow-up hiding phone",
        ),
        (
            "Rollout is smooth. Test card on file is 4111 1111 1111 1111 for QA.",
            ["credit_card"],
            "rollout hiding card",
        ),
        (
            "Standard update. Ship credentials to their ops lead, o.nakamura@example.org.",
            ["email"],
            "update hiding email",
        ),
    ]


def _synthetic_categories(
    rng: random.Random,
) -> dict[str, dict[str, list[tuple[str, list[str], str]]]]:
    categories: dict[str, dict[str, list[tuple[str, list[str], str]]]] = {}

    # -----------------------------------------------------------------------
    # 1. Structured PII
    # -----------------------------------------------------------------------
    categories["structured_pii"] = {
        "block": [
            (
                "Please update the file for Marcus Bell, 44 Oakfield Road, Trenton NJ 08608.",
                ["person", "address"],
                "name plus full postal address",
            ),
            (
                "Contact number for the account holder is 555-0148.",
                ["phone"],
                "bare phone",
            ),
            (
                "Her SSN is 541-88-3092 and she was born 04/17/1986.",
                ["ssn", "dob"],
                "ssn plus date of birth",
            ),
            (
                "Send the confirmation to priya.raman@example.com when it is ready.",
                ["email"],
                "bare email",
            ),
            (
                "Applicant: Dana Whitfield, DOB 1991-02-08, phone 555-0173.",
                ["person", "dob", "phone"],
                "three identifiers together",
            ),
            (
                "The new hire is Tomas Iglesias, reachable at t.iglesias@example.org or 555-0119.",
                ["person", "email", "phone"],
                "name plus two contact routes",
            ),
            (
                "Mailing address on record: 1820 Cedar Lane Apt 4B, Kansas City MO 64108.",
                ["address"],
                "address without name",
            ),
            (
                "Record shows Ruth Okonjo, born 12 March 1974, currently at 9 Harbour View Terrace.",
                ["person", "dob", "address"],
                "narrative form",
            ),
            (
                "Emergency contact is her brother, Aaron Feld, 555-0102.",
                ["person", "phone"],
                "relationship plus contact",
            ),
            (
                "Verify identity using the last four of the SSN, 3092, and the DOB 04/17/1986.",
                ["ssn", "dob"],
                "partial ssn still identifying with dob",
            ),
            (
                "Forward the packet to Nadia Christensen at 27 Ellsworth Street, Portland ME 04101.",
                ["person", "address"],
                "shipping instruction",
            ),
            (
                "Primary: kwame.asante@example.com. Secondary: 555-0165.",
                ["email", "phone"],
                "contact block",
            ),
            (
                "Subject of the review is Leonard Pyke, SSN 604-21-7735.",
                ["person", "ssn"],
                "name plus ssn",
            ),
            (
                "She listed her home as 3311 Fremont Avenue North, Seattle WA 98103.",
                ["address"],
                "conversational address",
            ),
            (
                "Patient intake for Ana Duarte lists DOB 09/30/1958 and phone 555-0187.",
                ["person", "dob", "phone"],
                "intake record",
            ),
            (
                "The signatory was Gregory Halloran, born June 2 1969, of 5 Winterbourne Close.",
                ["person", "dob", "address"],
                "formal register",
            ),
            (
                "Reach the tenant at 555-0134 or leave a note at 88 Bramble Court Unit 12.",
                ["phone", "address"],
                "two routes",
            ),
            (
                "Full legal name Samuel Adebayo-Grant, date of birth 15/08/1993.",
                ["person", "dob"],
                "non-US date order",
            ),
            (
                "Update the mailing list entry: Ingrid Solberg, isolberg@example.net.",
                ["person", "email"],
                "list entry",
            ),
            (
                "Driver on the incident report was Cheryl Vandermeer, licence issued 2011, phone 555-0156.",
                ["person", "phone"],
                "incident record",
            ),
        ],
        "approve": [
            (
                "Our intake form collects name, address, and phone number at signup.",
                [],
                "names the field types, contains no instance",
            ),
            (
                "We should stop storing date of birth unless there is a legal reason to keep it.",
                [],
                "policy discussion",
            ),
            (
                "The address field on the form is too short for international users.",
                [],
                "form design",
            ),
            (
                "Social security numbers must be encrypted at rest under the new policy.",
                [],
                "policy, no instance",
            ),
            (
                "Please confirm whether the customer supplied a phone number during onboarding.",
                [],
                "question about presence",
            ),
            (
                "The email column has a high null rate in last quarter's export.",
                [],
                "data quality",
            ),
            (
                "Legal asked us to document which tables contain personally identifiable information.",
                [],
                "meta discussion of PII",
            ),
            (
                "Users in the EU can request deletion of their contact details at any time.",
                [],
                "GDPR discussion",
            ),
            (
                "The signup flow validates postal codes but not street addresses.",
                [],
                "validation logic",
            ),
            (
                "We collect far more identifying data than we actually use in the product.",
                [],
                "critique",
            ),
            (
                "Date of birth should be optional on the registration screen.",
                [],
                "product decision",
            ),
            (
                "There are three different phone number formats in the legacy database.",
                [],
                "schema observation",
            ),
            (
                "Our retention schedule says contact information is purged after 24 months.",
                [],
                "retention policy",
            ),
            (
                "The form asks for a mailing address even for digital-only orders.",
                [],
                "UX complaint",
            ),
            (
                "Support agents should never read a full account number aloud on a call.",
                [],
                "handling rule",
            ),
            (
                "Name matching across the two systems is unreliable because of transliteration.",
                [],
                "technical problem",
            ),
            (
                "We need a field-level audit log for anything classified as personal data.",
                [],
                "engineering requirement",
            ),
            (
                "The privacy review covers every form that captures identifying information.",
                [],
                "process",
            ),
            (
                "Most of these records predate the consent flow entirely.",
                [],
                "historical note",
            ),
            (
                "Consider hashing email addresses before they reach the analytics pipeline.",
                [],
                "architecture proposal",
            ),
        ],
    }

    # -----------------------------------------------------------------------
    # 2. Financial documents
    # -----------------------------------------------------------------------
    categories["financial"] = {
        "block": [
            (
                "Wire the retainer to routing 084106768, account 4417820395.",
                ["account_number"],
                "wire instruction",
            ),
            (
                "Card on file ends 1111, full number 4111 1111 1111 1111, expiry 09/28.",
                ["credit_card"],
                "full card number",
            ),
            (
                "The statement for account 6620149883 shows a closing balance of 2,417.06.",
                ["account_number"],
                "statement line",
            ),
            (
                "Employer identification number for the entity is 47-3819205.",
                ["tax_id"],
                "EIN",
            ),
            ("Send payment to IBAN GB29 NWBK 6016 1331 9268 19.", ["iban"], "IBAN"),
            (
                "Beneficiary: Halvorsen Trading Ltd, acct 9902847715, SWIFT MIDLGB22.",
                ["account_number"],
                "international wire",
            ),
            (
                "The overdraft on checking 3391005522 has not cleared since March.",
                ["account_number"],
                "narrative with account",
            ),
            (
                "Please confirm receipt of the transfer to routing number 121000248.",
                ["routing_number"],
                "routing alone",
            ),
            (
                "Attached is the November statement for card 4111111111111111.",
                ["credit_card"],
                "unspaced card",
            ),
            (
                "His tax ID is 88-2047719 and the filing entity is a single-member LLC.",
                ["tax_id"],
                "EIN plus entity",
            ),
            (
                "Savings account 7714029386 was opened in 2019 with an initial deposit of 500.",
                ["account_number"],
                "account history",
            ),
            (
                "Direct deposit goes to routing 026009593, account 1150398827.",
                ["routing_number", "account_number"],
                "payroll setup",
            ),
            (
                "The escrow account, number 5583110274, holds the disputed funds.",
                ["account_number"],
                "legal-financial",
            ),
            (
                "Corporate card 4111-1111-1111-1111 was used for the Lisbon trip.",
                ["credit_card"],
                "hyphenated card",
            ),
            (
                "Remit to IBAN DE89 3704 0044 0532 0130 00 by end of month.",
                ["iban"],
                "European remittance",
            ),
            (
                "Loan servicing reference 4408117726 shows 14 payments remaining.",
                ["account_number"],
                "loan reference",
            ),
            (
                "Account 2298471003 was flagged for unusual activity twice last quarter.",
                ["account_number"],
                "fraud note",
            ),
            (
                "The vendor supplied routing 111000025 for ACH setup.",
                ["routing_number"],
                "vendor onboarding",
            ),
            (
                "Brokerage account 8871209934 holds the restricted shares.",
                ["account_number"],
                "brokerage",
            ),
            (
                "Please update the EIN on file from 31-7729104 to the new entity number.",
                ["tax_id"],
                "EIN change",
            ),
        ],
        "approve": [
            (
                "Revenue grew twelve percent quarter over quarter.",
                [],
                "aggregate metric",
            ),
            (
                "We should move the treasury function to a bank with better ACH support.",
                [],
                "vendor strategy",
            ),
            (
                "Wire transfers take two business days longer than we told the customer.",
                [],
                "process complaint",
            ),
            (
                "The finance team wants every invoice reconciled before the close.",
                [],
                "process",
            ),
            (
                "Our payment processor charges 2.9 percent plus thirty cents per transaction.",
                [],
                "public pricing",
            ),
            (
                "Cash runway is roughly eleven months at the current burn.",
                [],
                "aggregate",
            ),
            (
                "We need a policy for who can approve wires above a certain threshold.",
                [],
                "controls discussion",
            ),
            (
                "The bank reconciliation is still manual and takes two days each month.",
                [],
                "operations",
            ),
            (
                "Credit card fees are the third largest line item in the operating budget.",
                [],
                "budget",
            ),
            (
                "Accounts receivable aging has worsened since we relaxed payment terms.",
                [],
                "financial analysis",
            ),
            (
                "Routing numbers are nine digits and include a checksum.",
                [],
                "factual, no instance",
            ),
            (
                "We are switching from monthly to quarterly board reporting.",
                [],
                "governance",
            ),
            (
                "The auditors flagged our expense approval workflow as too permissive.",
                [],
                "audit finding",
            ),
            (
                "Gross margin improved after we renegotiated the hosting contract.",
                [],
                "aggregate",
            ),
            (
                "Consider requiring dual approval for any outbound transfer.",
                [],
                "control proposal",
            ),
            (
                "The IRS requires an employer identification number for any entity with employees.",
                [],
                "regulation, no instance",
            ),
            (
                "Payroll runs on the fifteenth and the last business day of each month.",
                [],
                "schedule",
            ),
            (
                "We have too many corporate cards outstanding relative to headcount.",
                [],
                "policy observation",
            ),
            (
                "Deferred revenue is recognised over the term of the contract.",
                [],
                "accounting",
            ),
            (
                "The budget assumes no additional headcount in the second half.",
                [],
                "planning",
            ),
        ],
    }

    # -----------------------------------------------------------------------
    # 3. Tax documents
    # -----------------------------------------------------------------------
    categories["tax"] = {
        "block": [
            (
                "W-2 for Elena Marchetti, SSN 522-70-4418, wages 84,200, federal withheld 12,880.",
                ["person", "ssn"],
                "W-2 shape",
            ),
            (
                "1099-NEC issued to Devon Aguilar, TIN 601-33-8827, nonemployee comp 46,500.",
                ["person", "ssn"],
                "1099 shape",
            ),
            (
                "Filing status married filing jointly, SSN 490-12-6653, spouse SSN 471-90-2284.",
                ["ssn"],
                "two SSNs",
            ),
            (
                "Box 1 wages 61,340 for employee SSN 338-55-9027.",
                ["ssn"],
                "W-2 box reference",
            ),
            (
                "Taxpayer Ruth Ellison, ITIN 912-84-5570, claimed two dependents.",
                ["person", "ssn"],
                "ITIN",
            ),
            (
                "The amended return for SSN 205-66-3391 reduced liability by 3,120.",
                ["ssn"],
                "amended return",
            ),
            (
                "Schedule C filed under EIN 45-8830127 reports 118,000 gross receipts.",
                ["tax_id"],
                "Schedule C",
            ),
            (
                "Head of household, SSN 617-29-4408, adjusted gross income 52,775.",
                ["ssn"],
                "filing status plus AGI",
            ),
            (
                "1099-MISC to Priyanka Shah, TIN 883-40-1195, rents 22,000.",
                ["person", "ssn"],
                "1099-MISC",
            ),
            (
                "Notice CP2000 references taxpayer SSN 774-51-2038 for tax year 2024.",
                ["ssn"],
                "IRS notice",
            ),
            (
                "Employee SSN 349-77-6612 had 9,410 withheld in box 2.",
                ["ssn"],
                "withholding",
            ),
            (
                "Return prepared for Anders Lindqvist, SSN 208-14-9963, refund 2,204.",
                ["person", "ssn"],
                "preparer note",
            ),
            (
                "Filing separately, SSN 560-02-7741, itemised deductions 19,300.",
                ["ssn"],
                "itemised",
            ),
            (
                "The K-1 lists partner Marisol Vega, TIN 736-88-0254, ownership 18 percent.",
                ["person", "ssn"],
                "K-1",
            ),
            (
                "Estimated payments posted to SSN 411-93-5528 total 8,000 for the year.",
                ["ssn"],
                "estimated payments",
            ),
            (
                "Dependent claimed: Oliver Nakamura, SSN 850-27-1146, born 2016.",
                ["person", "ssn"],
                "dependent",
            ),
            (
                "1099-INT to account holder SSN 293-60-4472, interest income 1,845.",
                ["ssn"],
                "1099-INT",
            ),
            (
                "Self-employment tax computed on net earnings for EIN 62-9014483.",
                ["tax_id"],
                "SE tax",
            ),
            (
                "The audit letter cites taxpayer SSN 158-42-7790 and tax years 2022 to 2024.",
                ["ssn"],
                "audit",
            ),
            (
                "Form 4868 extension filed for Gwendolyn Achebe, SSN 366-15-8802.",
                ["person", "ssn"],
                "extension",
            ),
        ],
        "approve": [
            (
                "The federal filing deadline is April 15 unless it falls on a weekend.",
                [],
                "public deadline",
            ),
            ("We should hire a CPA before the next filing season.", [], "planning"),
            (
                "Filing jointly usually lowers the effective rate for single-income households.",
                [],
                "general tax fact",
            ),
            (
                "Quarterly estimated payments are due in April, June, September, and January.",
                [],
                "schedule",
            ),
            ("The standard deduction increased again this year.", [], "public fact"),
            (
                "Nobody on the team understands how the R&D credit actually works.",
                [],
                "candid, no data",
            ),
            (
                "A 1099-NEC is issued to contractors, a W-2 to employees.",
                [],
                "form definitions",
            ),
            (
                "We need to decide whether to file an extension this year.",
                [],
                "decision",
            ),
            (
                "State tax treatment of remote employees varies considerably.",
                [],
                "policy",
            ),
            (
                "Our accountant recommends switching to an S corporation election.",
                [],
                "advice, no identifiers",
            ),
            (
                "Keep receipts for anything you plan to deduct as a business expense.",
                [],
                "guidance",
            ),
            (
                "The penalty for late filing is larger than the penalty for late payment.",
                [],
                "public fact",
            ),
            (
                "Payroll tax deposits are handled by the provider, not by us.",
                [],
                "process",
            ),
            (
                "Sales tax nexus rules changed after the Wayfair decision.",
                [],
                "case law, public",
            ),
            (
                "We should reconcile contractor payments before issuing any forms.",
                [],
                "process",
            ),
            (
                "Depreciation schedules for the equipment need updating.",
                [],
                "accounting",
            ),
            (
                "Nobody has confirmed whether the home office deduction applies here.",
                [],
                "open question",
            ),
            (
                "The tax year and the fiscal year are not the same for this entity.",
                [],
                "structural",
            ),
            (
                "Charitable deductions require documentation above a certain amount.",
                [],
                "rule",
            ),
            (
                "Our effective rate is lower than our marginal rate, as expected.",
                [],
                "aggregate",
            ),
        ],
    }

    # -----------------------------------------------------------------------
    # 4. Health documents
    # -----------------------------------------------------------------------
    categories["health"] = {
        "block": [
            (
                "Patient Harold Nwosu, MRN 4408822, diagnosed with type 2 diabetes in 2019.",
                ["person", "mrn", "diagnosis"],
                "name plus MRN plus diagnosis",
            ),
            (
                "Prescribed sertraline 50mg daily to Ms. Fiona Delacroix following the June visit.",
                ["person", "prescription"],
                "prescription with name",
            ),
            (
                "Insurance member ID XZQ889402215, plan holder Beatriz Oyelaran.",
                ["person", "insurance_id"],
                "insurance identifier",
            ),
            (
                "Dr. Amanda Reyes noted the lesion was benign on the 14 March biopsy.",
                ["person", "diagnosis"],
                "provider plus finding",
            ),
            (
                "MRN 7719043 shows three admissions for the same cardiac complaint.",
                ["mrn"],
                "MRN alone",
            ),
            (
                "The patient, Ivan Petrov, is on lithium and reports poor adherence.",
                ["person", "prescription"],
                "medication adherence",
            ),
            (
                "Referral to oncology for Grace Abera, member ID BLU4471902.",
                ["person", "insurance_id"],
                "referral",
            ),
            (
                "Chart for Sunil Kapoor, MRN 2298104, records a penicillin allergy.",
                ["person", "mrn"],
                "allergy record",
            ),
            (
                "Ms. Delacroix's HbA1c was 8.2 at the last draw.",
                ["person", "lab_result"],
                "lab with name",
            ),
            (
                "Attending physician Dr. Marcus Hollande documented suspected early dementia.",
                ["person", "diagnosis"],
                "provider plus diagnosis",
            ),
            (
                "Patient ID 5580117 tested positive and was started on antiretrovirals.",
                ["mrn", "diagnosis"],
                "sensitive diagnosis with ID",
            ),
            (
                "Claim submitted under member 9930party, subscriber Yusuf Demir, for an MRI.",
                ["person", "insurance_id"],
                "claim",
            ),
            (
                "Prescription for oxycodone 5mg written for Ana Beatriz Lima on 2 May.",
                ["person", "prescription"],
                "controlled substance",
            ),
            (
                "The discharge summary for MRN 3341276 lists post-surgical infection.",
                ["mrn", "diagnosis"],
                "discharge",
            ),
            (
                "Ms. Okoro's psychiatric evaluation is filed under record 8820441.",
                ["person", "mrn"],
                "mental health record",
            ),
            (
                "Group number 44120, member ID HHP7719023, dependent coverage active.",
                ["insurance_id"],
                "coverage detail",
            ),
            (
                "Dr. Lena Farkas increased the dose after the patient reported tremor.",
                ["person", "prescription"],
                "titration note",
            ),
            (
                "Genetic panel for Theo Almeida returned a BRCA1 variant.",
                ["person", "diagnosis"],
                "genetic result",
            ),
            (
                "Record 6612900 documents a termination of pregnancy in 2021.",
                ["mrn", "diagnosis"],
                "highly sensitive",
            ),
            (
                "Physical therapy authorised for Nadine Kowalski under policy PPO8830125.",
                ["person", "insurance_id"],
                "authorisation",
            ),
        ],
        "approve": [
            (
                "The clinic is open Monday through Friday from eight to five.",
                [],
                "logistics",
            ),
            (
                "We should switch to a provider network with better mental health coverage.",
                [],
                "benefits discussion",
            ),
            ("Deductibles reset in January for most plans.", [], "general fact"),
            ("The waiting room needs more chairs.", [], "facilities"),
            (
                "Telehealth adoption rose sharply and has not fallen back to baseline.",
                [],
                "trend",
            ),
            (
                "Our benefits package covers physical therapy at eighty percent.",
                [],
                "plan terms, no member",
            ),
            (
                "Prior authorisation is the most common source of billing delays.",
                [],
                "process",
            ),
            (
                "Diabetes prevalence has increased across most age groups.",
                [],
                "epidemiology",
            ),
            ("The EHR vendor is raising prices again at renewal.", [], "vendor"),
            (
                "Nurses are reporting that the new charting workflow takes longer.",
                [],
                "operations",
            ),
            (
                "Generic medications are substantially cheaper than brand equivalents.",
                [],
                "general",
            ),
            (
                "We need to post the updated privacy notice in the lobby.",
                [],
                "compliance",
            ),
            (
                "Appointment no-show rates are highest on Monday mornings.",
                [],
                "aggregate",
            ),
            ("The lab courier arrives twice daily.", [], "logistics"),
            (
                "HIPAA requires a business associate agreement with any vendor handling records.",
                [],
                "regulation",
            ),
            (
                "Staff training on the new system is scheduled for next month.",
                [],
                "internal",
            ),
            (
                "Insurance verification should happen before the visit, not after.",
                [],
                "process",
            ),
            (
                "The pharmacy benefit manager changed its formulary this year.",
                [],
                "benefits",
            ),
            (
                "Wait times improved after we added a second intake station.",
                [],
                "operations",
            ),
            (
                "Preventive visits are covered without a copay under most plans.",
                [],
                "plan terms",
            ),
        ],
    }

    # -----------------------------------------------------------------------
    # 5. Legal documents
    # -----------------------------------------------------------------------
    categories["legal"] = {
        "block": [
            (
                "Case No. 3:24-cv-01882, Hollis v. Bergstrom Manufacturing, filed in N.D. Cal.",
                ["case_number", "person"],
                "caption",
            ),
            (
                "The settlement with Ms. Carrington was 240,000 with a mutual non-disparagement clause.",
                ["person", "settlement"],
                "settlement terms",
            ),
            (
                "Privileged and confidential: counsel advises against producing the Dalton emails.",
                ["privilege", "person"],
                "privileged communication",
            ),
            (
                "Docket 2:23-cr-00417 lists the defendant as Emmanuel Bright.",
                ["case_number", "person"],
                "criminal docket",
            ),
            (
                "Attorney-client privileged. Our exposure on the Vance claim is roughly 1.2 million.",
                ["privilege", "person", "settlement"],
                "privileged assessment",
            ),
            (
                "Plaintiff Rosalind Achterberg alleges constructive dismissal in matter 1:25-cv-00903.",
                ["person", "case_number"],
                "allegation",
            ),
            (
                "We agreed to pay Mr. Okafor 85,000 to resolve the wage claim.",
                ["person", "settlement"],
                "wage settlement",
            ),
            (
                "Confidential settlement in Whitmore v. Pinnacle Health, case 4:22-cv-07741.",
                ["person", "case_number"],
                "confidential settlement",
            ),
            (
                "Counsel's memo on the Brennan matter is protected work product.",
                ["privilege", "person"],
                "work product",
            ),
            (
                "The consent decree in matter 5:21-cv-03318 requires quarterly compliance reports.",
                ["case_number"],
                "consent decree",
            ),
            (
                "Defendant Tobias Lindgren was served at his residence on 3 April.",
                ["person"],
                "service of process",
            ),
            (
                "Mediation resolved at 310,000 plus fees, parties Kaplan and Redmond Industries.",
                ["person", "settlement"],
                "mediation outcome",
            ),
            (
                "Do not forward: privileged analysis of our indemnity position with Sorensen.",
                ["privilege", "person"],
                "privilege warning",
            ),
            (
                "Arbitration reference ARB-2024-0881, claimant Yvette Boisvert.",
                ["case_number", "person"],
                "arbitration",
            ),
            (
                "The NDA with Halvard Systems was breached by their former CTO, Erik Sandoval.",
                ["person"],
                "breach allegation",
            ),
            (
                "Judgment entered against Meridian Freight in case 6:24-cv-02205 for 640,000.",
                ["case_number", "settlement"],
                "judgment",
            ),
            (
                "Attorney work product: our exposure if the Nakashima class is certified.",
                ["privilege", "person"],
                "class action",
            ),
            (
                "Ms. Adeyemi's severance included a release of all claims for 120,000.",
                ["person", "settlement"],
                "severance",
            ),
            (
                "Subpoena in matter 7:25-mc-00114 seeks documents from Grantham Partners.",
                ["case_number"],
                "subpoena",
            ),
            (
                "Privileged: counsel believes the Ferreira deposition damaged our position.",
                ["privilege", "person"],
                "litigation assessment",
            ),
        ],
        "approve": [
            (
                "We should review the standard contract template before the next renewal cycle.",
                [],
                "contract ops",
            ),
            ("Most commercial disputes settle before trial.", [], "general fact"),
            ("Our outside counsel rates went up again this year.", [], "vendor cost"),
            (
                "The indemnification clause is more aggressive than industry norm.",
                [],
                "clause discussion",
            ),
            (
                "Arbitration is generally faster than litigation but harder to appeal.",
                [],
                "general",
            ),
            (
                "Legal wants a two-week review window for any new vendor agreement.",
                [],
                "process",
            ),
            (
                "Non-compete enforceability varies significantly by state.",
                [],
                "law, no matter",
            ),
            (
                "We do not have a document retention policy that anyone follows.",
                [],
                "candid, no matter",
            ),
            (
                "The MSA and the SOW conflict on termination notice.",
                [],
                "drafting problem",
            ),
            (
                "Privilege can be waived by forwarding a memo to the wrong recipient.",
                [],
                "training point, meta",
            ),
            (
                "Consider adding a limitation of liability cap to the standard terms.",
                [],
                "proposal",
            ),
            (
                "Discovery costs usually exceed the amount in dispute for small claims.",
                [],
                "general",
            ),
            ("Our terms of service have not been updated in three years.", [], "gap"),
            (
                "Trademark registration takes longer than most founders expect.",
                [],
                "general",
            ),
            (
                "We need a process for handling law enforcement requests.",
                [],
                "process gap",
            ),
            ("Choice of law provisions matter more than people assume.", [], "general"),
            (
                "The board asked for a summary of our overall litigation posture.",
                [],
                "request, no specifics",
            ),
            (
                "Open source licence compliance is not currently tracked anywhere.",
                [],
                "compliance gap",
            ),
            ("Force majeure clauses got much more attention after 2020.", [], "trend"),
            (
                "Counsel recommends we document approval decisions more consistently.",
                [],
                "advice, no matter",
            ),
        ],
    }

    # -----------------------------------------------------------------------
    # 6. Credentials and secrets
    # -----------------------------------------------------------------------
    categories["credentials"] = {
        "block": _credentials_block(rng),
        "approve": [
            (
                "We should rotate API keys quarterly instead of annually.",
                [],
                "policy, no key",
            ),
            ("Never commit credentials to the repository.", [], "rule"),
            (
                "Set your API key as an environment variable before running the script.",
                [],
                "instruction, no value",
            ),
            (
                "Replace YOUR_API_KEY_HERE with the value from the dashboard.",
                [],
                "placeholder, tests over-redaction",
            ),
            (
                "The example in the docs uses sk-xxxxxxxxxxxxxxxx as a stand-in.",
                [],
                "masked placeholder",
            ),
            (
                "Our secrets live in Vault, not in the environment files.",
                [],
                "architecture",
            ),
            (
                "The token expired and needs to be regenerated from the console.",
                [],
                "status, no value",
            ),
            (
                "Use a password manager rather than sharing credentials over chat.",
                [],
                "guidance",
            ),
            (
                "Private keys should be generated on the machine that will use them.",
                [],
                "practice",
            ),
            (
                "The build failed because the secret was not available to the runner.",
                [],
                "CI diagnosis",
            ),
            (
                "We have too many long-lived tokens and no rotation policy.",
                [],
                "audit finding",
            ),
            (
                "The commit hash is 4f8a2b9c1e6d3057a8b4c2e9f1d6035a.",
                [],
                "hex string that is a git SHA, not a secret",
            ),
            (
                "Redacted in the log as ****, which makes debugging harder.",
                [],
                "masked value",
            ),
            ("Documentation should never contain a working credential.", [], "rule"),
            (
                "Two-factor authentication is now required for all admin accounts.",
                [],
                "policy",
            ),
            (
                "The checksum for the release artifact is d41d8cd98f00b204e9800998ecf8427e.",
                [],
                "md5 hash, not a secret",
            ),
            (
                "Service accounts should have the narrowest scope that works.",
                [],
                "principle",
            ),
            (
                "Someone pasted a key into the channel last month and we had to rotate.",
                [],
                "incident, no key",
            ),
            ("The SSH config points at the wrong identity file.", [], "config problem"),
            ("Consider short-lived credentials issued at deploy time.", [], "proposal"),
        ],
    }

    # -----------------------------------------------------------------------
    # 7. Contextual sensitivity without named entities
    # -----------------------------------------------------------------------
    categories["contextual"] = {
        "block": [
            (
                "I am going through chemotherapy and cannot afford the copay.",
                ["health", "financial_hardship"],
                "no named entity, high sensitivity",
            ),
            (
                "We are about to be sued by our former co-founder.",
                ["legal"],
                "no names",
            ),
            (
                "I have been sober for 90 days and it is still very hard.",
                ["health", "addiction"],
                "recovery disclosure",
            ),
            (
                "My partner lost their job and we are two months behind on rent.",
                ["financial_hardship"],
                "household distress",
            ),
            (
                "I was diagnosed with a condition I have not told my manager about.",
                ["health"],
                "undisclosed diagnosis",
            ),
            (
                "The company is going to miss payroll next month if the round does not close.",
                ["financial_hardship"],
                "corporate distress",
            ),
            (
                "I am in the middle of a custody dispute and it is affecting my work.",
                ["legal", "family"],
                "family legal",
            ),
            (
                "My immigration status is unresolved and the deadline is in six weeks.",
                ["immigration"],
                "status disclosure",
            ),
            (
                "I have been seeing a therapist twice a week since the layoff.",
                ["health"],
                "mental health",
            ),
            (
                "We quietly settled a harassment complaint last year.",
                ["legal"],
                "organisational",
            ),
            (
                "I filed for bankruptcy three years ago and it still affects my credit.",
                ["financial_hardship"],
                "financial history",
            ),
            (
                "My mother has early-onset dementia and I am her only caregiver.",
                ["health", "family"],
                "third party health",
            ),
            (
                "I am the anonymous source in the story that ran last week.",
                ["safety"],
                "source protection",
            ),
            (
                "Our biggest customer told us privately they are not renewing.",
                ["business_confidential"],
                "confidential business",
            ),
            (
                "I am on medication that affects my concentration in the mornings.",
                ["health"],
                "medication disclosure",
            ),
            (
                "There is an internal investigation into my department right now.",
                ["legal"],
                "investigation",
            ),
            (
                "We are in acquisition talks that have not been announced.",
                ["business_confidential"],
                "M&A",
            ),
            (
                "I had a miscarriage in March and have not told anyone at work.",
                ["health"],
                "highly sensitive",
            ),
            (
                "My visa depends on staying employed here, so I cannot negotiate.",
                ["immigration"],
                "leverage disclosure",
            ),
            (
                "I am being treated for an eating disorder and mealtimes are difficult.",
                ["health"],
                "sensitive diagnosis",
            ),
        ],
        "approve": [
            (
                "I am training for a marathon and my mornings are busy.",
                [],
                "benign personal",
            ),
            ("I am taking vacation the last week of the month.", [], "routine"),
            (
                "I prefer meetings in the afternoon if that works for everyone.",
                [],
                "preference",
            ),
            (
                "I have a dentist appointment on Thursday at two.",
                [],
                "routine appointment, no condition",
            ),
            ("I am learning Portuguese in the evenings.", [], "hobby"),
            ("My commute is about forty minutes each way.", [], "logistics"),
            ("I found the offsite genuinely useful this year.", [], "opinion"),
            (
                "I am moving apartments next month so I may be offline a day.",
                [],
                "logistics",
            ),
            (
                "I would rather work on the infrastructure side than the frontend.",
                [],
                "preference",
            ),
            ("I read the paper you sent and mostly agree with it.", [], "professional"),
            ("I am not a morning person but I manage.", [], "mild personal"),
            ("My laptop battery is failing and I need a replacement.", [], "equipment"),
            ("I have a standing conflict on Tuesdays at four.", [], "calendar"),
            ("I enjoyed the conference more than I expected to.", [], "opinion"),
            (
                "I am going to a wedding in June and will need those days off.",
                [],
                "leave request",
            ),
            (
                "I think we are over-indexing on this metric.",
                [],
                "professional opinion",
            ),
            (
                "I would like more feedback on my work than I currently get.",
                [],
                "career, not sensitive",
            ),
            ("I am picking up the on-call rotation next week.", [], "work logistics"),
            (
                "I have never used this framework before but I can learn it.",
                [],
                "skills",
            ),
            ("I am happy to take the notes in the meeting.", [], "volunteering"),
        ],
    }

    # -----------------------------------------------------------------------
    # 8. Benign-looking business prose
    #    Positives here are routine business prose with a real identifier
    #    buried in it. Negatives are routine business prose that merely
    #    sounds sensitive.
    # -----------------------------------------------------------------------
    categories["benign_business"] = {
        "block": _benign_business_block(rng),
        "approve": [
            (
                "Revenue is up but customer names in the deck should be anonymised.",
                [],
                "mentions customer names, includes none",
            ),
            (
                "We closed three deals this quarter, all in the mid-market segment.",
                [],
                "aggregate",
            ),
            ("The customer asked for a discount and we said no.", [], "no identifiers"),
            ("Our biggest account renewed without much negotiation.", [], "no name"),
            ("Sales wants access to the revenue dashboard.", [], "internal request"),
            (
                "Churn is concentrated in accounts that never completed onboarding.",
                [],
                "analysis",
            ),
            (
                "The pitch deck needs updating before the next round of meetings.",
                [],
                "materials",
            ),
            (
                "Two prospects asked about our security posture this week.",
                [],
                "aggregate",
            ),
            (
                "We should stop putting logos in the deck without permission.",
                [],
                "policy",
            ),
            (
                "Pipeline coverage is thinner than the target for next quarter.",
                [],
                "metric",
            ),
            ("The demo environment keeps timing out during calls.", [], "technical"),
            (
                "Procurement cycles at enterprises are longer than we modelled.",
                [],
                "observation",
            ),
            ("Our win rate improved after we changed the trial length.", [], "metric"),
            (
                "Marketing wants case studies but legal has not approved any.",
                [],
                "process",
            ),
            (
                "The customer success team is understaffed relative to account count.",
                [],
                "staffing",
            ),
            (
                "We lost a deal to a competitor on price, not features.",
                [],
                "loss reason",
            ),
            (
                "Renewal notices should go out ninety days ahead, not thirty.",
                [],
                "process",
            ),
            ("Support volume spikes every time we ship a release.", [], "pattern"),
            ("The onboarding checklist is out of date in three places.", [], "docs"),
            ("Nobody has owned the partner channel since the reorg.", [], "org gap"),
        ],
    }

    return categories


# Reassembly false blocking and cost

DIGITS = string.digits


def digit_dense_round(rng: random.Random, prose_pool: list[str]) -> list[str]:
    """12 values: ordinary prose, amounts, dates, box numbers, reference
    numbers. None of these are sensitive; the round is meant to be one that
    should never block."""
    values = []
    for _ in range(12):
        kind = rng.choice(("prose", "amount", "date", "box", "ref"))
        if kind == "prose":
            values.append(rng.choice(prose_pool))
        elif kind == "amount":
            values.append(f"{rng.randrange(100, 99999)}.{rng.randrange(0, 99):02d}")
        elif kind == "date":
            values.append(
                f"{rng.randrange(2015, 2027)}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"
            )
        elif kind == "box":
            values.append(f"Box {rng.randrange(1, 9999)}")
        else:
            values.append(f"REF-{rng.randrange(100000, 999999)}")
    return values


def random_digit_sources(rng: random.Random, length: int, count: int) -> set[str]:
    if length <= 0 or not 0 <= count <= 10**length:
        raise ValueError("source length must be positive and count must fit its space")
    sources: set[str] = set()
    while len(sources) < count:
        sources.add("".join(rng.choice(DIGITS) for _ in range(length)))
    return sources


def ceiling_round(rng: random.Random, total: int, n: int) -> list[str]:
    """n all-digit values whose lengths sum to exactly `total`, so the round
    sits at the MAX_REASSEMBLY_LENGTH ceiling without tripping it."""
    base, rem = divmod(total, n)
    lengths = [base + 1] * rem + [base] * (n - rem)
    rng.shuffle(lengths)
    return ["".join(rng.choice(DIGITS) for _ in range(length)) for length in lengths]


REALISTIC_DOCUMENTS = {
    "w2.txt": "Employer EIN 31-7729104\nBox 1 wages 48250.00\nEmployee SSN 912-84-7731\nAddress 44 Oakfield Road\n",
    "notes.txt": "Quarterly planning notes.\nContact jane.doe@example.com or 555-0148.\nAccount number: 8829930041\n",
    "1040.txt": "ssn: \nwages: \nein: \n",
}


def measure_reassembly_floor(trials: int = 300, seed: int = DEFAULT_SEED) -> dict:
    """False blocks by source length/count on seeded digit-dense benign rounds."""
    if trials <= 0:
        raise ValueError("trials must be positive")
    assert airlock.reassembles_identifier(["912 ok", "84 ok", "7731 ok"], {"912847731"})
    pool = [r.text[:80] for r in build_dataset(seed) if r.gold == "approve"]
    rng = random.Random(seed)
    rates = {}
    for length in (6, 8, 9):
        for count in (20, 40, 60):
            blocks = 0
            for _ in range(trials):
                values = digit_dense_round(rng, pool)
                sources = random_digit_sources(rng, length, count)
                blocks += airlock.reassembles_identifier(values, sources)
            rates[f"{length}d/{count}"] = {
                "blocks": blocks,
                "false_block_rate": blocks / trials,
            }
    return {"seed": seed, "trials": trials, "rates": rates}


def _time_reassembly(values: list[str], sources: set[str], reps: int) -> dict:
    times = []
    for _ in range(reps):
        started = time.perf_counter()
        blocked = airlock.reassembles_identifier(values, sources)
        times.append(time.perf_counter() - started)
        assert not blocked, "a match exited early and invalidated the timing"
    return {
        "mean_s": statistics.mean(times),
        "median_s": statistics.median(times),
        "all_s": times,
    }


def measure_reassembly_cost(reps: int = 5, seed: int = DEFAULT_SEED) -> dict:
    """Time the current guard at its length ceiling and across workspace sizes.

    Timings are machine-specific. A three-document fixture anchors the scaling
    curve to an identifier count measured through source_identifiers().
    """
    if reps <= 0:
        raise ValueError("reps must be positive")
    rng = random.Random(seed)
    values = ceiling_round(
        rng, airlock.MAX_REASSEMBLY_LENGTH, airlock.MAX_JOBS_PER_ROUND
    )
    sources = random_digit_sources(rng, 12, 400)
    assert (
        sum(len(airlock.normalise_identifier(v)) for v in values)
        == airlock.MAX_REASSEMBLY_LENGTH
    )
    ceiling = _time_reassembly(values, sources, reps)
    rng = random.Random(seed)
    values = [
        "".join(rng.choice(DIGITS) for _ in range(80))
        for _ in range(airlock.MAX_JOBS_PER_ROUND)
    ]
    scaling = {
        count: _time_reassembly(values, random_digit_sources(rng, 12, count), reps)
        for count in (1, 5, 50, 200, 400)
    }
    with tempfile.TemporaryDirectory(prefix="airlock-cost-") as tmp:
        root = Path(tmp)
        for name, text in REALISTIC_DOCUMENTS.items():
            (root / name).write_text(text)
        sources = airlock.source_identifiers(
            airlock.Sandbox(root=root, allow_writes=False)
        )
        realistic = _time_reassembly(values, sources, reps)
    return {
        "seed": seed,
        "reps": reps,
        "ceiling": ceiling,
        "by_source_count": scaling,
        "realistic_identifiers": len(sources),
        "realistic": realistic,
    }
