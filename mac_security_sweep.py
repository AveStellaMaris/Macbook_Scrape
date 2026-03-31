#!/usr/bin/env python3
"""
mac_security_sweep.py

Plug-and-play defensive macOS security sweep.
- Designed for non-technical users: run once, no prompts.
- Does NOT modify/delete system files.
- Identifies suspicious/broken/old login-start items and generates a safe review plan.

Typical run:
  python3 scripts/mac_security_sweep.py
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SUSPICIOUS_EXTENSIONS = {
    ".app", ".command", ".dmg", ".pkg", ".mpkg", ".sh", ".zsh", ".bash", ".py", ".js", ".jar", ".iso", ".exe", ".scr"
}
SCRIPT_EXTENSIONS = {".sh", ".zsh", ".bash", ".command", ".py", ".js"}
HIGH_RISK_DIRS = [Path.home() / "Downloads", Path.home() / "Desktop", Path.home() / "Documents", Path("/tmp")]
PERSISTENCE_PATHS = [
    Path.home() / "Library/LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("/private/var/root/Library/LaunchAgents"),
]
CRON_PATHS = [Path("/etc/crontab"), Path("/private/etc/crontab"), Path("/usr/lib/cron/tabs"), Path("/private/var/at/jobs")]
DEFAULT_EXCLUDES = {"/dev", "/proc", "/System/Volumes/Preboot", "/System/Volumes/VM", "/private/var/vm"}
TRUSTED_SUID_PREFIXES = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/System"]
APPLE_SAFE_PREFIXES = ["/System", "/usr", "/bin", "/sbin", "/Library/Apple", "/private/var/db"]


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    path: Optional[str]
    details: str


@dataclass
class LoginItemCandidate:
    label: str
    plist_path: str
    exec_path: Optional[str]
    reason: str
    age_days: int
    suggested_action: str


class MacSecuritySweep:
    def __init__(
        self,
        scan_root: Path,
        max_files: int,
        output_dir: Path,
        skip_clamav: bool,
        include_hidden: bool,
        deep_mode: bool,
    ) -> None:
        self.scan_root = scan_root
        self.max_files = max_files
        self.output_dir = output_dir
        self.skip_clamav = skip_clamav
        self.include_hidden = include_hidden
        self.deep_mode = deep_mode
        self.findings: List[Finding] = []
        self.login_candidates: List[LoginItemCandidate] = []
        self.telemetry: Dict[str, object] = {
            "files_scanned": 0,
            "dirs_scanned": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "warnings": [],
            "commands": [],
        }

    def run(self) -> Dict[str, object]:
        self._check_platform()
        self._collect_system_security_status()
        self._scan_persistence_locations()
        self._scan_login_items_for_old_broken_irrelevant()
        self._scan_cron_and_at_jobs()
        self._scan_running_processes()
        self._scan_network_activity()
        self._scan_filesystem()
        if self.deep_mode:
            self._scan_suid_sgid_binaries()
        self._run_clamav_scan()

        ended = datetime.now(timezone.utc)
        self.telemetry["end_time"] = ended.isoformat()
        self.telemetry["risk_score"] = self._risk_score()
        self.telemetry["summary"] = self._summary()

        report = {
            "scan_root": str(self.scan_root),
            "deep_mode": self.deep_mode,
            "telemetry": self.telemetry,
            "findings": [asdict(f) for f in self.findings],
            "login_item_candidates": [asdict(c) for c in self.login_candidates],
            "generated_at": ended.isoformat(),
        }
        self._write_reports(report)
        return report

    def _check_platform(self) -> None:
        if sys.platform != "darwin":
            self.telemetry["warnings"].append("This tool is optimized for macOS. Non-macOS results may be partial.")

    def _summary(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _risk_score(self) -> int:
        weights = {"critical": 30, "high": 10, "medium": 4, "low": 1}
        return min(sum(weights.get(f.severity.lower(), 0) for f in self.findings), 100)

    def _run_command(self, command: List[str], timeout: int = 40) -> Tuple[int, str]:
        self.telemetry["commands"].append(" ".join(command))
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            out = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            return result.returncode, out.strip()
        except Exception as exc:
            return 127, f"COMMAND_ERROR: {exc}"

    def _collect_system_security_status(self) -> None:
        checks = {
            "Gatekeeper": ["spctl", "--status"],
            "SIP": ["csrutil", "status"],
            "Firewall": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            "XProtect version": ["defaults", "read", "/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString"],
            "MRT version": ["defaults", "read", "/System/Library/CoreServices/MRT.app/Contents/Info", "CFBundleShortVersionString"],
        }

        for name, cmd in checks.items():
            if shutil.which(cmd[0]) is None and not cmd[0].startswith("/"):
                self.telemetry["warnings"].append(f"Missing command for {name}: {cmd[0]}")
                continue
            _, output = self._run_command(cmd)
            lowered = output.lower()
            disabled_signal = (
                "disabled" in lowered
                or "unknown" in lowered
                or output.startswith("COMMAND_ERROR")
            )
            if name == "Gatekeeper" and "assessments enabled" in lowered:
                disabled_signal = False
            if name == "Firewall" and "enabled" in lowered:
                disabled_signal = False
            if disabled_signal:
                self.findings.append(Finding("system_security", "medium", f"{name} may be disabled/misconfigured", None, output[:800]))

    def _parse_plist_exec(self, plist_data: dict) -> Optional[str]:
        prog = plist_data.get("Program")
        if isinstance(prog, str) and prog.strip():
            return prog.strip()
        args = plist_data.get("ProgramArguments")
        if isinstance(args, list) and args and isinstance(args[0], str):
            return args[0].strip()
        return None

    def _is_apple_or_core_path(self, path: Optional[str]) -> bool:
        if not path:
            return False
        return any(path.startswith(prefix) for prefix in APPLE_SAFE_PREFIXES)

    def _candidate_reason(self, label: str, plist_path: Path, exec_path: Optional[str]) -> Optional[Tuple[str, str]]:
        age_days = int((datetime.now(timezone.utc).timestamp() - plist_path.stat().st_mtime) / 86400)

        if label.startswith("com.apple"):
            return None

        if exec_path:
            resolved = str(Path(exec_path))
            if self._is_apple_or_core_path(resolved):
                return None
            if not Path(resolved).exists():
                return (f"Broken startup item (missing executable): {resolved}", "disable_then_remove")
        else:
            return ("Missing Program/ProgramArguments in plist", "disable_then_remove")

        if age_days >= 365:
            return (f"Old third-party startup item ({age_days} days old)", "review_disable_if_unused")

        if any(k in label.lower() for k in ["update", "helper", "agent", "daemon"]):
            return ("Potentially stale helper/agent startup entry", "review_disable_if_unused")

        return None

    def _scan_persistence_locations(self) -> None:
        for root in PERSISTENCE_PATHS:
            if not root.exists():
                continue
            for item in root.glob("*.plist"):
                try:
                    st = item.lstat()
                    if item.is_symlink():
                        self.findings.append(Finding("persistence", "high", "Launch plist is a symlink", str(item), "Symlinked launch entries can hide real payloads."))
                    if item.name.startswith("."):
                        self.findings.append(Finding("persistence", "high", "Hidden launch plist", str(item), "Hidden launch plist can indicate stealth persistence."))
                    if root.as_posix().startswith("/Library") and st.st_uid != 0:
                        self.findings.append(Finding("persistence", "high", "System launch plist not root-owned", str(item), f"Owner UID={st.st_uid}, expected UID 0."))

                    code, plutil_out = self._run_command(["plutil", "-convert", "json", "-o", "-", str(item)], timeout=15)
                    if code != 0:
                        self.findings.append(Finding("persistence", "medium", "Unreadable or malformed launch plist", str(item), plutil_out[:700]))
                        continue

                    data = json.loads(plutil_out)
                    lowered = json.dumps(data).lower()
                    suspicious_tokens = ["base64", "curl", "wget", "python -c", "osascript", "mktemp", "chmod +x"]
                    hits = [tok for tok in suspicious_tokens if tok in lowered]
                    if hits:
                        self.findings.append(Finding("persistence", "high", "Launch plist contains suspicious command patterns", str(item), f"Matched tokens: {', '.join(hits)}"))

                except Exception as exc:
                    self.telemetry["warnings"].append(f"Persistence scan error for {item}: {exc}")

    def _scan_login_items_for_old_broken_irrelevant(self) -> None:
        for root in PERSISTENCE_PATHS:
            if not root.exists():
                continue
            for plist_file in root.glob("*.plist"):
                try:
                    raw = plist_file.read_bytes()
                    data = plistlib.loads(raw)
                    label = str(data.get("Label", plist_file.stem))
                    exec_path = self._parse_plist_exec(data)
                    assessment = self._candidate_reason(label, plist_file, exec_path)
                    if assessment:
                        reason, action = assessment
                        age_days = int((datetime.now(timezone.utc).timestamp() - plist_file.stat().st_mtime) / 86400)
                        self.login_candidates.append(
                            LoginItemCandidate(
                                label=label,
                                plist_path=str(plist_file),
                                exec_path=exec_path,
                                reason=reason,
                                age_days=age_days,
                                suggested_action=action,
                            )
                        )
                except Exception as exc:
                    self.telemetry["warnings"].append(f"Login item parse failed for {plist_file}: {exc}")

    def _scan_cron_and_at_jobs(self) -> None:
        for path in CRON_PATHS:
            if not path.exists():
                continue
            if path.is_file():
                self._inspect_text_job_file(path)
            elif path.is_dir():
                for child in path.iterdir():
                    if child.is_file():
                        self._inspect_text_job_file(child)

    def _inspect_text_job_file(self, path: Path) -> None:
        try:
            content = path.read_text(errors="ignore")[:8000].lower()
        except Exception as exc:
            self.telemetry["warnings"].append(f"Could not read {path}: {exc}")
            return
        suspicious = ["curl ", "wget ", "python -c", "osascript", "base64", "nc -", "bash -i", "zsh -i"]
        hits = [token for token in suspicious if token in content]
        if hits:
            self.findings.append(Finding("scheduled_tasks", "high", "Suspicious cron/at job content", str(path), f"Matched tokens: {', '.join(hits)}"))

    def _scan_running_processes(self) -> None:
        if shutil.which("ps") is None:
            self.telemetry["warnings"].append("ps command not available; skipping process scan.")
            return
        code, output = self._run_command(["ps", "aux"], timeout=25)
        if code != 0:
            self.telemetry["warnings"].append(f"ps aux failed: {output[:300]}")
            return
        for line in output.splitlines()[1:]:
            lowered = line.lower()
            if any(token in lowered for token in ["/tmp/", "osascript", "python -c", "curl ", "wget "]):
                self.findings.append(Finding("runtime", "medium", "Potentially suspicious running command", None, line[:700]))

    def _scan_network_activity(self) -> None:
        if shutil.which("lsof") is None:
            self.telemetry["warnings"].append("lsof not available; skipping network process correlation.")
            return
        code, output = self._run_command(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout=40)
        if code != 0:
            self.telemetry["warnings"].append(f"lsof network scan failed: {output[:300]}")
            return
        suspicious_ports = {1337, 4444, 5555, 6666, 31337}
        for line in output.splitlines()[1:]:
            if "->" not in line:
                continue
            for port in suspicious_ports:
                if f":{port}" in line:
                    self.findings.append(Finding("network", "high", "Connection on suspicious remote port", None, line[:700]))
                    break

    def _should_skip_dir(self, path: str) -> bool:
        if path in DEFAULT_EXCLUDES:
            return True
        if not self.include_hidden and Path(path).name.startswith("."):
            return True
        return False

    @staticmethod
    def _world_writable(st_mode: int) -> bool:
        return bool(st_mode & stat.S_IWOTH)

    @staticmethod
    def _looks_executable(path: Path, st_mode: int) -> bool:
        return bool(st_mode & stat.S_IXUSR) or path.suffix.lower() in SCRIPT_EXTENSIONS

    def _codesign_suspicious(self, file_path: str) -> Optional[str]:
        if shutil.which("codesign") is None:
            return None
        code, output = self._run_command(["codesign", "-dv", "--verbose=2", file_path], timeout=20)
        text = output.lower()
        if code != 0 or "code object is not signed" in text or "not signed at all" in text:
            return "unsigned_or_unverifiable"
        if "authority=" not in text:
            return "missing_authority_chain"
        return None

    def _scan_filesystem(self) -> None:
        scanned = 0
        for root, dirs, files in os.walk(self.scan_root, topdown=True):
            self.telemetry["dirs_scanned"] = int(self.telemetry["dirs_scanned"]) + 1
            dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]

            for name in files:
                fpath = os.path.join(root, name)
                scanned += 1
                self.telemetry["files_scanned"] = scanned
                if scanned >= self.max_files:
                    self.telemetry["warnings"].append(f"Stopped at max-files threshold ({self.max_files}).")
                    return

                try:
                    st = os.lstat(fpath)
                except Exception:
                    continue

                path_obj = Path(fpath)
                lowered = name.lower()
                ext = path_obj.suffix.lower()

                if self._world_writable(st.st_mode) and str(path_obj.parent).startswith("/Applications"):
                    self.findings.append(Finding("permissions", "high", "World-writable file in /Applications", fpath, "App files writable by all users increase tampering risk."))

                if ext in SUSPICIOUS_EXTENSIONS and any(str(path_obj).startswith(str(base)) for base in HIGH_RISK_DIRS if base.exists()):
                    age_days = int((datetime.now(timezone.utc).timestamp() - st.st_mtime) / 86400)
                    sev = "high" if age_days <= 7 and self._looks_executable(path_obj, st.st_mode) else ("medium" if age_days <= 30 else "low")
                    self.findings.append(Finding("suspicious_file", sev, "Potentially risky file in high-risk directory", fpath, f"Extension={ext}, modified={age_days} days ago."))
                    if self.deep_mode and self._looks_executable(path_obj, st.st_mode):
                        sig = self._codesign_suspicious(fpath)
                        if sig:
                            self.findings.append(Finding("signature", "high", "Executable/script appears unsigned or unverifiable", fpath, f"Signature assessment: {sig}"))

                if lowered.endswith(".mobileconfig"):
                    self.findings.append(Finding("config_profile", "medium", "Configuration profile file found", fpath, "Review unknown profiles; malicious profiles can alter trust/traffic settings."))

                if any(k in lowered for k in ["invoice", "payment", "wire", "payroll"]) and ext in {".app", ".dmg", ".pkg", ".zip"}:
                    self.findings.append(Finding("social_engineering", "medium", "Financially themed installer/archive", fpath, "Fraudware often impersonates finance/payroll docs."))

    def _scan_suid_sgid_binaries(self) -> None:
        if shutil.which("find") is None:
            self.telemetry["warnings"].append("find command unavailable; skipping suid/sgid audit.")
            return
        find_cmd = ["find", str(self.scan_root), "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"]
        code, output = self._run_command(find_cmd, timeout=120)
        if code != 0 and not output:
            self.telemetry["warnings"].append("SUID/SGID discovery failed.")
            return
        for line in output.splitlines():
            candidate = line.strip()
            if candidate and not any(candidate.startswith(p) for p in TRUSTED_SUID_PREFIXES):
                self.findings.append(Finding("privilege_escalation", "high", "SUID/SGID binary outside trusted system paths", candidate, "Unexpected privileged binary location; investigate."))

    def _run_clamav_scan(self) -> None:
        if self.skip_clamav:
            return
        clamscan = shutil.which("clamscan")
        if clamscan is None:
            self.telemetry["warnings"].append("ClamAV missing. Install with: brew install clamav")
            return
        _, output = self._run_command([clamscan, "-r", "--infected", "--max-filesize=200M", str(self.scan_root)], timeout=5400)
        lowered = output.lower()
        if "infected files: 0" in lowered:
            return
        if "infected files:" in lowered:
            self.findings.append(Finding("malware_scan", "critical", "ClamAV reported infected files", str(self.scan_root), output[-2500:]))
        else:
            self.telemetry["warnings"].append("ClamAV output inconclusive; review manually.")

    def _write_cleanup_plan(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        plan_path = self.output_dir / "login_item_cleanup_plan.sh"
        lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "# REVIEW FIRST: This script is generated as a suggestion and is NOT auto-run by the scanner.",
            "# It only targets non-Apple launch items identified as broken/stale.",
            "",
        ]

        for item in self.login_candidates:
            if item.label.startswith("com.apple"):
                continue
            plist = item.plist_path
            if any(plist.startswith(prefix) for prefix in APPLE_SAFE_PREFIXES):
                continue
            lines.extend([
                f"echo 'Reviewing {item.label} ({item.reason})'",
                f"launchctl bootout system '{plist}' 2>/dev/null || launchctl bootout gui/$UID '{plist}' 2>/dev/null || true",
                f"pkill -f '{item.label}' 2>/dev/null || true",
                f"# rm -f '{plist}'   # uncomment only after manual review",
                "",
            ])

        plan_path.write_text("\n".join(lines), encoding="utf-8")
        os.chmod(plan_path, 0o700)
        return plan_path

    def _write_reports(self, report: Dict[str, object]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"mac_security_report_{ts}.json"
        md_path = self.output_dir / f"mac_security_report_{ts}.md"
        cleanup_plan = self._write_cleanup_plan()

        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        summary = report["telemetry"]["summary"]
        lines = [
            "# macOS Security Sweep Report",
            "",
            f"- Scan root: `{report['scan_root']}`",
            f"- Deep mode: `{report['deep_mode']}`",
            f"- Generated at: `{report['generated_at']}`",
            f"- Files scanned: `{report['telemetry']['files_scanned']}`",
            f"- Directories scanned: `{report['telemetry']['dirs_scanned']}`",
            f"- Risk score: `{report['telemetry']['risk_score']}` / 100",
            f"- Login cleanup review script: `{cleanup_plan}`",
            "",
            "## Severity Summary",
            f"- Critical: {summary['critical']}",
            f"- High: {summary['high']}",
            f"- Medium: {summary['medium']}",
            f"- Low: {summary['low']}",
            "",
            "## Startup/Login Item Candidates (non-Apple only)",
        ]

        if not self.login_candidates:
            lines.append("No non-Apple broken/stale startup candidates found.")
        else:
            for idx, c in enumerate(self.login_candidates, 1):
                lines.extend([
                    f"### {idx}. {c.label}",
                    f"- Plist: `{c.plist_path}`",
                    f"- Executable: `{c.exec_path or 'N/A'}`",
                    f"- Reason: {c.reason}",
                    f"- Age (days): {c.age_days}",
                    f"- Suggested action: {c.suggested_action}",
                    "",
                ])

        lines.append("## Findings")
        findings = report["findings"]
        if not findings:
            lines.append("No major findings from current heuristics.")
        else:
            for idx, f in enumerate(findings, 1):
                lines.extend([
                    f"### {idx}. {f['title']} ({f['severity'].upper()})",
                    f"- Category: `{f['category']}`",
                    f"- Path: `{f['path'] or 'N/A'}`",
                    f"- Details: {f['details']}",
                    "",
                ])

        warnings = report["telemetry"].get("warnings", [])
        if warnings:
            lines.append("## Warnings")
            for w in warnings:
                lines.append(f"- {w}")

        md_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")
        print(f"Cleanup review script: {cleanup_plan}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plug-and-play deep macOS security sweep (no auto-modification).")
    parser.add_argument("--scan-root", type=Path, default=Path("/"), help="Root path to scan (default: /)")
    parser.add_argument("--max-files", type=int, default=900000, help="Maximum number of files to inspect")
    parser.add_argument("--output-dir", type=Path, default=Path.home() / "Desktop" / "SecuritySweepReports", help="Report directory")
    parser.add_argument("--skip-clamav", action="store_true", help="Skip ClamAV malware scan")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files and folders")
    parser.add_argument("--deep-mode", action="store_true", default=True, help="Enable deeper checks (default: on)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sweep = MacSecuritySweep(
        scan_root=args.scan_root,
        max_files=args.max_files,
        output_dir=args.output_dir,
        skip_clamav=args.skip_clamav,
        include_hidden=args.include_hidden,
        deep_mode=args.deep_mode,
    )
    report = sweep.run()
    summary = report["telemetry"]["summary"]
    exit_code = 1 if summary["critical"] > 0 or summary["high"] > 0 else 0
    print(f"Completed. Risk score: {report['telemetry']['risk_score']} (exit code {exit_code})")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
