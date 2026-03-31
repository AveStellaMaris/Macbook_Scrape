#!/usr/bin/env python3
"""
mac_security_sweep.py

Defensive macOS sweep + optional non-destructive quarantine workflow.
- Scan stage: persistence, startup/login items, cron/at, process/network heuristics,
  risky files, optional SUID/SGID review, optional ClamAV.
- Cleanup stage (optional): auto-generate and optionally execute a quarantine plan
  for high-confidence non-Apple startup items.
"""

from __future__ import annotations

import argparse
import csv
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

SUSPICIOUS_EXTENSIONS = {".app", ".command", ".dmg", ".pkg", ".mpkg", ".sh", ".zsh", ".bash", ".py", ".js", ".jar", ".iso", ".exe", ".scr"}
SCRIPT_EXTENSIONS = {".sh", ".zsh", ".bash", ".command", ".py", ".js"}
HIGH_RISK_DIRS = [Path.home() / "Downloads", Path.home() / "Desktop", Path.home() / "Documents", Path("/tmp")]
PERSISTENCE_PATHS = [Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"), Path("/private/var/root/Library/LaunchAgents")]
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
    confidence: str = "medium"


@dataclass
class LoginItemCandidate:
    label: str
    plist_path: str
    exec_path: Optional[str]
    reason: str
    age_days: int
    suggested_action: str
    confidence: str
    vendor: str


class MacSecuritySweep:
    def __init__(self, scan_root: Path, max_files: int, output_dir: Path, skip_clamav: bool, include_hidden: bool, deep_mode: bool, auto_quarantine: bool) -> None:
        self.scan_root = scan_root
        self.max_files = max_files
        self.output_dir = output_dir
        self.skip_clamav = skip_clamav
        self.include_hidden = include_hidden
        self.deep_mode = deep_mode
        self.auto_quarantine = auto_quarantine
        self.findings: List[Finding] = []
        self.login_candidates: List[LoginItemCandidate] = []
        self.telemetry: Dict[str, object] = {
            "files_scanned": 0,
            "dirs_scanned": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "warnings": [],
            "errors": [],
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
        self._dedupe_login_candidates()

        ended = datetime.now(timezone.utc)
        self.telemetry["end_time"] = ended.isoformat()
        self.telemetry["risk_score"] = self._risk_score()
        self.telemetry["summary"] = self._summary()
        self.telemetry["vendor_groups"] = self._vendor_groups()

        report = {
            "scan_root": str(self.scan_root),
            "deep_mode": self.deep_mode,
            "auto_quarantine": self.auto_quarantine,
            "telemetry": self.telemetry,
            "findings": [asdict(f) for f in self.findings],
            "login_item_candidates": [asdict(c) for c in self.login_candidates],
            "generated_at": ended.isoformat(),
        }
        self._write_reports(report)
        if self.auto_quarantine:
            self._run_quarantine_script(mode="apply")
        return report

    def _check_platform(self) -> None:
        if sys.platform != "darwin":
            self.telemetry["warnings"].append("This tool is optimized for macOS. Non-macOS results may be partial.")

    def _summary(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def _risk_score(self) -> int:
        weights = {"critical": 30, "high": 10, "medium": 4, "low": 1}
        return min(sum(weights.get(f.severity, 0) for f in self.findings), 100)

    def _vendor_groups(self) -> Dict[str, int]:
        grouped: Dict[str, int] = {}
        for c in self.login_candidates:
            grouped[c.vendor] = grouped.get(c.vendor, 0) + 1
        return dict(sorted(grouped.items(), key=lambda kv: (-kv[1], kv[0])))

    def _run_command(self, command: List[str], timeout: int = 45) -> Tuple[int, str, bool]:
        self.telemetry["commands"].append(" ".join(command))
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            out = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            return result.returncode, out.strip(), False
        except subprocess.TimeoutExpired:
            msg = f"TIMEOUT after {timeout}s: {' '.join(command)}"
            self.telemetry["warnings"].append(msg)
            return 124, msg, True
        except Exception as exc:
            msg = f"COMMAND_ERROR: {exc}"
            self.telemetry["errors"].append(msg)
            return 127, msg, False

    def _collect_system_security_status(self) -> None:
        checks = {
            "Gatekeeper": ["spctl", "--status"],
            "SIP": ["csrutil", "status"],
            "Firewall": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            "XProtect": ["defaults", "read", "/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString"],
            "MRT": ["defaults", "read", "/System/Library/CoreServices/MRT.app/Contents/Info", "CFBundleShortVersionString"],
        }
        for name, cmd in checks.items():
            if shutil.which(cmd[0]) is None and not cmd[0].startswith("/"):
                self.telemetry["warnings"].append(f"Missing command for {name}: {cmd[0]}")
                continue
            _, output, timed_out = self._run_command(cmd)
            if timed_out or output.startswith("COMMAND_ERROR"):
                continue
            lowered = output.lower()
            disabled = "disabled" in lowered or "unknown" in lowered
            if name == "Gatekeeper" and "assessments enabled" in lowered:
                disabled = False
            if name == "Firewall" and "enabled" in lowered:
                disabled = False
            if disabled:
                self.findings.append(Finding("system_security", "medium", f"{name} may be disabled", None, output[:700], "high"))

    @staticmethod
    def _vendor_from_label(label: str) -> str:
        label = label.lower()
        if label.startswith("com."):
            parts = label.split(".")
            if len(parts) >= 2 and parts[1]:
                return parts[1]
        return label.split(".")[0] if "." in label else label

    def _parse_plist_exec(self, plist_data: dict) -> Optional[str]:
        prog = plist_data.get("Program")
        if isinstance(prog, str) and prog.strip():
            return prog.strip()
        args = plist_data.get("ProgramArguments")
        if isinstance(args, list) and args and isinstance(args[0], str):
            return args[0].strip()
        return None

    def _is_apple_or_core_path(self, path: Optional[str]) -> bool:
        return bool(path and any(path.startswith(prefix) for prefix in APPLE_SAFE_PREFIXES))

    def _candidate_reason(self, label: str, plist_path: Path, exec_path: Optional[str]) -> Optional[Tuple[str, str, str]]:
        age_days = int((datetime.now(timezone.utc).timestamp() - plist_path.stat().st_mtime) / 86400)
        if label.startswith("com.apple"):
            return None
        if exec_path:
            resolved = str(Path(exec_path))
            if self._is_apple_or_core_path(resolved):
                return None
            if not Path(resolved).exists():
                return (f"Broken startup item (missing executable): {resolved}", "quarantine", "high")
        else:
            return ("Missing Program/ProgramArguments", "quarantine", "high")
        if age_days >= 365:
            return (f"Old third-party startup item ({age_days} days)", "review_quarantine", "medium")
        if any(k in label.lower() for k in ["update", "helper", "agent", "daemon"]):
            return ("Potentially stale helper/agent", "review_quarantine", "low")
        return None

    def _scan_persistence_locations(self) -> None:
        for root in PERSISTENCE_PATHS:
            if not root.exists():
                continue
            for item in root.glob("*.plist"):
                try:
                    st = item.lstat()
                    if item.is_symlink():
                        self.findings.append(Finding("persistence", "high", "Launch plist is a symlink", str(item), "Symlinked launch entry can hide payloads.", "high"))
                    if item.name.startswith("."):
                        self.findings.append(Finding("persistence", "high", "Hidden launch plist", str(item), "Hidden persistence artifact.", "high"))
                    if root.as_posix().startswith("/Library") and st.st_uid != 0:
                        self.findings.append(Finding("persistence", "high", "System launch plist not root-owned", str(item), f"Owner UID={st.st_uid}", "high"))

                    code, out, timed_out = self._run_command(["plutil", "-convert", "json", "-o", "-", str(item)], timeout=20)
                    if timed_out or code != 0:
                        self.telemetry["warnings"].append(f"Could not parse plist for heuristic review: {item}")
                        continue
                    data = json.loads(out)
                    lowered = json.dumps(data).lower()
                    tokens = ["base64", "curl", "wget", "python -c", "osascript", "mktemp", "chmod +x"]
                    hits = [tok for tok in tokens if tok in lowered]
                    if hits:
                        self.findings.append(Finding("persistence", "high", "Launch plist contains suspicious tokens", str(item), f"Matched: {', '.join(hits)}", "medium"))
                except Exception as exc:
                    self.telemetry["warnings"].append(f"Persistence scan error for {item}: {exc}")

    def _scan_login_items_for_old_broken_irrelevant(self) -> None:
        for root in PERSISTENCE_PATHS:
            if not root.exists():
                continue
            for plist_file in root.glob("*.plist"):
                try:
                    data = plistlib.loads(plist_file.read_bytes())
                    label = str(data.get("Label", plist_file.stem))
                    exec_path = self._parse_plist_exec(data)
                    assessment = self._candidate_reason(label, plist_file, exec_path)
                    if assessment:
                        reason, action, confidence = assessment
                        age_days = int((datetime.now(timezone.utc).timestamp() - plist_file.stat().st_mtime) / 86400)
                        self.login_candidates.append(LoginItemCandidate(
                            label=label,
                            plist_path=str(plist_file),
                            exec_path=exec_path,
                            reason=reason,
                            age_days=age_days,
                            suggested_action=action,
                            confidence=confidence,
                            vendor=self._vendor_from_label(label),
                        ))
                except Exception as exc:
                    self.telemetry["warnings"].append(f"Login item parse failed for {plist_file}: {exc}")

    def _dedupe_login_candidates(self) -> None:
        seen = {}
        for c in self.login_candidates:
            key = (c.label, c.plist_path)
            if key not in seen:
                seen[key] = c
        self.login_candidates = list(seen.values())

    def _scan_cron_and_at_jobs(self) -> None:
        for path in CRON_PATHS:
            if not path.exists():
                continue
            if path.is_file():
                self._inspect_text_job_file(path)
            elif path.is_dir():
                try:
                    for child in path.iterdir():
                        if child.is_file():
                            self._inspect_text_job_file(child)
                except PermissionError:
                    self.telemetry["warnings"].append(f"Permission denied reading cron directory: {path}")
                except OSError as exc:
                    self.telemetry["warnings"].append(f"Could not inspect cron directory {path}: {exc}")

    def _inspect_text_job_file(self, path: Path) -> None:
        try:
            content = path.read_text(errors="ignore")[:12000].lower()
        except Exception as exc:
            self.telemetry["warnings"].append(f"Could not read {path}: {exc}")
            return
        hits = [t for t in ["curl ", "wget ", "python -c", "osascript", "base64", "nc -", "bash -i", "zsh -i"] if t in content]
        if hits:
            self.findings.append(Finding("scheduled_tasks", "high", "Suspicious cron/at content", str(path), f"Matched tokens: {', '.join(hits)}", "medium"))

    def _scan_running_processes(self) -> None:
        if shutil.which("ps") is None:
            self.telemetry["warnings"].append("ps command not available; skipping process scan.")
            return
        code, out, timed_out = self._run_command(["ps", "aux"], timeout=30)
        if timed_out or code != 0:
            return
        for line in out.splitlines()[1:]:
            low = line.lower()
            if any(t in low for t in ["/tmp/", "osascript", "python -c", "curl ", "wget "]):
                self.findings.append(Finding("runtime", "medium", "Potentially suspicious running command", None, line[:700], "low"))

    def _scan_network_activity(self) -> None:
        if shutil.which("lsof") is None:
            self.telemetry["warnings"].append("lsof not available; skipping network scan.")
            return
        code, out, timed_out = self._run_command(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout=45)
        if timed_out or code != 0:
            return
        for line in out.splitlines()[1:]:
            if "->" in line and any(f":{p}" in line for p in [1337, 4444, 5555, 6666, 31337]):
                self.findings.append(Finding("network", "high", "Connection on suspicious port", None, line[:700], "low"))

    def _should_skip_dir(self, path: str) -> bool:
        return path in DEFAULT_EXCLUDES or (not self.include_hidden and Path(path).name.startswith("."))

    @staticmethod
    def _world_writable(st_mode: int) -> bool:
        return bool(st_mode & stat.S_IWOTH)

    @staticmethod
    def _looks_executable(path: Path, st_mode: int) -> bool:
        return bool(st_mode & stat.S_IXUSR) or path.suffix.lower() in SCRIPT_EXTENSIONS

    def _codesign_suspicious(self, file_path: str) -> Optional[str]:
        if shutil.which("codesign") is None:
            return None
        code, out, timed_out = self._run_command(["codesign", "-dv", "--verbose=2", file_path], timeout=20)
        if timed_out:
            return None
        txt = out.lower()
        if code != 0 or "not signed" in txt:
            return "unsigned_or_unverifiable"
        if "authority=" not in txt:
            return "missing_authority_chain"
        return None

    def _scan_filesystem(self) -> None:
        scanned = 0
        for root, dirs, files in os.walk(self.scan_root, topdown=True):
            self.telemetry["dirs_scanned"] = int(self.telemetry["dirs_scanned"]) + 1
            dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]
            for name in files:
                scanned += 1
                self.telemetry["files_scanned"] = scanned
                if scanned >= self.max_files:
                    self.telemetry["warnings"].append(f"Stopped at max-files threshold ({self.max_files}).")
                    return
                fpath = os.path.join(root, name)
                try:
                    st = os.lstat(fpath)
                except Exception:
                    continue
                p = Path(fpath)
                low = name.lower()
                ext = p.suffix.lower()

                if self._world_writable(st.st_mode) and str(p.parent).startswith("/Applications"):
                    self.findings.append(Finding("permissions", "high", "World-writable file in /Applications", fpath, "Increased tampering risk.", "high"))

                if ext in SUSPICIOUS_EXTENSIONS and any(str(p).startswith(str(base)) for base in HIGH_RISK_DIRS if base.exists()):
                    age_days = int((datetime.now(timezone.utc).timestamp() - st.st_mtime) / 86400)
                    sev = "high" if age_days <= 7 and self._looks_executable(p, st.st_mode) else ("medium" if age_days <= 30 else "low")
                    self.findings.append(Finding("suspicious_file", sev, "Potentially risky file in high-risk directory", fpath, f"Extension={ext}, modified={age_days} days", "low"))
                    if self.deep_mode and self._looks_executable(p, st.st_mode):
                        sig = self._codesign_suspicious(fpath)
                        if sig:
                            self.findings.append(Finding("signature", "high", "Executable appears unsigned/unverifiable", fpath, f"Signature assessment: {sig}", "medium"))

                if low.endswith(".mobileconfig"):
                    if not str(p).startswith("/System") and "com.apple" not in low:
                        self.findings.append(Finding("config_profile", "medium", "Non-Apple configuration profile found", fpath, "Review unknown profiles.", "medium"))

                if any(k in low for k in ["invoice", "payment", "wire", "payroll"]) and ext in {".app", ".dmg", ".pkg", ".zip"}:
                    self.findings.append(Finding("social_engineering", "medium", "Financially themed installer/archive", fpath, "Fraudware often impersonates finance docs.", "low"))

    def _scan_suid_sgid_binaries(self) -> None:
        if shutil.which("find") is None:
            self.telemetry["warnings"].append("find command unavailable; skipping suid/sgid audit.")
            return
        code, out, timed_out = self._run_command(["find", str(self.scan_root), "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"], timeout=180)
        if timed_out:
            return
        if code != 0 and not out:
            self.telemetry["warnings"].append("SUID/SGID discovery failed.")
            return
        for line in out.splitlines():
            candidate = line.strip()
            if not candidate.startswith("/"):
                continue
            if not any(candidate.startswith(prefix) for prefix in TRUSTED_SUID_PREFIXES):
                self.findings.append(Finding("privilege_escalation", "high", "SUID/SGID binary outside trusted paths", candidate, "Unexpected privileged binary location.", "medium"))

    def _run_clamav_scan(self) -> None:
        if self.skip_clamav:
            return
        clamscan = shutil.which("clamscan")
        if clamscan is None:
            self.telemetry["warnings"].append("ClamAV missing. No antivirus scan was run.")
            return
        freshclam = shutil.which("freshclam")
        if freshclam:
            _, _, _ = self._run_command([freshclam], timeout=600)
        _, out, timed_out = self._run_command([clamscan, "-r", "--infected", "--max-filesize=200M", str(self.scan_root)], timeout=7200)
        if timed_out:
            return
        low = out.lower()
        if "infected files: 0" in low:
            return
        if "infected files:" in low:
            self.findings.append(Finding("malware_scan", "critical", "ClamAV reported infected files", str(self.scan_root), out[-2500:], "high"))
        else:
            self.telemetry["warnings"].append("ClamAV output inconclusive; review manually.")

    def _cleanup_candidates_for_quarantine(self) -> List[LoginItemCandidate]:
        return [c for c in self.login_candidates if c.suggested_action in {"quarantine", "review_quarantine"} and c.confidence in {"high", "medium"} and not c.label.startswith("com.apple")]

    def _write_cleanup_manifest_csv(self, candidates: List[LoginItemCandidate]) -> Path:
        path = self.output_dir / "cleanup_manifest.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["label", "vendor", "plist_path", "exec_path", "reason", "confidence", "suggested_action"])
            for c in candidates:
                writer.writerow([c.label, c.vendor, c.plist_path, c.exec_path or "", c.reason, c.confidence, c.suggested_action])
        return path

    def _write_cleanup_plan(self, candidates: List[LoginItemCandidate]) -> Path:
        plan = self.output_dir / "login_item_cleanup_plan.sh"
        lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "MODE=${1:-dry-run}",
            "TS=$(date +%Y%m%d_%H%M%S)",
            "AUDIT_DIR=\"$HOME/Desktop/SecuritySweepReports\"",
            "mkdir -p \"$AUDIT_DIR\" \"/Library/LaunchAgents_DISABLED\" \"/Library/LaunchDaemons_DISABLED\" \"$HOME/Library/LaunchAgents_DISABLED\"",
            "AUDIT_CSV=\"$AUDIT_DIR/quarantine_actions_$TS.csv\"",
            "echo 'timestamp,label,plist,action,result' > \"$AUDIT_CSV\"",
            "run(){ if [[ \"$MODE\" == \"apply\" ]]; then eval \"$1\"; else echo \"[DRY-RUN] $1\"; fi; }",
            "",
        ]
        for c in candidates:
            p = c.plist_path
            lines.extend([
                f"echo 'Processing {c.label} ({c.reason})'",
                f"run \"launchctl bootout system '{p}' 2>/dev/null || launchctl bootout gui/$UID '{p}' 2>/dev/null || true\"",
                f"run \"pkill -f '{c.label}' 2>/dev/null || true\"",
                f"if [[ '{p}' == /Library/LaunchAgents/* ]]; then run \"mv '{p}' /Library/LaunchAgents_DISABLED/\"; fi",
                f"if [[ '{p}' == /Library/LaunchDaemons/* ]]; then run \"mv '{p}' /Library/LaunchDaemons_DISABLED/\"; fi",
                f"if [[ '{p}' == $HOME/Library/LaunchAgents/* ]]; then run \"mv '{p}' $HOME/Library/LaunchAgents_DISABLED/\"; fi",
                f"echo \"$(date -u +%FT%TZ),{c.label},{p},quarantine,$MODE\" >> \"$AUDIT_CSV\"",
                "",
            ])
        plan.write_text("\n".join(lines), encoding="utf-8")
        os.chmod(plan, 0o700)
        return plan

    def _run_quarantine_script(self, mode: str) -> None:
        plan = self.output_dir / "login_item_cleanup_plan.sh"
        if not plan.exists():
            self.telemetry["warnings"].append("Cleanup plan missing; auto-quarantine skipped.")
            return
        _, _, _ = self._run_command(["bash", str(plan), mode], timeout=1800)

    def _write_reports(self, report: Dict[str, object]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"mac_security_report_{ts}.json"
        md_path = self.output_dir / f"mac_security_report_{ts}.md"

        candidates = self._cleanup_candidates_for_quarantine()
        manifest = self._write_cleanup_manifest_csv(candidates)
        plan = self._write_cleanup_plan(candidates)

        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        summary = report["telemetry"]["summary"]
        lines = [
            "# macOS Security Sweep Report",
            "",
            f"- Scan root: `{report['scan_root']}`",
            f"- Deep mode: `{report['deep_mode']}`",
            f"- Auto quarantine: `{report['auto_quarantine']}`",
            f"- Files scanned: `{report['telemetry']['files_scanned']}`",
            f"- Risk score: `{report['telemetry']['risk_score']}` / 100",
            f"- Cleanup manifest CSV: `{manifest}`",
            f"- Cleanup script: `{plan}`",
            "",
            "## Severity Summary",
            f"- Critical: {summary['critical']}",
            f"- High: {summary['high']}",
            f"- Medium: {summary['medium']}",
            f"- Low: {summary['low']}",
            "",
            "## Vendor Grouping (startup items)",
        ]
        vendor_groups = report["telemetry"].get("vendor_groups", {})
        if vendor_groups:
            for k, v in vendor_groups.items():
                lines.append(f"- {k}: {v}")
        else:
            lines.append("- None")

        lines.append("\n## Startup/Login Item Candidates")
        if not self.login_candidates:
            lines.append("No non-Apple startup candidates found.")
        else:
            for i, c in enumerate(self.login_candidates, 1):
                lines.extend([
                    f"### {i}. {c.label}",
                    f"- Vendor: `{c.vendor}`",
                    f"- Confidence: `{c.confidence}`",
                    f"- Plist: `{c.plist_path}`",
                    f"- Executable: `{c.exec_path or 'N/A'}`",
                    f"- Reason: {c.reason}",
                    f"- Suggested action: {c.suggested_action}",
                    "",
                ])

        lines.append("## Findings")
        if not report["findings"]:
            lines.append("No major findings from current heuristics.")
        else:
            for i, f in enumerate(report["findings"], 1):
                lines.extend([
                    f"### {i}. {f['title']} ({f['severity'].upper()})",
                    f"- Category: `{f['category']}`",
                    f"- Confidence: `{f['confidence']}`",
                    f"- Path: `{f['path'] or 'N/A'}`",
                    f"- Details: {f['details']}",
                    "",
                ])

        warns = report["telemetry"].get("warnings", [])
        errs = report["telemetry"].get("errors", [])
        if warns:
            lines.append("## Warnings")
            lines.extend([f"- {w}" for w in warns])
        if errs:
            lines.append("## Errors")
            lines.extend([f"- {e}" for e in errs])

        md_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")
        print(f"Cleanup manifest CSV: {manifest}")
        print(f"Cleanup script: {plan}")
        print("Run cleanup script manually:")
        print(f"  bash '{plan}' dry-run")
        print(f"  bash '{plan}' apply")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="macOS security sweep + optional quarantine automation")
    p.add_argument("--scan-root", type=Path, default=Path("/"), help="Root path to scan")
    p.add_argument("--max-files", type=int, default=900000, help="Maximum files to inspect")
    p.add_argument("--output-dir", type=Path, default=Path.home() / "Desktop" / "SecuritySweepReports", help="Report directory")
    p.add_argument("--skip-clamav", action="store_true", help="Skip ClamAV scan")
    p.add_argument("--include-hidden", action="store_true", help="Include hidden dirs/files")
    p.add_argument("--deep-mode", action="store_true", default=True, help="Enable deeper checks")
    p.add_argument("--auto-quarantine", action="store_true", help="After scan, execute cleanup plan in apply mode (non-destructive move, no delete)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    sweep = MacSecuritySweep(
        scan_root=args.scan_root,
        max_files=args.max_files,
        output_dir=args.output_dir,
        skip_clamav=args.skip_clamav,
        include_hidden=args.include_hidden,
        deep_mode=args.deep_mode,
        auto_quarantine=args.auto_quarantine,
    )
    report = sweep.run()
    summary = report["telemetry"]["summary"]
    code = 1 if summary["critical"] > 0 or summary["high"] > 0 else 0
    print(f"Completed. Risk score: {report['telemetry']['risk_score']} (exit code {code})")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
