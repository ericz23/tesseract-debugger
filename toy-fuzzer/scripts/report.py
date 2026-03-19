#!/usr/bin/env python3
"""
report.py — Parse libFuzzer log files from each experiment configuration
and print a formatted summary table of quantitative metrics.

Usage:
    python3 scripts/report.py results/

libFuzzer log format examples:
    #0      READ units: 5
    #5      NEW    cov: 12 ft: 18 corp: 1/5b exec/s: 0 rss: 46Mb
    #1024   REDUCE cov: 15 ft: 22 corp: 3/14b exec/s: 512 rss: 47Mb
    ==1234== ERROR: AddressSanitizer: stack-buffer-overflow ...
    SUMMARY: AddressSanitizer: stack-buffer-overflow ...
    Done 4096 runs in 60 second(s)
    stat::number_of_executed_units: 4096
    stat::average_exec_per_sec:     68
    stat::new_units_added:          31
    stat::slowest_unit_time_sec:    0
    stat::peak_rss_mb:              47
"""

import os
import re
import sys
from pathlib import Path


CFG_META = {
    "cfg-1": ("None",         "Empty"),
    "cfg-2": ("None",         "Seeded"),
    "cfg-3": ("ASan",         "Empty"),
    "cfg-4": ("ASan",         "Seeded"),
    "cfg-5": ("UBSan",        "Empty"),
    "cfg-6": ("UBSan",        "Seeded"),
    "cfg-7": ("ASan+UBSan",   "Empty"),
    "cfg-8": ("ASan+UBSan",   "Seeded"),
}

# Patterns for libFuzzer progress lines: "#N  KEYWORD  cov: N ft: N corp: X [lim: N] exec/s: N"
# The "lim: N" field is optional (not present on INITED lines but present on later lines).
RE_STAT_LINE  = re.compile(r"#(\d+)\s+\S+\s+cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*\S+(?:\s+lim:\s*\d+)?\s+exec/s:\s*(\d+)")
# Crash marker line: the fuzzer prints the artifact path
RE_CRASH_ART  = re.compile(r"artifact_prefix.*?; Test unit written to (.*crash-\S+)")
# libFuzzer also prints "SUMMARY: ... crash" or ASan/UBSan summaries
RE_CRASH_SUM  = re.compile(r"SUMMARY:\s+(\S+):\s+(\S+)")
# Final stats block
RE_TOTAL_EXEC = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
RE_EXEC_PER_S = re.compile(r"stat::average_exec_per_sec:\s*(\d+)")
# Wall time from "Done N runs in T second(s)"
RE_DONE       = re.compile(r"Done\s+(\d+)\s+runs\s+in\s+(\d+)\s+second")
# libFuzzer progress time — extract from the #N line with a preceding timestamp
# (libFuzzer does not emit wall-clock per line; we approximate crash time by
# checking if a crash artifact appeared and using the run elapsed time from
# the shell script's exit timing or the "Done" line.)
RE_NEW_LINE   = re.compile(r"#(\d+)\s+(NEW|REDUCE|pulse)\s+cov:\s*(\d+)")
RE_EXIT_CODE  = re.compile(r"FUZZER_EXIT_CODE:\s*(\d+)")


def parse_log(log_path: Path) -> dict:
    result = {
        "crash_found":      False,
        "crash_type":       "—",
        "crash_exec":       "—",      # exec count at crash
        "total_exec":       "—",
        "exec_per_sec":     "—",
        "final_cov":        "—",
        "final_ft":         "—",
        "corpus_entries":   "—",
        "run_time_s":       "—",
    }

    if not log_path.exists():
        return result

    text = log_path.read_text(errors="replace")
    lines = text.splitlines()

    last_cov = None
    last_ft  = None
    last_exec_ps = None

    crash_exec = None
    found_crash_line = False

    for i, line in enumerate(lines):
        # Progress stat lines
        m = RE_STAT_LINE.search(line)
        if m:
            last_cov     = int(m.group(2))
            last_ft      = int(m.group(3))
            last_exec_ps = int(m.group(4))

        # Crash artifact — libFuzzer prints the artifact path after the crash
        m = RE_CRASH_ART.search(line)
        if m:
            result["crash_found"] = True
            if crash_exec is None:
                # Walk backwards to find the most recent #N stat/progress line
                for prev in reversed(lines[:i+1]):
                    pm = re.search(r"#(\d+)", prev)
                    if pm:
                        crash_exec = int(pm.group(1))
                        break

        # Crash summary (sanitizer or libFuzzer)
        m = RE_CRASH_SUM.search(line)
        if m and not found_crash_line:
            result["crash_type"]  = f"{m.group(1)}: {m.group(2)}"
            found_crash_line = True

        # Also catch UBSan-style: "runtime error: ..."
        if "runtime error:" in line and not found_crash_line:
            short = line.strip()[:60]
            result["crash_type"]  = f"UBSan: {short}"
            found_crash_line = True
            result["crash_found"] = True
            if crash_exec is None:
                for prev in reversed(lines[:i+1]):
                    pm = re.search(r"#(\d+)", prev)
                    if pm:
                        crash_exec = int(pm.group(1))
                        break

        # Final stats block (only present when fuzzer exits cleanly)
        m = RE_TOTAL_EXEC.search(line)
        if m:
            result["total_exec"] = int(m.group(1))

        m = RE_EXEC_PER_S.search(line)
        if m:
            result["exec_per_sec"] = int(m.group(1))

        m = RE_DONE.search(line)
        if m:
            result["run_time_s"] = int(m.group(2))

        # Detect UBSan abort: exit code 134 (SIGABRT) = crash, even without artifact
        m = RE_EXIT_CODE.search(line)
        if m:
            code = int(m.group(1))
            if code not in (0, 77):  # 77 = max_total_time reached (normal exit)
                result["crash_found"] = True
                if not found_crash_line:
                    result["crash_type"] = f"SIGABRT (exit {code})"
                # For UBSan-only aborts without an artifact line, infer crash exec
                # from the last #N stat line in the log (last corpus reduction point).
                if crash_exec is None:
                    for prev in reversed(lines[:i]):
                        pm = re.search(r"#(\d+)", prev)
                        if pm:
                            crash_exec = int(pm.group(1))
                            break

    if last_cov is not None:
        result["final_cov"] = last_cov
    if last_ft is not None:
        result["final_ft"] = last_ft
    # Use last observed exec/s from progress lines when the stat:: block is absent (crash runs)
    if last_exec_ps is not None and (result["exec_per_sec"] == "—" or result["exec_per_sec"] == 0):
        result["exec_per_sec"] = last_exec_ps

    if crash_exec is not None:
        result["crash_exec"] = crash_exec

    return result


def count_crashes(crash_dir: Path) -> int:
    if not crash_dir.exists():
        return 0
    return len([f for f in crash_dir.iterdir() if f.name.startswith("crash-")])


def count_corpus(corpus_dir: Path) -> int:
    if not corpus_dir.exists():
        return 0
    return len([f for f in corpus_dir.iterdir() if not f.name.startswith(".")])


def main():
    if len(sys.argv) < 2:
        print("Usage: report.py <results_dir>")
        sys.exit(1)

    results_root = Path(sys.argv[1])

    configs = sorted(CFG_META.keys())

    rows = []
    for cfg in configs:
        sanitizer, corpus_type = CFG_META[cfg]
        cfg_dir    = results_root / cfg
        log_file   = cfg_dir / "fuzzer.log"
        crash_dir  = cfg_dir / "crashes"
        corpus_dir = cfg_dir / "corpus"

        metrics = parse_log(log_file)
        n_crashes       = count_crashes(crash_dir)
        n_corpus        = count_corpus(corpus_dir)

        if n_crashes > 0:
            metrics["crash_found"] = True

        metrics["corpus_entries"] = n_corpus

        # Estimate time-to-crash when the stat block is absent (fuzzer aborted on crash)
        # and we have both crash exec count and exec/s from progress lines.
        if (metrics["run_time_s"] == "—" and
                metrics["crash_found"] and
                metrics["crash_exec"] != "—" and
                metrics["exec_per_sec"] not in ("—", 0)):
            est = round(int(metrics["crash_exec"]) / int(metrics["exec_per_sec"]), 1)
            metrics["run_time_s"] = f"~{est}s"

        rows.append((cfg, sanitizer, corpus_type, metrics, n_crashes))

    # -------------------------------------------------------------------------
    # Print summary table
    # -------------------------------------------------------------------------
    SEP = "=" * 120
    print(SEP)
    print("  TOY FUZZER EXPERIMENT — RESULTS SUMMARY")
    print(SEP)
    print()

    header = (
        f"{'Cfg':<6} {'Sanitizer':<14} {'Corpus':<8} "
        f"{'Crashed?':<10} {'Crash type':<35} "
        f"{'Exec@crash':<12} {'Exec/s':<8} "
        f"{'Cov':<6} {'FT':<6} {'Corpus':<8} {'Time(s)':<8}"
    )
    print(header)
    print("-" * 120)

    for (cfg, sanitizer, corpus_type, m, n_crashes) in rows:
        crashed   = "YES" if m["crash_found"] else "no"
        ctype     = (m["crash_type"] or "—")[:34]
        exec_cr   = str(m["crash_exec"])
        exec_ps   = str(m["exec_per_sec"])
        cov       = str(m["final_cov"])
        ft        = str(m["final_ft"])
        corpus_n  = str(m["corpus_entries"])
        time_s    = str(m["run_time_s"])

        print(
            f"{cfg:<6} {sanitizer:<14} {corpus_type:<8} "
            f"{crashed:<10} {ctype:<35} "
            f"{exec_cr:<12} {exec_ps:<8} "
            f"{cov:<6} {ft:<6} {corpus_n:<8} {time_s:<8}"
        )

    print()
    print(SEP)
    print()
    print("METRIC DEFINITIONS:")
    print("  Cfg         — experiment configuration ID (1–8)")
    print("  Sanitizer   — memory/UB sanitizer(s) linked into the fuzzer binary")
    print("  Corpus      — whether curated seed inputs were provided at start")
    print("  Crashed?    — did the fuzzer find any crash within the 60s budget?")
    print("  Crash type  — sanitizer report or 'runtime error' from the first crash")
    print("  Exec@crash  — #executions elapsed when first crash was found")
    print("  Exec/s      — fuzzer throughput (executions per second)")
    print("  Cov         — edge coverage count at end of run")
    print("  FT          — feature count at end of run (finer coverage metric)")
    print("  Corpus      — number of interesting inputs accumulated in corpus")
    print("  Time(s)     — total wall-clock time of the run")
    print()


if __name__ == "__main__":
    main()
