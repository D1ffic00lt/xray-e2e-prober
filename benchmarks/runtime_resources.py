#!/usr/bin/env python3
"""Short, reproducible idle-resource sample for managed real-Xray runtimes."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

from xray_e2e_prober.runtime import XrayRuntimeManager


VLESS_URI = (
    "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443"
    "?encryption=none&security=tls&type=raw&sni=example.com#benchmark"
)


def _status(pid: int) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            values["rss_kib"] = int(line.split()[1])
        elif line.startswith("Threads:"):
            values["threads"] = int(line.split()[1])
    values["fds"] = len(tuple(Path(f"/proc/{pid}/fd").iterdir()))
    return values


def _cpu_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    # The command name is parenthesized and may contain spaces.
    fields = raw[raw.rfind(")") + 2 :].split()
    return int(fields[11]) + int(fields[12])


async def _sample(size: int, seconds: float, binary: str) -> dict[str, Any]:
    manager = XrayRuntimeManager(binary, startup_timeout=5, config_test_timeout=5)
    started_at = time.monotonic()
    runtimes = []
    try:
        for _ in range(size):
            runtimes.append(
                await manager.start_for({"payload": VLESS_URI}, "connection")
            )
        startup_seconds = time.monotonic() - started_at
        pids = [os.getpid(), *(runtime.process.pid for runtime in runtimes)]
        before = {pid: _cpu_ticks(pid) for pid in pids}
        await asyncio.sleep(seconds)
        after = {pid: _cpu_ticks(pid) for pid in pids}
        statuses = {pid: _status(pid) for pid in pids}
        ticks = sum(after[pid] - before[pid] for pid in pids)
        clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        xray_pids = pids[1:]
        return {
            "managed_configs": size,
            "sample_seconds": seconds,
            "startup_seconds": round(startup_seconds, 3),
            "processes": len(pids),
            "threads": sum(item["threads"] for item in statuses.values()),
            "open_fds": sum(item["fds"] for item in statuses.values()),
            "controller_rss_mib": round(statuses[pids[0]].get("rss_kib", 0) / 1024, 2),
            "xray_rss_mib": round(
                sum(statuses[pid].get("rss_kib", 0) for pid in xray_pids) / 1024, 2
            ),
            "total_rss_mib": round(
                sum(item.get("rss_kib", 0) for item in statuses.values()) / 1024, 2
            ),
            "idle_cpu_percent_one_core": round(
                ticks / clock_ticks / seconds * 100, 2
            ),
        }
    finally:
        await manager.close()


async def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1,4,8")
    parser.add_argument("--sample-seconds", type=float, default=1.0)
    parser.add_argument("--xray-binary", default=os.environ.get("XRAY_BINARY", "xray"))
    args = parser.parse_args()
    sizes = [int(value) for value in args.sizes.split(",")]
    if not sizes or any(value < 1 for value in sizes):
        parser.error("sizes must be positive integers")
    if args.sample_seconds <= 0:
        parser.error("sample-seconds must be positive")
    results = [
        await _sample(size, args.sample_seconds, args.xray_binary) for size in sizes
    ]
    print(
        json.dumps(
            {
                "schema_version": 1,
                "python": os.sys.version.split()[0],
                "xray_binary": args.xray_binary,
                "workload": "idle managed VLESS RAW/TLS configs; no target requests",
                "results": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(_main())
