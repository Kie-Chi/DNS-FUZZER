from __future__ import annotations
from typing import Dict, Any, List, Tuple, Set, Optional
from collections import Counter, defaultdict
from pathlib import Path
import time
import json

from ..utils.logger import get_logger

logger = get_logger(__name__)


CacheItem = Tuple[str, str, str, bool]


def _extract_cache_added(entry: Dict[str, Any]) -> Set[CacheItem]:
    """Extract normalized cache 'added' items from a DNS-Monitor cache entry."""
    items: Set[CacheItem] = set()
    try:
        diff = entry.get("diff") or {}
        added = diff.get("added") or []
        for it in added:
            name = str(it.get("name", ""))
            rtype = str(it.get("rtype", ""))
            rdata = str(it.get("rdata", ""))
            is_neg = bool(it.get("is_neg", False))
            items.add((name, rtype, rdata, is_neg))
    except Exception as e:
        logger.debug(f"Failed to extract cache added items: {e}")
    return items


def _extract_resolver_tx(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a compact resolver transaction snapshot."""
    tx = entry.get("transaction") or {}
    return {
        "query_name": tx.get("query_name"),
        "query_type": tx.get("query_type"),
        "rcode": tx.get("rcode"),
        "answer_count": tx.get("answer_count"),
        "duration": tx.get("duration"),
        "status": tx.get("status"),
    }


class CompareEngine:
    """Maintain a rolling window of monitor results and compute comparisons."""

    def __init__(
        self,
        window_size: int = 10,
        enable_cache_compare: bool = True,
        enable_resolver_compare: bool = True,
    ) -> None:
        self.window: List[Dict[str, Any]] = []
        self.window_size = max(1, int(window_size))
        self.enable_cache_compare = enable_cache_compare
        self.enable_resolver_compare = enable_resolver_compare

    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a monitor result into the rolling window."""
        self.window.append(result)
        if len(self.window) > self.window_size:
            self.window.pop(0)

    def compute_summary(self) -> Dict[str, Any]:
        """Compute a comparison summary across current window."""
        summary: Dict[str, Any] = {
            "timestamp": time.time(),
            "window_size": len(self.window),
            "cache": {},
            "resolver": {},
        }

        if not self.window:
            summary["message"] = "No data in window"
            return summary

        # Cache comparison across sources and window
        if self.enable_cache_compare:
            # Track per-source item frequencies
            source_counters: Dict[str, Counter] = defaultdict(Counter)
            # Latest snapshot cross-source diffs (from most recent result)
            latest = self.window[-1]
            latest_cache_sources = {k: v for k, v in latest.items() if k.startswith("cache:")}
            latest_sets: Dict[str, Set[CacheItem]] = {}
            for src, entry in latest_cache_sources.items():
                latest_sets[src] = _extract_cache_added(entry)

            # Build window counters
            for res in self.window:
                for src, entry in res.items():
                    if not src.startswith("cache:"):
                        continue
                    items = _extract_cache_added(entry)
                    for it in items:
                        source_counters[src][it] += 1

            # Compute cross-source differences for latest
            cross_diffs: Dict[str, Any] = {}
            sources = list(latest_sets.keys())
            if len(sources) >= 2:
                for i in range(len(sources)):
                    for j in range(i + 1, len(sources)):
                        s1, s2 = sources[i], sources[j]
                        only_s1 = sorted(list(latest_sets[s1] - latest_sets[s2]))
                        only_s2 = sorted(list(latest_sets[s2] - latest_sets[s1]))
                        both = sorted(list(latest_sets[s1] & latest_sets[s2]))
                        cross_diffs[f"{s1} vs {s2}"] = {
                            "only_left": only_s1[:25],
                            "only_right": only_s2[:25],
                            "intersection": both[:25],
                        }

            # Top frequent items per source
            top_per_source: Dict[str, List[Tuple[CacheItem, int]]] = {}
            for src, counter in source_counters.items():
                top_per_source[src] = counter.most_common(25)

            summary["cache"] = {
                "latest_cross_diffs": cross_diffs,
                "top_items_per_source": {
                    src: [
                        {
                            "item": {
                                "name": it[0],
                                "rtype": it[1],
                                "rdata": it[2],
                                "is_neg": it[3],
                            },
                            "count": cnt,
                        }
                        for it, cnt in top_per_source[src]
                    ]
                    for src in top_per_source
                },
            }

        # Resolver comparison across window
        if self.enable_resolver_compare:
            # Aggregate basic stats per resolver source
            durations: Dict[str, List[float]] = defaultdict(list)
            rcode_counts: Dict[str, Counter] = defaultdict(Counter)
            answer_counts: Dict[str, List[int]] = defaultdict(list)

            for res in self.window:
                for src, entry in res.items():
                    if not src.startswith("resolver:"):
                        continue
                    tx = _extract_resolver_tx(entry)
                    dur = tx.get("duration")
                    ans = tx.get("answer_count")
                    rcode = tx.get("rcode")
                    if isinstance(dur, (int, float)):
                        durations[src].append(float(dur))
                    if isinstance(ans, int):
                        answer_counts[src].append(ans)
                    if rcode:
                        rcode_counts[src][rcode] += 1

            resolver_summary: Dict[str, Any] = {}
            for src in set(list(durations.keys()) + list(rcode_counts.keys()) + list(answer_counts.keys())):
                dur_list = durations.get(src, [])
                avg_duration = sum(dur_list) / len(dur_list) if dur_list else None
                rcode_top = rcode_counts.get(src, Counter()).most_common(3)
                ans_list = answer_counts.get(src, [])
                avg_answers = sum(ans_list) / len(ans_list) if ans_list else None
                resolver_summary[src] = {
                    "avg_duration": avg_duration,
                    "rcode_top": rcode_top,
                    "avg_answers": avg_answers,
                    "samples": len(dur_list) if dur_list else 0,
                }

            summary["resolver"] = resolver_summary

        return summary

    def save_summary(self, output_dir: Path, summary: Optional[Dict[str, Any]] = None) -> Path:
        """Save comparison summary to a JSON file and return the path."""
        if summary is None:
            summary = self.compute_summary()
        ts = int(time.time())
        out = output_dir / f"compare_{ts}.json"
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
            logger.debug(f"Saved compare summary to {out}")
        except Exception as e:
            logger.error(f"Failed to save compare summary: {e}")
        return out