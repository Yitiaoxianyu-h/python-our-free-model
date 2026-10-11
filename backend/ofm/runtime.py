"""两个产品入口共用的模型运行时。

创建不启动网络任务；入口先绑定本地监听器，再决定何时刷新和探测。
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Callable

from .adapter import FreeModelAdapter, ROUTE_MAIN, ROUTE_REGION
from .catalog import (
    build_catalog,
    build_eac_catalog,
    build_kilo_catalog,
    is_eac_entry,
    is_kilo_entry,
    parse_listing,
    revive_kilo_catalog,
)
from .http_client import CODE, get_json
from .kilo import fetch_kilo_listing
from .probe import STATE, detect_egress, probe_catalog
from .store import (
    AVAILABILITY_INITIAL,
    SETTINGS_INITIAL,
    STATS_INITIAL,
    STATS_VERSION,
    JsonStore,
    migrate_stats,
    prune_days,
    record_turn,
    record_usage,
)
from .upstream import mint_request_id, session_for_conversation

FALLBACK_IDS = [
    "mimo-v2.6-flash-free", "mimo-v2.5-free", "ling-3.0-flash-fin-free",
    "nemotron-3-ultra-free", "nemotron-3.5-lightning-free", "space-bunny-free",
    "muse-spark-1.3-contributor-free", "muse-spark-1.2-contributor-free",
]
FALLBACK_CATALOG = build_catalog(FALLBACK_IDS)


def create_runtime_stores(data_dir: str) -> dict:
    os.makedirs(data_dir, exist_ok=True)
    def open_store(name, initial):
        return JsonStore(os.path.join(data_dir, name), initial)
    settings = open_store("settings.json", SETTINGS_INITIAL)
    stats = open_store("stats.json", STATS_INITIAL)
    availability = open_store("availability.json", AVAILABILITY_INITIAL)
    catalog_store = open_store("catalog.json", {"version": 1, "at": 0, "entries": [e["id"] for e in FALLBACK_CATALOG]})
    if stats.get().get("version") != STATS_VERSION:
        stats.edit(migrate_stats)
    return {
        "settings": settings, "stats": stats, "availability": availability, "catalogStore": catalog_store,
        "dispose": lambda: [s.dispose() for s in (settings, stats, availability, catalog_store)],
    }


def create_model_runtime(*, settings, stats, availability, catalogStore, logger=print,
                         attribution_user_agent="our-free-model", resolve_image=None,
                         sealed_credential=None, on_sealed_unavailable=None, on_topology=None,
                         channel_catalog=None, refresh_channels=None) -> dict:
    sealed_credential = sealed_credential or (lambda: None)
    on_sealed_unavailable = on_sealed_unavailable or (lambda: None)
    on_topology = on_topology or (lambda: None)
    channel_catalog = channel_catalog or (lambda: [])

    catalog = _materialize_catalog(catalogStore.get().get("entries") or [])
    sealed_catalog = [] if sealed_credential() is None else build_eac_catalog(catalogStore.get().get("sealIds") or [])
    kilo_catalog = revive_kilo_catalog(catalogStore.get().get("kiloRows"))
    egress = availability.get().get("egress")
    gateway_latency = {"ms": 0, "at": 0}
    disposed = {"value": False}
    reprobe_timer = {"task": None}

    def merge_catalogs():
        nonlocal catalog
        base = [e for e in catalog if not e.get("channel") or e.get("channel") in ("eac", "kilo")]
        channel_rows = list(channel_catalog())
        merged = list(base)
        for row in [*sealed_catalog, *kilo_catalog, *channel_rows]:
            if not any(e["id"] == row["id"] for e in merged):
                merged.append(row)
        catalog = merged

    merge_catalogs()

    def state() -> dict:
        return {"catalog": catalog, "membership": compute_membership(catalog, availability.get(), settings.get()),
                "settings": settings.get(), "attributionUserAgent": attribution_user_agent}

    def emit_topology():
        if not disposed["value"]:
            on_topology()

    def on_region_blocked(_model_id):
        if disposed["value"] or reprobe_timer["task"] is not None:
            return
        async def later():
            await asyncio.sleep(4)
            reprobe_timer["task"] = None
            if not disposed["value"]:
                try:
                    await refresh_availability(True)
                except Exception as exc:
                    logger(f"our-free-model: region reprobe failed ({exc})")
        reprobe_timer["task"] = asyncio.create_task(later())

    adapter = FreeModelAdapter(
        state=state, resolve_image=resolve_image, sealed_credential=sealed_credential,
        record_usage=lambda record: (_record_usage(stats, record), stats.edit(lambda v: prune_days(v, 120))),
        record_turn=lambda record: record_turn(stats, record),
        warn=lambda message: logger(message),
        on_region_blocked=on_region_blocked,
    )

    refresh_lock = asyncio.Lock()
    refresh_state = {"forced": False, "probed": False}

    async def refresh_catalog(*, probe: bool = True, force: bool = False):
        if disposed["value"]:
            return catalog
        async with refresh_lock:
            await _refresh_catalog_once(probe=probe, force=force)
            return catalog

    async def _refresh_catalog_once(*, probe: bool, force: bool):
        nonlocal catalog
        ids = []
        try:
            ids = parse_listing(await fetch_listing())
        except Exception as exc:
            if not disposed["value"]:
                logger(f"our-free-model: model listing refresh failed ({exc}); keeping the cached catalog")
        if disposed["value"]:
            return catalog
        if ids:
            catalog = build_catalog(ids)
            catalogStore.update({"at": int(time.time() * 1000), "entries": [e["id"] for e in catalog]})
            catalogStore.flush()
            settings.update({"catalogSyncedAt": int(time.time() * 1000)})
        else:
            catalog = _materialize_catalog(catalogStore.get().get("entries") or [])
        await _refresh_sealed_roster()
        if disposed["value"]:
            return catalog
        await _refresh_kilo_roster()
        if disposed["value"]:
            return catalog
        if refresh_channels is not None:
            try:
                await refresh_channels()
            except Exception as error:  # noqa: BLE001
                logger(f"our-free-model: channel catalog refresh failed ({error})")
        merge_catalogs()
        if probe:
            await refresh_availability(force)
        emit_topology()
        return catalog

    async def _refresh_sealed_roster():
        nonlocal sealed_catalog
        credential = sealed_credential()
        if credential is None:
            sealed_catalog = []
            on_sealed_unavailable()
            return
        try:
            from .eac import fetch_sealed_listing
            ids = parse_listing(await fetch_sealed_listing(credential))
            if disposed["value"]:
                return
            if ids:
                sealed_catalog = build_eac_catalog(ids)
                catalogStore.update({"sealIds": [e["id"] for e in sealed_catalog]})
        except Exception as exc:
            if disposed["value"]:
                return
            code = getattr(exc, "code", None)
            if code == CODE["credential"]:
                sealed_catalog = []
                catalogStore.update({"sealIds": []})
                logger("our-free-model: the sealed lane refused its credential; its models are hidden until it is accepted again")
                return
            logger(f"our-free-model: sealed lane listing failed ({code or exc}); keeping its cached roster")

    async def _refresh_kilo_roster():
        nonlocal kilo_catalog
        try:
            payload = await fetch_kilo_listing()
            if disposed["value"]:
                return
            if payload.get("error") or not isinstance(payload.get("data"), list):
                raise RuntimeError("invalid Kilo model listing")
            kilo_catalog = build_kilo_catalog(payload["data"])
            catalogStore.update({"kiloRows": kilo_catalog})
        except Exception as exc:
            if not disposed["value"]:
                logger(f"our-free-model: Kilo channel listing failed ({getattr(exc, 'code', exc)}); keeping its cached roster")

    async def fetch_listing():
        if disposed["value"]:
            return {"data": []}
        started = time.time() * 1000
        listing = await get_json("/zen/v1/models",
                                 session=session_for_conversation("catalog:our-free-model"),
                                 request_id=mint_request_id(),
                                 attribution_user_agent=attribution_user_agent)
        if not disposed["value"]:
            gateway_latency["ms"] = time.time() * 1000 - started
            gateway_latency["at"] = int(time.time() * 1000)
        return listing

    probe_round = {"task": None}
    backoff = {"streak": 0, "until": 0}

    async def _run_probe_round():
        probeable = [e for e in catalog if not is_eac_entry(e) and not is_kilo_entry(e)]

        def on_result(model_id, result):
            if disposed["value"]:
                return
            availability.edit(lambda value: {
                **value,
                "results": {**(value.get("results") or {}), model_id: {
                    "state": result["state"],
                    **({} if result.get("detail") is None else {"detail": result["detail"]}),
                    **({} if result.get("ttftMs") is None else {"ttftMs": result["ttftMs"]}),
                    "latencyMs": result.get("latencyMs", 0), "at": int(time.time() * 1000),
                }},
            })

        results = await probe_catalog(probeable, attribution_user_agent, on_result, 2)
        if disposed["value"]:
            return {}
        availability.update({"at": int(time.time() * 1000), "egress": egress})
        availability.flush()
        verdicts = list(results.values())
        if verdicts and all(r["state"] == STATE["unavailable"] for r in verdicts):
            logger(f"our-free-model: the gateway refused all {len(verdicts)} models this round; keeping them advertised")
        all_throttled = bool(verdicts) and all(r["state"] == STATE["throttled"] for r in verdicts)
        backoff["streak"] = backoff["streak"] + 1 if all_throttled else 0
        backoff["until"] = (int(time.time() * 1000) + min(30 * 2 ** (backoff["streak"] - 1), 120) * 60000) if all_throttled else 0
        if all_throttled:
            logger("our-free-model: the probe round hit the lane's quota; availability probes paused")
        emit_topology()
        return results

    async def refresh_availability(force: bool = False):
        if disposed["value"] or (not force and backoff["until"] > int(time.time() * 1000)):
            return {}
        if probe_round["task"] is not None and not probe_round["task"].done():
            return await probe_round["task"]
        probe_round["task"] = asyncio.create_task(_run_probe_round())
        try:
            return await probe_round["task"]
        finally:
            probe_round["task"] = None

    async def watch_egress() -> bool:
        nonlocal egress
        if disposed["value"]:
            return False
        seen = await detect_egress()
        if disposed["value"] or seen is None:
            return False
        previous = availability.get().get("egress")
        changed = previous is None or previous.get("ip") != seen.get("ip") or (
            seen.get("country") is not None and previous.get("country") != seen.get("country"))
        egress = seen
        if changed:
            availability.update({"egress": seen})
            availability.flush()
            logger(f"our-free-model: egress changed to {seen.get('ip')}; re-probing availability")
            await refresh_availability(True)
        return True

    def dispose():
        if disposed["value"]:
            return
        disposed["value"] = True
        task = reprobe_timer["task"]
        if task is not None:
            task.cancel()

    return {
        "state": state, "adapter": adapter,
        "refreshCatalog": refresh_catalog, "refreshAvailability": refresh_availability,
        "watchEgress": watch_egress, "fetchListing": fetch_listing,
        "publicModelRows": lambda: public_model_rows(state()),
        "get_catalog": lambda: catalog,
        "get_egress": lambda: egress,
        "get_gateway_latency": lambda: gateway_latency,
        "dispose": dispose,
    }


def _materialize_catalog(ids):
    rebuilt = build_catalog(ids)
    return rebuilt if rebuilt else FALLBACK_CATALOG


def _record_usage(stats, record):
    record_usage(stats, record)


def compute_membership(catalog, availability_snapshot, settings) -> dict:
    results = (availability_snapshot or {}).get("results") or {}
    expose = (settings or {}).get("exposeRegionModels") is not False

    def verdict_of(entry):
        return (results.get(entry["id"]) or {}).get("state")

    probeable = [e for e in catalog if not e.get("channel")]
    refused_all = bool(probeable) and all(verdict_of(e) == STATE["unavailable"] for e in probeable)
    usable = [e for e in catalog if verdict_of(e) != STATE["unavailable"]]
    if refused_all:
        usable = catalog
    main, region = [], []
    for entry in usable:
        if verdict_of(entry) != STATE["regionBlocked"]:
            main.append(entry["id"])
        elif expose:
            region.append(entry["id"])
    membership: dict[str, list[str]] = {}
    if main:
        membership[ROUTE_MAIN] = main
    if region:
        membership[ROUTE_REGION] = region
    return membership


def public_model_rows(snapshot) -> list[dict]:
    membership = set(snapshot["membership"].get(ROUTE_MAIN, []))
    if snapshot.get("settings", {}).get("exposeRegionModels") is not False:
        membership |= set(snapshot["membership"].get(ROUTE_REGION, []))
    created = int(time.time())
    return [{"id": e["id"], "object": "model", "created": created, "owned_by": "our-free-model",
             **({} if e.get("contextWindow") is None else {"context_window": e["contextWindow"]})}
            for e in snapshot["catalog"] if e["id"] in membership]
