"""免费车道的模型目录。

两个来源分层：上游清单（``/zen/v1/models``）给出权威 id 集合；
本地能力表给出上下文窗口/视觉/思考等能力（上游清单只披露 id）。
另含 EAC 与 Kilo 两条渠道的目录构建。
"""

from __future__ import annotations

import re
from typing import Any

from .upstream import base_model_id, is_responses_model

ALWAYS_FREE = {"union-alpha", "space-bunny-free"}

CAPABILITIES = [
    {"match": r"^mimo.*v2\.6", "vision": True, "reasoning": True, "contextWindow": 1048576, "maxOutput": 131072, "canDisableThinking": False},
    {"match": r"^mimo.*v2\.5", "vision": True, "reasoning": True, "contextWindow": 1048576, "maxOutput": 131072, "canDisableThinking": False},
    {"match": r"^mimo", "vision": True, "reasoning": True, "contextWindow": 262144, "maxOutput": 131072},
    {"match": r"^muse.?spark", "vision": True, "reasoning": True, "contextWindow": 1048576, "maxOutput": 131072},
    {"match": r"^nemotron", "vision": False, "reasoning": True, "contextWindow": 128000, "maxOutput": 32768},
    {"match": r"^ling", "vision": False, "reasoning": True, "contextWindow": 128000, "maxOutput": 32768},
    {"match": r"^space.?bunny", "vision": True, "reasoning": True, "contextWindow": 262144, "maxOutput": 65536},
    {"match": r"^union", "vision": True, "reasoning": False, "contextWindow": 262144, "maxOutput": 131072},
    {"match": r"^deepseek", "vision": False, "reasoning": True, "contextWindow": 128000, "maxOutput": 64000},
    {"match": r"^jev", "vision": False, "reasoning": False, "contextWindow": 32768, "maxOutput": 4096},
]

DISPLAY_NAMES = {
    "mimo-v2.6-flash-free": "MiMo V2.6 Flash",
    "mimo-v2.5-free": "MiMo V2.5",
    "muse-spark-1.3-contributor-free": "Muse Spark 1.3",
    "muse-spark-1.2-contributor-free": "Muse Spark 1.2",
    "nemotron-3-ultra-free": "Nemotron 3 Ultra",
    "nemotron-3.5-lightning-free": "Nemotron 3.5 Lightning",
    "ling-3.0-flash-fin-free": "Ling 3.0 Flash Fin",
    "space-bunny-free": "Space Bunny",
    "union-alpha": "Union Alpha",
    "deepseek-v4-flash-free": "DeepSeek V4 Flash",
    "jev-1.13-free": "Jev 1.13",
}

REGION_SENSITIVE = [r"^muse.?spark"]


def is_free_lane(model_id: str | None) -> bool:
    base = base_model_id(model_id)
    if base in ALWAYS_FREE:
        return True
    return re.search(r"(?:^|[-_])free(?:$|[-_.])", base) is not None


def capabilities_for(model_id: str) -> dict:
    base = base_model_id(model_id)
    for entry in CAPABILITIES:
        if re.match(entry["match"], base):
            return entry
    return {"vision": False, "reasoning": True, "contextWindow": 131072, "maxOutput": 32768}


def is_region_sensitive(model_id: str | None) -> bool:
    base = base_model_id(model_id)
    return any(re.match(p, base) for p in REGION_SENSITIVE)


def display_model_name(model_id: str | None) -> str:
    base = base_model_id(model_id)
    if base in DISPLAY_NAMES:
        return DISPLAY_NAMES[base]
    words = re.sub(r"[-_.]+", " ", base).strip().split(" ")
    return " ".join(w if re.match(r"^\d", w) else (w.upper() if w.isupper() else w[:1].upper() + w[1:]) for w in words if w)


def _num(value):
    return int(value) if isinstance(value, (int, float)) and value > 0 else None


def build_catalog(ids: list) -> list[dict]:
    """合并上游清单与本地能力表。"""
    seen = set()
    entries = []
    for raw in ids:
        model_id = str(raw or "").strip()
        if model_id == "" or not is_free_lane(model_id):
            continue
        base = base_model_id(model_id)
        if base in seen:
            continue
        seen.add(base)
        caps = capabilities_for(base)
        entries.append({
            "id": base,
            "name": display_model_name(base),
            "wire": "responses" if is_responses_model(base) else "chat",
            "vision": caps.get("vision") is True,
            "reasoning": caps.get("reasoning") is not False,
            "contextWindow": _num(caps.get("contextWindow")) or 131072,
            "maxOutput": _num(caps.get("maxOutput")) or 32768,
            "canDisableThinking": caps.get("canDisableThinking") is not False,
            "regionSensitive": is_region_sensitive(base),
        })
    return entries


def parse_listing(payload) -> list[str]:
    """解析网关的 ``{"data":[{"id":…}]}`` 清单。"""
    if isinstance(payload, dict):
        rows = payload.get("data") if isinstance(payload.get("data"), list) else (
            payload.get("models") if isinstance(payload.get("models"), list) else [])
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    out = []
    for row in rows:
        value = row if isinstance(row, str) else (row.get("id") if isinstance(row, dict) else None)
        if isinstance(value, str) and value != "":
            out.append(value)
    return out


# ── EAC 协付渠道目录 ────────────────────────────────────────────────────────

EAC_CHANNEL = "eac"
EAC_TAG = "EAC"

EAC_DISPLAY_NAMES = {
    "deepseek-ai/deepseek-v4.1-flash": "DeepSeek V4.1 Flash",
    "moonshotai/kimi-k2.6": "Kimi K2.6",
    "moonshotai/kimi-k3": "Kimi K3",
    "openai/gpt-oss-20b": "GPT-OSS 20B",
    "z-ai/glm-5.3": "GLM 5.3",
    "z-ai/glm-5.3-flash": "GLM 5.3 Flash",
}

EAC_CAPABILITIES = [
    {"match": r"^deepseek-ai/deepseek-v4", "vision": True, "reasoning": True, "contextWindow": 1048576, "maxOutput": 384000,
     "efforts": ["disabled", "low", "high", "max"], "effortDefault": "high",
     "effortPatch": {"reasoning_effort": "$effort"}, "effortOffPatch": {"reasoning": {"enabled": False}}},
    {"match": r"^moonshotai/kimi-k3", "vision": True, "reasoning": True, "contextWindow": 1048576, "maxOutput": 131072,
     "efforts": ["low", "high", "max"], "effortDefault": "high", "effortPatch": {"reasoning_effort": "$effort"}},
    {"match": r"^moonshotai/kimi", "vision": True, "reasoning": True, "contextWindow": 262144, "maxOutput": 98304,
     "efforts": ["low", "high", "max"], "effortDefault": "high", "effortPatch": {"reasoning_effort": "$effort"}},
    {"match": r"^z-ai/glm-5\.3-flash", "vision": True, "reasoning": True, "contextWindow": 1048576, "maxOutput": 131072,
     "efforts": ["low", "high", "max"], "effortDefault": "high",
     "effortPatch": {"thinking": {"type": "enabled"}, "output_config": {"effort": "$effort"}}},
    {"match": r"^z-ai/glm-5", "vision": False, "reasoning": True, "contextWindow": 1048576, "maxOutput": 131072,
     "efforts": ["low", "high", "max"], "effortDefault": "high",
     "effortPatch": {"thinking": {"type": "enabled"}, "output_config": {"effort": "$effort"}}},
    {"match": r"^openai/gpt-oss", "vision": False, "reasoning": True, "contextWindow": 131072, "maxOutput": 32768,
     "efforts": ["low", "medium", "high"], "effortDefault": "medium", "effortPatch": {"reasoning_effort": "$effort"}},
]


def eac_display_name(model_id: str) -> str:
    base = str(model_id or "").strip()
    bare = base[base.find("/") + 1:] if "/" in base else base
    known = EAC_DISPLAY_NAMES.get(base)
    pretty = known or " ".join(
        w if re.match(r"^\d", w) else (w.upper() if w.isupper() else w[:1].upper() + w[1:])
        for w in re.sub(r"[-_.]+", " ", bare).strip().split(" ") if w)
    return f"{EAC_TAG} {pretty}"


def _eac_capabilities_for(model_id: str) -> dict:
    for entry in EAC_CAPABILITIES:
        if re.match(entry["match"], model_id):
            return entry
    return {"vision": False, "reasoning": True, "contextWindow": 131072, "maxOutput": 32768}


def build_eac_catalog(ids: list) -> list[dict]:
    seen = set()
    entries = []
    for raw in ids:
        model_id = str(raw or "").strip()
        if model_id == "" or model_id in seen:
            continue
        seen.add(model_id)
        caps = _eac_capabilities_for(model_id)
        entry = {
            "id": model_id, "name": eac_display_name(model_id), "channel": EAC_CHANNEL, "wire": "chat",
            "vision": caps.get("vision") is True, "reasoning": caps.get("reasoning") is not False,
            "contextWindow": _num(caps.get("contextWindow")) or 131072,
            "maxOutput": _num(caps.get("maxOutput")) or 32768,
            "canDisableThinking": bool(isinstance(caps.get("efforts"), list) and "disabled" in caps["efforts"]),
            "regionSensitive": False,
        }
        if isinstance(caps.get("efforts"), list):
            entry["efforts"] = list(caps["efforts"])
            entry["effortDefault"] = caps.get("effortDefault")
        if caps.get("effortPatch") is not None:
            entry["effortPatch"] = caps["effortPatch"]
        if caps.get("effortOffPatch") is not None:
            entry["effortOffPatch"] = caps["effortOffPatch"]
        entries.append(entry)
    return entries


def is_eac_entry(entry: dict | None) -> bool:
    return bool(entry and entry.get("channel") == EAC_CHANNEL)


# ── Kilo 渠道目录 ───────────────────────────────────────────────────────────

KILO_CHANNEL = "kilo"
KILO_TAG = "Kilo"

KILO_EFFORT_PATCH = {"reasoning": {"effort": "$effort"}}
KILO_EFFORT_OFF_PATCH = {"reasoning": {"enabled": False}}
KILO_REASONING_MANDATORY = [r"^stepfun/", r"^liquid/", r"^thinkingmachines/"]
KILO_NO_DISABLE_IDS = {"kilo-auto/free", "openrouter/free"}


def _kilo_effort_menu_for(row: dict) -> dict:
    params = row.get("supported_parameters") if isinstance(row.get("supported_parameters"), list) else []
    if "reasoning" not in params:
        return {}
    model_id = str(row.get("id", ""))
    can_disable = not any(re.match(p, model_id) for p in KILO_REASONING_MANDATORY) and model_id not in KILO_NO_DISABLE_IDS
    menu = {
        "efforts": ["disabled", "low", "medium", "high"] if can_disable else ["low", "medium", "high"],
        "effortDefault": "high",
        "effortPatch": KILO_EFFORT_PATCH,
    }
    if can_disable:
        menu["effortOffPatch"] = KILO_EFFORT_OFF_PATCH
    menu["canDisableThinking"] = can_disable
    return menu


def is_kilo_free_row(row) -> bool:
    return isinstance(row, dict) and row.get("isFree") is True and isinstance(row.get("id"), str) and row["id"].strip() != ""


def kilo_display_name(row: dict) -> str:
    raw = row.get("name").strip() if isinstance(row.get("name"), str) else ""
    bare = re.sub(r"\s*\(free\)\s*$", "", re.sub(r"^[^:]{1,40}:\s+", "", raw or str(row.get("id", "")))).strip()
    if bare == "":
        bare = re.sub(r"[-_.]+", " ", str(row.get("id", ""))).strip()
    pretty = " ".join(w if re.match(r"^\d", w) else (w.upper() if w.isupper() else w[:1].upper() + w[1:]) for w in bare.split(" ") if w)
    return f"{KILO_TAG} {pretty}"


def _kilo_entry_of(row: dict) -> dict:
    context = _num(row.get("context_length")) or _num((row.get("top_provider") or {}).get("context_length")) or 131072
    output = _num((row.get("top_provider") or {}).get("max_completion_tokens")) or 32768
    modalities = (row.get("architecture") or {}).get("input_modalities")
    modalities = modalities if isinstance(modalities, list) else []
    menu = _kilo_effort_menu_for(row)
    entry = {
        "id": str(row["id"]).strip(), "name": kilo_display_name(row), "channel": KILO_CHANNEL, "wire": "chat",
        "vision": "image" in modalities, "reasoning": True, "contextWindow": context, "maxOutput": output,
        "canDisableThinking": menu.get("canDisableThinking") is True, "regionSensitive": False,
    }
    if menu.get("efforts") is not None:
        entry["efforts"] = list(menu["efforts"])
        entry["effortDefault"] = menu["effortDefault"]
        entry["effortPatch"] = menu["effortPatch"]
        if menu.get("effortOffPatch") is not None:
            entry["effortOffPatch"] = menu["effortOffPatch"]
    return entry


def build_kilo_catalog(rows: list) -> list[dict]:
    seen = set()
    entries = []
    for row in rows if isinstance(rows, list) else []:
        if not is_kilo_free_row(row):
            continue
        entry = _kilo_entry_of(row)
        if entry["id"] in seen:
            continue
        seen.add(entry["id"])
        entries.append(entry)
    return entries


def revive_kilo_catalog(stored) -> list[dict]:
    seen = set()
    entries = []
    for row in stored if isinstance(stored, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"].strip() == "" or row.get("channel") != KILO_CHANNEL:
            continue
        entry = _kilo_entry_of({**row, "name": row.get("name") if isinstance(row.get("name"), str) and row["name"] else row["id"]})
        entry["name"] = row.get("name") if isinstance(row.get("name"), str) and row["name"] else kilo_display_name({"id": row["id"]})
        entry["contextWindow"] = _num(row.get("contextWindow")) or 131072
        entry["maxOutput"] = _num(row.get("maxOutput")) or 32768
        entry["vision"] = row.get("vision") is True
        if isinstance(row.get("efforts"), list) and row["efforts"]:
            entry["efforts"] = [level for level in row["efforts"] if isinstance(level, str)]
            entry["effortDefault"] = row.get("effortDefault") if isinstance(row.get("effortDefault"), str) else entry.get("effortDefault")
            if isinstance(row.get("effortPatch"), dict):
                entry["effortPatch"] = row["effortPatch"]
            if isinstance(row.get("effortOffPatch"), dict):
                entry["effortOffPatch"] = row["effortOffPatch"]
            entry["canDisableThinking"] = "disabled" in entry["efforts"]
        if entry["id"] in seen:
            continue
        seen.add(entry["id"])
        entries.append(entry)
    return entries


def is_kilo_entry(entry: dict | None) -> bool:
    return bool(entry and entry.get("channel") == KILO_CHANNEL)
