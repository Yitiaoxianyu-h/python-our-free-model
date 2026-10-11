"""思考强度策略。

实测结论：该车道向上游传递 ``reasoning_effort`` 字符串无效——网关接受
``reasoning_effort``/``thinking.budget_tokens``/``enable_thinking`` 等字段后一律忽略。
唯一被强制执行的控件是 ``max_tokens``，思考量直接跟随它。

因此本模块把「思考档位」实现为**真实下发的生成长度上限**。

思考不可关闭的模型（``canDisableThinking == False``）三档整体翻倍，
因为思考与可见答案共享同一输出额度。
"""

from __future__ import annotations

from typing import Any

LEVELS = [
    {"id": "light", "name": "Light", "zh": "精简", "ceiling": 2048,
     "hint": "terse deliberation, the fastest answer here."},
    {"id": "balanced", "name": "Balanced", "zh": "均衡", "ceiling": 8192,
     "hint": "enough to reason through a normal turn."},
    {"id": "deep", "name": "Deep", "zh": "深思", "ceiling": None,
     "hint": "the model's full output capacity, extended deliberation."},
]

DEFAULT_LEVEL = "balanced"
ALWAYS_THINKING_FACTOR = 2
MIN_BUDGET = 512


def supports_effort(model: dict | None) -> bool:
    return bool(model and model.get("reasoning") is True)


def has_declared_effort_menu(model: dict | None) -> bool:
    efforts = model.get("efforts") if model else None
    return isinstance(efforts, list) and len(efforts) > 0


def eac_default_level(model: dict | None) -> str | None:
    levels = model.get("efforts") if model else None
    if not isinstance(levels, list) or not levels:
        return None
    return model.get("effortDefault") if model.get("effortDefault") in levels else levels[0]


def resolve_level(level: str | None, model: dict | None):
    if has_declared_effort_menu(model):
        chosen = level if level in model["efforts"] else eac_default_level(model)
        return {"id": chosen}
    if not supports_effort(model):
        return None
    for candidate in LEVELS:
        if candidate["id"] == level:
            return candidate
    return next(c for c in LEVELS if c["id"] == DEFAULT_LEVEL)


def _ceiling_of(entry: dict | None, model: dict | None):
    if entry is None or entry.get("ceiling") is None:
        return None
    return entry["ceiling"] * ALWAYS_THINKING_FACTOR if model and model.get("canDisableThinking") is False else entry["ceiling"]


def _usable_tokens(value) -> float:
    return value if isinstance(value, (int, float)) and value > 0 else float("inf")


def budget_for(level: str | None, model: dict | None, requested=None, fallback=None) -> int:
    capacity = min(
        (model or {}).get("maxOutput") or 32768,
        _usable_tokens(requested),
        _usable_tokens(fallback),
    )
    if has_declared_effort_menu(model):
        return max(MIN_BUDGET, int(capacity))
    ceiling = _ceiling_of(resolve_level(level, model), model)
    if ceiling is None:
        return max(MIN_BUDGET, int(capacity))
    return max(MIN_BUDGET, int(min(ceiling, capacity)))


def budget_ladder(model: dict, requested=None, fallback=None) -> list[dict]:
    return [{"id": entry["id"], "name": entry["name"],
             "tokens": budget_for(entry["id"], model, requested, fallback),
             "isDefault": entry["id"] == DEFAULT_LEVEL} for entry in LEVELS]


def _instantiate_patch(patch, effort):
    if isinstance(patch, str):
        return effort if patch == "$effort" else patch
    if isinstance(patch, list):
        return [_instantiate_patch(v, effort) for v in patch]
    if isinstance(patch, dict):
        return {k: _instantiate_patch(v, effort) for k, v in patch.items()}
    return patch


def effort_patch_for(level: str | None, model: dict | None):
    efforts = model.get("efforts") if model else None
    if not isinstance(efforts, list) or not efforts:
        return None
    chosen = level if level in efforts else eac_default_level(model)
    if chosen == "disabled" and model.get("effortOffPatch") is not None:
        return _instantiate_patch(model["effortOffPatch"], chosen)
    if model.get("effortPatch") is None:
        return None
    return _instantiate_patch(model["effortPatch"], chosen)


def default_effort_for(model: dict | None) -> str:
    if has_declared_effort_menu(model):
        return eac_default_level(model) or DEFAULT_LEVEL
    return DEFAULT_LEVEL


def _declared_efforts_for(model: dict):
    levels = model.get("efforts") if isinstance(model.get("efforts"), list) else None
    if not levels:
        return None
    names = {"disabled": "Off", "low": "Low", "medium": "Medium", "high": "High", "max": "Max"}
    return [{"id": i, "name": names.get(i, i),
             "description": "thinking switched off for this turn; the answer alone" if i == "disabled"
             else f'thinking level "{i}", sent to the gateway as this model\'s own effort field'} for i in levels]


def _kilos(tokens: int) -> str:
    return f"{round(tokens / 1024)} K"


def efforts_for(model: dict, requested=None, fallback=None):
    if has_declared_effort_menu(model):
        return _declared_efforts_for(model)
    if not supports_effort(model):
        return None
    out = []
    for row in budget_ladder(model, requested, fallback):
        hint = next((l["hint"] for l in LEVELS if l["id"] == row["id"]), "")
        suffix = " (thinking cannot be switched off on this model)" if model.get("canDisableThinking") is False else ""
        out.append({"id": row["id"], "name": row["name"],
                    "description": f"{_kilos(row['tokens'])} output ceiling, shared by thinking and the answer{suffix}: {hint}"})
    return out
