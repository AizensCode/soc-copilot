"""Model list prices, for turning token counts into dollars.

Deliberately a small committed table rather than a live lookup: pricing
is not available from the API, and an investigation's recorded cost
should not change because a network call failed. Prices are USD per
million tokens, list rate.

What this does NOT model: prompt-cache discounts, batch pricing, or
negotiated rates. Every number derived from here is an upper-bound
estimate for budgeting — never a bill. An unknown model prices at zero
and says so via `is_priced`, which is the honest answer: a wrong price
is worse than a missing one, because it silently pollutes the averages
a tiering decision would be made from.
"""

# USD per million tokens (input, output), list price.
_PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4-5": (5.00, 25.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}


def is_priced(model: str) -> bool:
    """Whether this model has a committed price (so cost is meaningful)."""
    return _resolve(model) is not None


def _resolve(model: str) -> tuple[float, float] | None:
    """Exact match first, then longest known prefix — model IDs carry
    date suffixes (claude-sonnet-5-20260514) that share a price."""
    if model in _PRICES:
        return _PRICES[model]
    candidates = [k for k in _PRICES if model.startswith(k)]
    if not candidates:
        return None
    return _PRICES[max(candidates, key=len)]


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """List-price cost in USD for a token count. 0.0 for unknown models."""
    price = _resolve(model)
    if price is None:
        return 0.0
    in_rate, out_rate = price
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000
