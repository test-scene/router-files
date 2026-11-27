"""Pure filtering and sorting, independent of the GUI framework."""
from __future__ import annotations

from oui_lookup import NOTICE_LOCAL, NOTICE_UNKNOWN
from wifi_scanner import AccessPoint


def filter_and_sort(points: list[AccessPoint], query: str = "", sort_by: str = "Имя сети",
                    ascending: bool = True) -> list[AccessPoint]:
    term = query.strip().casefold()
    rows = [point for point in points if not term or term in " ".join([
        point.shown_ssid, point.bssid, point.vendor, point.shown_security, point.adapter
    ]).casefold()]
    reverse = not ascending
    if sort_by == "Производитель":
        known = [p for p in rows if p.vendor and p.vendor not in (NOTICE_UNKNOWN, NOTICE_LOCAL)]
        unknown = [p for p in rows if not p.vendor or p.vendor in (NOTICE_UNKNOWN, NOTICE_LOCAL)]
        known.sort(key=lambda p: (p.vendor.casefold(), p.ssid.casefold(), p.bssid), reverse=reverse)
        unknown.sort(key=lambda p: (not bool(p.vendor), p.ssid.casefold(), p.bssid))
        return known + unknown
    if sort_by == "Сигнал":
        known = [p for p in rows if p.signal is not None]
        unknown = [p for p in rows if p.signal is None]
        known.sort(key=lambda p: (p.signal, p.ssid.casefold()), reverse=reverse)
        return known + unknown
    known = [p for p in rows if p.ssid and p.ssid != "--"]
    unknown = [p for p in rows if not p.ssid or p.ssid == "--"]
    known.sort(key=lambda p: (p.ssid.casefold(), p.bssid), reverse=reverse)
    return known + unknown


def network_column_widths(available: int) -> dict[str, int]:
    """Fit every column into the viewport; never leave a hidden right edge."""
    minimum = {"#0": 72, "ssid": 80, "vendor": 130, "bssid": 158,
               "signal": 68, "security": 120, "adapter": 124}
    available = max(len(minimum), available)
    total = sum(minimum.values())
    if available < total:
        sizes = {key: max(1, value * available // total) for key, value in minimum.items()}
    else:
        sizes = minimum.copy()
        extra = available - total
        sizes["ssid"] += extra * 38 // 100
        sizes["vendor"] += extra * 34 // 100
        sizes["security"] += extra * 28 // 100
    remainder = available - sum(sizes.values())
    keys = ("ssid", "vendor", "security", "bssid", "adapter", "signal", "#0")
    for index in range(remainder):
        sizes[keys[index % len(keys)]] += 1
    return sizes


def fit_cell_text(value: str, width: int, measure) -> str:
    """Keep table cells on one line and clip by measured pixels, not character count."""
    text = " ".join(str(value).split())
    if measure(text) <= width:
        return text
    suffix = "…"
    if width < measure(suffix):
        return ""
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if measure(text[:middle] + suffix) <= width:
            low = middle
        else:
            high = middle - 1
    return text[:low] + suffix
