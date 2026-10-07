from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .config import NSE_PROFILES

BLOCKED_CATEGORIES = frozenset({"brute", "dos", "exploit", "intrusive"})
BASIC_CATEGORIES = ("default", "discovery", "safe")
DEEP_CATEGORIES = ("default", "discovery", "safe", "vuln")
CATEGORY_BLOCK = re.compile(r"categories\s*=\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL)
CATEGORY_NAME = re.compile(r"['\"]([A-Za-z0-9_-]+)['\"]")


@dataclass
class NseInventory:
    root: Path | None = None
    scripts: dict[str, frozenset[str]] = field(default_factory=dict)

    @property
    def categories(self) -> set[str]:
        found: set[str] = set()
        for cats in self.scripts.values():
            found.update(cats)
        return found


def nse_roots() -> list[Path]:
    roots: list[Path] = [
        Path("/usr/share/nmap/scripts"),
        Path("/usr/local/share/nmap/scripts"),
        Path(r"C:\Program Files (x86)\Nmap\scripts"),
        Path(r"C:\Program Files\Nmap\scripts"),
    ]
    nmap = shutil.which("nmap")
    if nmap:
        binary = Path(nmap).resolve()
        roots.extend(
            (
                binary.parent / "scripts",
                binary.parent.parent / "share" / "nmap" / "scripts",
            )
        )
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        out.append(resolved)
    return out


def parse_nse_categories(text: str) -> frozenset[str]:
    match = CATEGORY_BLOCK.search(text)
    if not match:
        return frozenset()
    return frozenset(CATEGORY_NAME.findall(match.group(1)))


def inventory_nse(root: Path | None = None) -> NseInventory:
    roots = [root] if root is not None else nse_roots()
    inventory = NseInventory()
    for candidate in roots:
        files = list(candidate.glob("*.nse"))
        if not files:
            continue
        inventory.root = candidate
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:8000]
            except OSError:
                continue
            inventory.scripts[path.stem] = parse_nse_categories(text)
        break
    return inventory


def script_spec_for_mode(mode: str, inventory: NseInventory | None = None) -> str:
    inventory = inventory if inventory is not None else inventory_nse()
    fallback = NSE_PROFILES.get(mode, NSE_PROFILES["advanced"])
    if not inventory.scripts:
        return fallback
    available = {c.lower() for c in inventory.categories}
    if mode == "basic":
        cats = [c for c in BASIC_CATEGORIES if c in available]
        return ",".join(cats) or fallback
    if mode == "deep":
        cats = [c for c in DEEP_CATEGORIES if c in available]
        return ",".join(cats) or fallback
    allowed = sorted(c for c in available if c not in BLOCKED_CATEGORIES)
    if not allowed:
        return fallback
    return "(" + " or ".join(allowed) + ")"


def inventory_summary(inventory: NseInventory | None = None) -> str:
    inventory = inventory if inventory is not None else inventory_nse()
    if not inventory.scripts or inventory.root is None:
        return "NSE INVENTORY > no local .nse catalog found; using Nmap category fallback"
    cats = ", ".join(sorted(inventory.categories)) or "uncategorized"
    blocked = sorted(c for c in inventory.categories if c in BLOCKED_CATEGORIES)
    extra = f"; local blocked categories present but excluded: {', '.join(blocked)}" if blocked else ""
    return (
        f"NSE INVENTORY > {len(inventory.scripts)} live .nse scripts in {inventory.root} "
        f"(categories: {cats}){extra}"
    )
