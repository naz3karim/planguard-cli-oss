from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml


@dataclass(frozen=True)
class Pack:
    name: str
    version: str
    description: str
    rules_dir: Path

    @staticmethod
    def load(pack_dir: Path) -> "Pack":
        pack_file = pack_dir / "pack.yaml"
        data: Dict[str, Any] = yaml.safe_load(pack_file.read_text(encoding="utf-8")) or {}
        name = str(data.get("name", pack_dir.name))
        version = str(data.get("version", "0.0.0"))
        description = str(data.get("description", ""))
        rules_dir = pack_dir / str(data.get("rules_dir", "rules"))
        return Pack(name=name, version=version, description=description, rules_dir=rules_dir)
