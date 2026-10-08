# rules_loader.py
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError


class Rule(BaseModel):
    name: str
    category: str
    score: float = Field(ge=0.0, le=1.0)
    pattern: str
    enabled: bool = True


class RuleSet(BaseModel):
    rules: list[Rule]


class RuleFileError(Exception):
    """Raised when the rule file is missing, unreadable, or malformed."""
    pass


def load_rules(path: str | Path) -> RuleSet:
    """Load and validate a YAML rule file.

    Raises RuleFileError if the file does not exist, cannot be read,
    is not valid YAML, or does not match the expected schema.
    """
    path = Path(path)

    if not path.exists():
        raise RuleFileError(f"Rule file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise RuleFileError(f"Invalid YAML in {path}: {exc}") from exc
    except OSError as exc:
        raise RuleFileError(f"Could not read {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuleFileError(f"Rule file must be a mapping, got {type(raw).__name__}")

    try:
        return RuleSet(**raw)
    except ValidationError as exc:
        raise RuleFileError(f"Rule schema validation failed: {exc}") from exc