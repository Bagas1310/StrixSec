"""
Persistence Storage Manager for StrixSec Scope System.
"""

from __future__ import annotations

import json
from pathlib import Path

from strixsec.core.errors import StorageError
from strixsec.scope.models import ScopeConfig, ScopeEntry
from strixsec.scope.normalizer import normalize_target

DEFAULT_SCOPE_FILE = Path(".strixsec_scope.json")


class ScopeStorage:
    """Storage manager to load, persist, and mutate scope configuration JSON files."""

    def __init__(self, file_path: Path = DEFAULT_SCOPE_FILE) -> None:
        self.file_path = file_path

    def load_scope(self) -> ScopeConfig:
        """Load scope configuration from JSON file. Returns empty config if file doesn't exist."""
        if not self.file_path.exists():
            return ScopeConfig()

        try:
            with open(self.file_path, encoding="utf-8") as f:
                data = json.load(f)
            return ScopeConfig.model_validate(data)
        except Exception as err:
            raise StorageError(
                f"Failed to load scope configuration file '{self.file_path}': {err}"
            ) from err

    def save_scope(self, config: ScopeConfig) -> None:
        """Save scope configuration to JSON file atomically."""
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(config.to_dict(), f, indent=2)
        except Exception as err:
            raise StorageError(
                f"Failed to save scope configuration file '{self.file_path}': {err}"
            ) from err

    def add_target(self, raw_target: str, is_exclusion: bool = False) -> ScopeEntry:
        """Normalize target and add it to scope configuration.

        Args:
            raw_target: Target string to add.
            is_exclusion: If True, add to excluded_targets; else allowed_targets.

        Returns:
            The created ScopeEntry.
        """
        norm_target, target_type = normalize_target(raw_target)
        entry = ScopeEntry(
            raw_target=raw_target,
            normalized_target=norm_target,
            target_type=target_type,
            is_exclusion=is_exclusion,
        )

        config = self.load_scope()
        target_list = config.excluded_targets if is_exclusion else config.allowed_targets

        # Prevent duplicate normalized entries
        if not any(e.normalized_target == norm_target for e in target_list):
            target_list.append(entry)
            self.save_scope(config)

        return entry

    def remove_target(self, raw_target: str) -> bool:
        """Remove a target entry matching raw or normalized target string.

        Returns:
            True if an entry was removed, False otherwise.
        """
        norm_target, _ = normalize_target(raw_target)
        config = self.load_scope()
        initial_count = len(config.allowed_targets) + len(config.excluded_targets)

        config.allowed_targets = [
            e
            for e in config.allowed_targets
            if e.raw_target != raw_target and e.normalized_target != norm_target
        ]
        config.excluded_targets = [
            e
            for e in config.excluded_targets
            if e.raw_target != raw_target and e.normalized_target != norm_target
        ]

        final_count = len(config.allowed_targets) + len(config.excluded_targets)
        removed = final_count < initial_count
        if removed:
            self.save_scope(config)
        return removed
