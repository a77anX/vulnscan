"""Authorized-scope enforcement for professional engagements.

A scope file names exactly which hosts (and optionally which paths to exclude) a scan is
allowed to touch. Binding a scan to one lets a student or a teammate run the same command
you'd run without being able to accidentally point it at something out of bounds.

File format is JSON by default (no new required dependency); .yml/.yaml is also accepted if
PyYAML is installed (`pip install pyyaml`), purely as a convenience.

Example scope.json:
{
  "client": "Acme Corp",
  "authorized_by": "Jane Dela Cruz, CTO",
  "date_authorized": "2026-11-01",
  "targets": ["https://staging.acme.example.com"],
  "excluded_paths": ["/admin/delete-account", "/api/payments"]
}
"""
from __future__ import annotations
import json
import os
from urllib.parse import urlparse


class ScopeViolation(RuntimeError):
    pass


class Scope:
    def __init__(self, data: dict):
        self.client = data.get("client", "")
        self.authorized_by = data.get("authorized_by", "")
        self.date_authorized = data.get("date_authorized", "")
        self.targets = [t.rstrip("/") for t in data.get("targets", [])]
        self.excluded_paths = list(data.get("excluded_paths", []))
        if not self.targets:
            raise ValueError('scope file must list at least one target under "targets"')

    @classmethod
    def load(cls, path):
        ext = os.path.splitext(path)[1].lower()
        with open(path, "r", encoding="utf-8") as fh:
            if ext in (".yml", ".yaml"):
                try:
                    import yaml
                except ImportError as e:
                    raise RuntimeError(
                        f"{path} is YAML but PyYAML isn't installed. Run `pip install pyyaml`, "
                        "or save the scope file as .json instead."
                    ) from e
                data = yaml.safe_load(fh)
            else:
                data = json.load(fh)
        return cls(data)

    def _host_allowed(self, url):
        host = urlparse(url).netloc
        return any(urlparse(t).netloc == host for t in self.targets)

    def check(self, url):
        """Raise ScopeViolation if `url` falls outside the authorized scope."""
        if not self._host_allowed(url):
            raise ScopeViolation(
                f"{url} is outside the authorized scope "
                f"({', '.join(self.targets)}). Refusing to scan it."
            )
        path = urlparse(url).path
        for excl in self.excluded_paths:
            if path.startswith(excl):
                raise ScopeViolation(f"{url} matches an excluded path ({excl}); skipping.")

    def summary(self):
        bits = [f"client: {self.client}" if self.client else None,
               f"authorized by: {self.authorized_by}" if self.authorized_by else None,
               f"date: {self.date_authorized}" if self.date_authorized else None,
               f"targets: {', '.join(self.targets)}"]
        return "; ".join(b for b in bits if b)
