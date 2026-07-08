"""Nuclei CLI wrapper (stub)."""

from typing import Any

from tools.base import BaseSecurityTool


class NucleiTool(BaseSecurityTool):
    name = "nuclei"

    async def run(self, target: str, scope: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("Nuclei tool integration not yet implemented")
