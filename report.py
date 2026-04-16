"""
report.py – Static report writer for the AWS Z3 Verifier.

Modul ini telah disederhanakan agar setiap kali dijalankan, file laporan 
akan menimpa file sebelumnya (overwrite) di folder yang dituju. 
Tidak ada lagi penomoran file (report_1, report_2, dst).

Struktur folder yang dihasilkan di dalam 'output/':
    ├── main/           → report.txt
    ├── scenario_1/     → report.txt
    ├── scenario_2/     → report.txt
    ├── scenario_3/     → report.txt
    ├── scenario_4/     → report.txt
    └── scenario_5/     → report.txt
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

# Root folder untuk semua laporan
_PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = _PROJECT_ROOT / "output"


class Reporter:
    """Kumpulkan hasil verifikasi lalu tulis/timpa ke file report.txt."""

    def __init__(self, scope: str) -> None:
        self.scope = scope
        self._folder = REPORTS_DIR / scope
        self._folder.mkdir(parents=True, exist_ok=True)
        self._rows: list[tuple[str, str, Any]] = []
        self._started_at = datetime.now()

    def add_result(self, label: str, result: str, model: Any = None) -> None:
        """Tambahkan satu baris hasil ke laporan."""
        self._rows.append((label, result, model))

    def save(self, extra_notes: str = "") -> Path:
        """Tulis/Timpa laporan ke file report.txt."""
        # Nama file dibuat statis agar selalu replace/overwrite
        report_path = self._folder / "report.txt"
        
        content = self._render(extra_notes)
        report_path.write_text(content, encoding="utf-8")
        
        # Baris print notifikasi ke terminal sudah dihapus di sini
        return report_path

    def _verdict(self, result: str) -> str:
        return "VULNERABLE" if result == "SAT" else "SAFE"

    def _format_model(self, model: Any) -> str:
        """Format Z3 model menjadi string yang mudah dibaca."""
        if model is None:
            return ""
        try:
            parts = [f"{d.name()}={model[d]}" for d in model.decls()]
            return ", ".join(parts)
        except Exception:
            return str(model)

    def _render(self, extra_notes: str) -> str:
        """Render seluruh konten laporan sebagai string."""
        vuln = sum(1 for _, r, _ in self._rows if r == "SAT")
        safe = len(self._rows) - vuln
        finished_at = datetime.now()
        duration = (finished_at - self._started_at).total_seconds()

        lines: list[str] = []
        sep = "=" * 65

        lines += [
            sep,
            "  AWS Infrastructure Security Verifier (Z3 SMT)",
            sep,
            f"  Scope   : {self.scope}",
            f"  Started : {self._started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Finished: {finished_at.strftime('%Y-%m-%d %H:%M:%S')}  "
            f"({duration:.2f}s)",
            sep,
            "",
            "  SECURITY VERIFICATION RESULTS (LATEST)",
            "  " + "-" * 63,
        ]

        for label, result, model in self._rows:
            verdict = self._verdict(result)
            lines.append(f"  {label:<25}: {result:<5} {verdict}")
            ce = self._format_model(model)
            if ce:
                lines.append(f"    └─ counterexample: [{ce}]")

        lines += [
            "  " + "-" * 63,
            "",
            f"  Summary: {vuln} VULNERABLE  |  {safe} SAFE",
            "",
        ]

        if extra_notes:
            lines += ["  NOTES", "  " + "-" * 63, f"  {extra_notes}", ""]

        lines.append(sep)
        return "\n".join(lines) + "\n"