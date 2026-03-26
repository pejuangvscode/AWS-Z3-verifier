"""
reporter.py – Auto-incrementing report writer for the AWS Z3 Verifier.

Setiap kali dipanggil, modul ini mencari nomor report terakhir di folder
yang dituju, lalu membuat file baru dengan nomor berikutnya.

Struktur folder yang dihasilkan:
    reports/
    ├── main/           ← hasil run main.py
    │   ├── report_1.txt
    │   ├── report_2.txt
    │   └── ...
    ├── scenario_1/     ← hasil run scenario_1.py saja
    ├── scenario_2/
    ├── scenario_3/
    ├── scenario_4/
    └── scenario_5/

Penggunaan:
    from report import Reporter

    rpt = Reporter("scenario_1")          # atau "main"
    rpt.add_result("SSH Check", "SAT", model)
    rpt.add_result("HTTP Check", "UNSAT", None)
    rpt.save()                             # tulis ke file, cetak path-nya
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

# Root folder untuk semua laporan — satu level di atas file ini (project root)
_PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = _PROJECT_ROOT / "reports"


class Reporter:
    """Kumpulkan hasil verifikasi lalu tulis ke file laporan bernomor otomatis.

    Args:
        scope: Nama sub-folder laporan, misalnya ``"main"``, ``"scenario_1"``, dll.
    """

    def __init__(self, scope: str) -> None:
        self.scope = scope
        self._folder = REPORTS_DIR / scope
        self._folder.mkdir(parents=True, exist_ok=True)
        self._rows: list[tuple[str, str, Any]] = []  # (label, result, model)
        self._started_at = datetime.now()

    # ──────────────────────────────────────────────────────────────────────────
    # Public helpers
    # ──────────────────────────────────────────────────────────────────────────

    def add_result(self, label: str, result: str, model: Any = None) -> None:
        """Tambahkan satu baris hasil ke laporan.

        Args:
            label:  Deskripsi singkat pemeriksaan, misal ``"Internet→EC2 SSH"``.
            result: ``"SAT"`` (vulnerable) atau ``"UNSAT"`` (safe).
            model:  Z3 ModelRef opsional; ditampilkan sebagai counterexample.
        """
        self._rows.append((label, result, model))

    def save(self, extra_notes: str = "") -> Path:
        """Tulis laporan ke file bernomor berikutnya dan kembalikan path-nya.

        Args:
            extra_notes: Teks tambahan opsional yang disisipkan di akhir laporan.

        Returns:
            :class:`pathlib.Path` ke file laporan yang baru dibuat.
        """
        report_path = self._next_report_path()
        content = self._render(extra_notes)
        report_path.write_text(content, encoding="utf-8")
        print(f"\nReport saved → {report_path.relative_to(_PROJECT_ROOT)}")
        return report_path

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _next_report_path(self) -> Path:
        """Return path untuk file laporan berikutnya (auto-increment)."""
        existing = sorted(self._folder.glob("report_*.txt"))
        if not existing:
            next_num = 1
        else:
            # Ambil nomor tertinggi dari nama file yang sudah ada
            nums = []
            for p in existing:
                try:
                    nums.append(int(p.stem.split("_")[1]))
                except (IndexError, ValueError):
                    pass
            next_num = (max(nums) + 1) if nums else 1
        return self._folder / f"report_{next_num}.txt"

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
            "  SECURITY VERIFICATION RESULTS",
            "  " + "-" * 63,
        ]

        for label, result, model in self._rows:
            verdict = self._verdict(result)
            lines.append(f"  {label:<4}: {result:<1} {verdict}")
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