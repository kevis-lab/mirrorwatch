from __future__ import annotations

import asyncio
import os
import re
import sys
import threading
import time
from pathlib import Path

import pandas as pd
from PyQt5.QtCore import QObject, Qt, QUrl, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QDesktopServices, QFont, QImage, QPainter, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QProgressBar, QSpinBox, QTableWidget, QMenu,
    QTableWidgetItem, QVBoxLayout, QWidget,
)
from pyppeteer import launch

from comparer import capture, compare
from detector import check_candidate_urls, generate_candidate_urls, normalise_url
from network import get_host_and_ips, hostname_from_url


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"


def natural_domain_key(domain: str) -> tuple:
    """Sort base domain, its www variant, then numerical variants naturally."""
    host = domain.lower().removeprefix("www.")
    labels = host.split(".", 1)
    name, suffix = labels[0], labels[1] if len(labels) > 1 else ""
    number = ""
    while name and name[-1].isdigit():
        number = name[-1] + number
        name = name[:-1]
    return (name, int(number) if number else -1, suffix, domain.lower().startswith("www."))


class DualColorProgressBar(QProgressBar):
    """Progress bar with percentage text that switches from dark to white over the filled area."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTextVisible(False)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect()
        radius = 4

        # Background.
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#edf1f2"))
        painter.drawRoundedRect(rect, radius, radius)

        # Filled part.
        value = self.value()
        minimum = self.minimum()
        maximum = self.maximum()
        fraction = 0.0 if maximum <= minimum else (value - minimum) / (maximum - minimum)
        fraction = max(0.0, min(1.0, fraction))
        fill_width = round(rect.width() * fraction)
        fill_rect = rect.adjusted(0, 0, -(rect.width() - fill_width), 0)
        if fill_width > 0:
            painter.setBrush(QColor("#4b8795"))
            painter.drawRoundedRect(fill_rect, radius, radius)

        # Draw the same percentage twice: dark on the background, then white
        # clipped to the filled area. This keeps the text readable at every value.
        text = f"{round(fraction * 100)}%"
        font = self.font()
        font.setPointSize(11)
        font.setBold(True)
        painter.setFont(font)

        text_rect = rect
        painter.setPen(QColor("#4b8795"))
        painter.drawText(text_rect, Qt.AlignCenter, text)

        if fill_width > 0:
            painter.save()
            painter.setClipRect(fill_rect)
            painter.setPen(QColor("white"))
            painter.drawText(text_rect, Qt.AlignCenter, text)
            painter.restore()

        painter.end()


class Signals(QObject):
    status = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    overall_progress = pyqtSignal(int)
    phase = pyqtSignal(str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    failed = pyqtSignal(str)


def score_result(record: dict, reference_url: str, reference_ips: list[str], visual: int, textual: int) -> tuple[int, str]:
    ref_host = hostname_from_url(reference_url)
    target_host = hostname_from_url(record["target"])
    redirects_to_reference = target_host == ref_host
    same_network = bool(set(record["ips"]) & set(reference_ips))
    score = round(visual * .58 + textual * .32 + (10 if same_network else 0))
    if redirects_to_reference:
        return 100, "PŘESMĚROVÁNÍ"
    if score >= 80:
        return min(score, 99), "VYSOKÉ RIZIKO"
    if score >= 55:
        return score, "PODEZŘELÉ"
    return score, "NÍZKÁ SHODA"


async def analyse(reference_input, start, end, tlds, prefix, suffix, signals, stopped):
    paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    executable = next((path for path in paths if Path(path).exists()), None)
    browser = await launch(
        executablePath=executable,
        headless=True,
        handleSIGINT=False,
        handleSIGTERM=False,
        handleSIGHUP=False,
        args=["--no-sandbox"],
    )
    try:
        reference_url = normalise_url(reference_input)
        page = await browser.newPage()
        await page.setUserAgent(USER_AGENT)
        await page.setViewport({"width": 1440, "height": 900})
        signals.phase.emit("Načítání reference")
        signals.status.emit("Načítám referenční web…")
        signals.progress.emit(0, 100)
        signals.overall_progress.emit(0)
        reference = await capture(page, reference_url)
        ref_host, ref_ips = get_host_and_ips(reference_url)
        signals.result.emit({
            "domain": ref_host,
            "verdict": "REFERENCE",
            "is_reference": True,
            "target": reference_url,
            "status": 200,
            "ips": ref_ips,
            "shared_ips": ref_ips,
            "visual": 100,
            "text": 100,
            "score": 100,
            "image": reference["image"],
            "title": reference["title"],
            "redirects": [],
        })
        candidates = generate_candidate_urls(reference_url, start, end, tlds, prefix, suffix)
        total_candidates = len(candidates)
        probe_started = time.monotonic()
        signals.phase.emit("Dostupnost domén")
        signals.status.emit(f"Prověřuji dostupnost domén: 0/{total_candidates} · Zbývá: výpočet…")

        def format_eta(seconds: float | None) -> str:
            if seconds is None or seconds < 0 or seconds != seconds:
                return "výpočet…"
            seconds = int(round(seconds))
            if seconds < 60:
                return f"~{seconds} s"
            minutes, secs = divmod(seconds, 60)
            if minutes < 60:
                return f"~{minutes} min {secs:02d} s"
            hours, minutes = divmod(minutes, 60)
            return f"~{hours} h {minutes:02d} min"

        def probe_progress(done, total):
            elapsed = time.monotonic() - probe_started
            rate = done / elapsed if done > 0 and elapsed > 0 else 0
            remaining = (total - done) / rate if rate > 0 else None
            signals.progress.emit(done, max(total, 1))
            signals.overall_progress.emit(round(done / max(total, 1) * 70))
            signals.phase.emit("Dostupnost domén")
            signals.status.emit(
                f"Prověřuji dostupnost domén: {done}/{total} · "
                f"Rychlost: {rate:.1f}/s · Zbývá: {format_eta(remaining)}"
            )

        records = await check_candidate_urls(
            candidates, USER_AGENT, stopped, progress_callback=probe_progress
        )

        # Keep a proven redirect even if the final destination answers with 4xx.
        # Other 4xx/5xx pages are noise and are not rendered as screenshots.
        ref_target_host = hostname_from_url(reference_url)
        records = [
            record for record in records
            if hostname_from_url(record["target"]) == ref_target_host or 200 <= record["status"] < 400
        ]

        comparison_total = len(records)
        comparison_started = time.monotonic()
        signals.progress.emit(0, max(comparison_total, 1))
        signals.overall_progress.emit(70)
        if comparison_total:
            signals.phase.emit("Porovnávání")
            signals.status.emit(
                f"Porovnávám 0/{comparison_total} · Zbývá: výpočet…"
            )
        else:
            signals.status.emit("Porovnávání: nebyly nalezeny dostupné domény.")

        for index, record in enumerate(records, 1):
            if stopped.is_set():
                break
            elapsed = time.monotonic() - comparison_started
            rate = (index - 1) / elapsed if index > 1 and elapsed > 0 else 0
            remaining = (comparison_total - (index - 1)) / rate if rate > 0 else None
            signals.phase.emit("Porovnávání")
            signals.status.emit(
                f"Porovnávám {index - 1}/{comparison_total} · "
                f"Rychlost: {rate:.1f}/s · Zbývá: {format_eta(remaining)}"
            )
            try:
                if hostname_from_url(record["target"]) == ref_target_host:
                    signals.result.emit({
                        **record,
                        "domain": hostname_from_url(record["name"]),
                        "is_reference": False,
                        "verdict": "PŘESMĚROVÁNÍ",
                        "visual": 100,
                        "text": 100,
                        "score": 100,
                        "image": reference["image"],
                        "title": "Cíl přesměrování odpovídá referenční doméně.",
                        "shared_ips": sorted(set(record["ips"]) & set(ref_ips)),
                    })
                    elapsed = time.monotonic() - comparison_started
                    rate = index / elapsed if index > 0 and elapsed > 0 else 0
                    remaining = (comparison_total - index) / rate if rate > 0 else None
                    signals.progress.emit(index, max(comparison_total, 1))
                    signals.overall_progress.emit(70 + round(index / max(comparison_total, 1) * 30))
                    signals.phase.emit("Porovnávání")
                    signals.status.emit(
                        f"Porovnávám {index}/{comparison_total} · "
                        f"Rychlost: {rate:.1f}/s · Zbývá: {format_eta(remaining)}"
                    )
                    continue

                visual, textual, image, title = await compare(page, record["target"], reference)
                score, verdict = score_result(record, reference_url, ref_ips, visual, textual)
                signals.result.emit({
                    **record,
                    "domain": hostname_from_url(record["name"]),
                    "is_reference": False,
                    "verdict": verdict,
                    "visual": visual,
                    "text": textual,
                    "score": score,
                    "image": image,
                    "title": title,
                    "shared_ips": sorted(set(record["ips"]) & set(ref_ips)),
                })
            except Exception:
                pass
            elapsed = time.monotonic() - comparison_started
            rate = index / elapsed if index > 0 and elapsed > 0 else 0
            remaining = (comparison_total - index) / rate if rate > 0 else None
            signals.progress.emit(index, max(comparison_total, 1))
            signals.overall_progress.emit(70 + round(index / max(comparison_total, 1) * 30))
            signals.phase.emit("Porovnávání")
            signals.status.emit(
                f"Porovnávání: {index}/{comparison_total} · "
                f"Rychlost: {rate:.1f}/s · Zbývá: {format_eta(remaining)}"
            )
    except Exception as error:
        signals.failed.emit(str(error))
    finally:
        await browser.close()
        signals.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.rows: list[dict] = []
        self.current_phase = "Čekám na spuštění"
        self.stop_event = threading.Event()
        self.signals = Signals()
        self.setWindowTitle("MirrorWatch")
        self.resize(1440, 900)
        self._build_ui()
        self._connect()

    def _build_ui(self):
        self.setStyleSheet(STYLESHEET)
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(26, 22, 30, 26)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        brand = QLabel("MirrorWatch")
        brand.setObjectName("title")
        descriptor = QLabel("Ověřování domén")
        descriptor.setObjectName("eyebrow")
        heading.addWidget(brand)
        heading.addSpacing(16)
        heading.addWidget(descriptor)
        heading.addStretch()
        heading.addWidget(QLabel("Lokální analýza"))
        layout.addLayout(heading)

        body = QHBoxLayout()
        body.setSpacing(16)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(22, 22, 22, 22)
        side.setSpacing(12)

        scan_title = QLabel("Nový sken")
        scan_title.setObjectName("sectionTitle")
        side.addWidget(scan_title)
        hint = QLabel("Nastavte rozsah hledání")
        hint.setObjectName("hint")
        side.addWidget(hint)
        side.addSpacing(8)
        side.addWidget(QLabel("REFERENČNÍ DOMÉNA"))

        self.reference = QLineEdit("https://spintexas5.com/")
        self.reference.setPlaceholderText("example.com")
        self.reference.setClearButtonEnabled(True)
        side.addWidget(self.reference)

        side.addSpacing(6)
        side.addWidget(QLabel("KONCOVKY"))
        self.tlds = {}
        tld_grid = QGridLayout()
        for index, tld in enumerate(("cz", "com", "bet", "win", "top", "vip", "online", "site", "games", "fun")):
            box = QCheckBox(f".{tld}")
            # Only the TLD of the initial reference is selected.
            box.setChecked(tld == "com")
            self.tlds[tld] = box
            tld_grid.addWidget(box, index // 2, index % 2)
        side.addLayout(tld_grid)

        side.addWidget(QLabel("VLASTNÍ KONCOVKY"))
        self.custom_tlds = QLineEdit()
        self.custom_tlds.setPlaceholderText("např. xyz, app")
        self.custom_tlds.setToolTip("Koncovky oddělujte čárkou.\nTečku psát nemusíte.")
        side.addWidget(self.custom_tlds)

        side.addSpacing(6)
        side.addWidget(QLabel("RYCHLÝ ROZSAH"))
        self.range_preset = QComboBox()
        self.range_preset.addItem("1–100", (1, 100))
        self.range_preset.addItem("1–1 000", (1, 1000))
        self.range_preset.addItem("1–5 000", (1, 5000))
        self.range_preset.addItem("1–10 000", (1, 10000))
        self.range_preset.addItem("5 001–10 000", (5001, 10000))
        self.range_preset.addItem("Vlastní", None)
        self.range_preset.setCurrentIndex(1)
        side.addWidget(self.range_preset)

        side.addWidget(QLabel("ČÍSELNÉ VARIANTY"))
        range_layout = QHBoxLayout()
        self.start = QSpinBox()
        self.start.setRange(0, 100000)
        self.start.setValue(1)
        self.end = QSpinBox()
        self.end.setRange(0, 100000)
        self.end.setValue(1000)
        range_layout.addWidget(self.start)
        range_layout.addWidget(QLabel("až"))
        range_layout.addWidget(self.end)
        side.addLayout(range_layout)

        self.prefix = QCheckBox("Před názvem")
        self.suffix = QCheckBox("Za názvem")
        self.suffix.setChecked(True)
        side.addWidget(self.prefix)
        side.addWidget(self.suffix)
        side.addStretch()

        self.run = QPushButton("Spustit sken")
        self.run.setObjectName("primary")
        self.stop = QPushButton("Zastavit")
        self.stop.setEnabled(False)
        self.export = QPushButton("Exportovat výsledky")
        self.export.setEnabled(False)
        side.addWidget(self.run)
        side.addWidget(self.stop)
        side.addWidget(self.export)
        body.addWidget(sidebar, 0)

        main_panel = QFrame()
        main_panel.setObjectName("mainPanel")
        panel_layout = QVBoxLayout(main_panel)
        panel_layout.setContentsMargins(22, 20, 22, 20)
        panel_layout.setSpacing(14)

        panel_header = QHBoxLayout()
        title = QLabel("Nálezy")
        title.setObjectName("sectionTitle")
        panel_header.addWidget(title)
        panel_header.addStretch()
        self.status = QLabel("Čekám na spuštění")
        self.status.setObjectName("status")
        panel_header.addWidget(self.status)
        panel_layout.addLayout(panel_header)

        summary_row = QHBoxLayout()
        summary_row.setSpacing(8)
        self.summary_both = self.create_summary_badge("Obě varianty", 0, "both")
        self.summary_only_www = self.create_summary_badge("Pouze www", 0, "only_www")
        self.summary_only_bare = self.create_summary_badge("Pouze bez www", 0, "only_bare")
        self.summary_lists = {"both": [], "only_www": [], "only_bare": []}
        summary_row.addWidget(self.summary_both)
        summary_row.addWidget(self.summary_only_www)
        summary_row.addWidget(self.summary_only_bare)
        summary_row.addStretch()
        panel_layout.addLayout(summary_row)

        progress_header = QHBoxLayout()
        overall_label = QLabel("Celkový průběh")
        overall_label.setObjectName("progressLabel")
        progress_header.addWidget(overall_label)
        panel_layout.addLayout(progress_header)

        self.overall_progress = DualColorProgressBar()
        self.overall_progress.setToolTip("Celkový průběh celého skenu.")
        panel_layout.addWidget(self.overall_progress)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "Doména", "Verdikt", "Skóre", "Vizuál", "Text",
            "HTTP", "Cílová URL", "Síť", "Náhled"
        ])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(False)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setDefaultSectionSize(92)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.setColumnWidth(8, 154)
        self.table.setToolTip("Dvojklik na řádek otevře testovanou doménu v prohlížeči.")
        panel_layout.addWidget(self.table, 1)

        body.addWidget(main_panel, 1)
        layout.addLayout(body, 1)
        self.setCentralWidget(root)

    def _connect(self):
        self.run.clicked.connect(self.start_analysis)
        self.stop.clicked.connect(self.stop_event.set)
        self.export.clicked.connect(self.export_xlsx)
        self.reference.returnPressed.connect(self.start_analysis)
        # Update TLD defaults only after the user finishes editing, not on every keystroke.
        self.reference.editingFinished.connect(self.suggest_scan_defaults)
        self.range_preset.currentIndexChanged.connect(self.apply_range_preset)
        self.start.valueChanged.connect(self.range_edited)
        self.end.valueChanged.connect(self.range_edited)
        self.table.cellDoubleClicked.connect(self.open_row_url)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_row_context_menu)
        self.signals.status.connect(self.status.setText)
        self.signals.phase.connect(self.update_phase)
        self.signals.progress.connect(
            lambda done, total: self.update_phase_progress(done, total)
        )
        self.signals.overall_progress.connect(self.overall_progress.setValue)
        self.signals.result.connect(self.add_result)
        self.signals.finished.connect(self.finished)
        self.signals.failed.connect(
            lambda error: QMessageBox.warning(self, "Analýza se nezdařila", error)
        )

    def start_analysis(self):
        if not self.run.isEnabled():
            return

        domain = self.reference.text().strip()
        tlds = [tld for tld, check in self.tlds.items() if check.isChecked()]
        custom = [
            part.strip().lower().lstrip(".")
            for part in self.custom_tlds.text().split(",")
            if part.strip()
        ]
        invalid = [tld for tld in custom if not re.fullmatch(r"[a-z0-9-]{2,63}", tld)]
        if invalid:
            QMessageBox.information(
                self,
                "Neplatná koncovka",
                f"Zkontrolujte vlastní koncovky: {', '.join(invalid)}",
            )
            return

        tlds = sorted(set(tlds + custom))
        if not domain or not tlds:
            QMessageBox.information(
                self,
                "Chybí údaje",
                "Zadejte referenční doménu a vyberte alespoň jednu koncovku.",
            )
            return

        if self.start.value() > self.end.value():
            QMessageBox.information(
                self,
                "Neplatný rozsah",
                "Počáteční číslo nemůže být vyšší než koncové.",
            )
            return

        self.rows.clear()
        self.table.setRowCount(0)
        self.overall_progress.setValue(0)
        self.update_phase_progress(0, 1)
        self.update_phase("Příprava skenu")
        self.stop_event.clear()
        self.run.setEnabled(False)
        self.stop.setEnabled(True)

        thread = threading.Thread(
            target=lambda: asyncio.run(
                analyse(
                    domain,
                    self.start.value(),
                    self.end.value(),
                    tlds,
                    self.prefix.isChecked(),
                    self.suffix.isChecked(),
                    self.signals,
                    self.stop_event,
                )
            ),
            daemon=True,
        )
        thread.start()

    def suggest_scan_defaults(self, value: str | None = None):
        value = self.reference.text().strip() if value is None else value
        if not value:
            return

        try:
            host = hostname_from_url(normalise_url(value))
        except Exception:
            return

        if not host:
            return

        tld = host.rsplit(".", 1)[-1].lower()
        if tld in self.tlds:
            for checkbox in self.tlds.values():
                checkbox.setChecked(False)
            self.tlds[tld].setChecked(True)

        label = host.removeprefix("www.").split(".", 1)[0]
        prefix = bool(re.match(r"^\d+", label))
        suffix = bool(re.search(r"\d+$", label))
        if prefix or suffix:
            self.prefix.setChecked(prefix)
            self.suffix.setChecked(suffix)

    def apply_range_preset(self):
        preset = self.range_preset.currentData()
        if not preset:
            return
        self.start.blockSignals(True)
        self.end.blockSignals(True)
        self.start.setValue(preset[0])
        self.end.setValue(preset[1])
        self.start.blockSignals(False)
        self.end.blockSignals(False)

    def range_edited(self):
        selected = self.range_preset.currentData()
        if selected != (self.start.value(), self.end.value()):
            self.range_preset.blockSignals(True)
            self.range_preset.setCurrentText("Vlastní")
            self.range_preset.blockSignals(False)

    def create_summary_badge(self, label: str, count: int, category: str) -> QLabel:
        badge = QLabel(f"{label}: {count}")
        badge.setObjectName("summaryBadge")
        badge.setToolTip("Zatím žádné výsledky")
        badge.setContextMenuPolicy(Qt.CustomContextMenu)
        badge.customContextMenuRequested.connect(
            lambda _pos, key=category: self.copy_summary_domains(key)
        )
        return badge

    def copy_summary_domains(self, category: str):
        domains = self.summary_lists.get(category, [])
        if not domains:
            QMessageBox.information(
                self,
                "Kopírování",
                "V této kategorii zatím nejsou žádné domény.",
            )
            return

        QApplication.clipboard().setText("\n".join(domains))
        self.status.setText(f"Zkopírováno {len(domains)} domén do schránky")

    @staticmethod
    def _url_for_row(item: dict) -> str:
        return item.get("name") or item.get("target") or ""

    def open_row_url(self, row: int, _column: int):
        if row < 0 or row >= len(self.rows):
            return
        item = self.rows[row]
        url = self._url_for_row(item)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def update_phase(self, text: str):
        # The current phase is already shown in the status text at the top-right.
        # Keep it as internal state so the progress logic can remain simple.
        self.current_phase = text

    def update_phase_progress(self, done: int, total: int):
        # Progress is displayed by the single overall progress bar.
        # This signal remains connected for compatibility with the worker flow.
        return

    def show_row_context_menu(self, position):
        row = self.table.rowAt(position.y())
        if row < 0 or row >= len(self.rows):
            return
        item = self.rows[row]
        menu = QMenu(self)
        open_domain = menu.addAction("Otevřít doménu")
        open_target = menu.addAction("Otevřít cílovou URL")
        menu.addSeparator()
        copy_domain = menu.addAction("Kopírovat doménu")
        copy_target = menu.addAction("Kopírovat cílovou URL")
        copy_ip = menu.addAction("Kopírovat IP adresy")
        menu.addSeparator()
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen == open_domain:
            QDesktopServices.openUrl(QUrl(self._url_for_row(item)))
        elif chosen == open_target and item.get("target"):
            QDesktopServices.openUrl(QUrl(item["target"]))
        elif chosen == copy_domain:
            QApplication.clipboard().setText(item.get("domain", ""))
            self.status.setText("Doména zkopírována do schránky")
        elif chosen == copy_target:
            QApplication.clipboard().setText(item.get("target", ""))
            self.status.setText("Cílová URL zkopírována do schránky")
        elif chosen == copy_ip:
            QApplication.clipboard().setText("\n".join(item.get("ips", [])))
            self.status.setText("IP adresy zkopírovány do schránky")

    def add_result(self, row: dict):
        self.rows.append(row)
        self.export.setEnabled(True)
        self.rows.sort(key=lambda item: natural_domain_key(item["domain"]))

        selected_domain = None
        current = self.table.currentRow()
        if current >= 0 and current < len(self.rows):
            selected_domain = self.table.item(current, 0).text() if self.table.item(current, 0) else None

        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(len(self.rows))

        colours = {
            "REFERENCE": "#2563eb",
            "PŘESMĚROVÁNÍ": "#0f766e",
            "VYSOKÉ RIZIKO": "#dc2626",
            "PODEZŘELÉ": "#d97706",
            "NÍZKÁ SHODA": "#64748b",
        }

        for index, item in enumerate(self.rows):
            network_label = (
                "Reference"
                if item["verdict"] == "REFERENCE"
                else (
                    f"Shodná ({len(item.get('shared_ips', []))})"
                    if item.get("shared_ips")
                    else "Odlišná"
                )
            )
            values = [
                item["domain"],
                item["verdict"],
                f"{item['score']} %",
                f"{item['visual']} %",
                f"{item['text']} %",
                item["status"],
                item["target"],
                network_label,
            ]

            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setToolTip(item.get("title", ""))

                if column in (0, 6):
                    font = QFont("Segoe UI", 9)
                    font.setUnderline(True)
                    cell.setFont(font)
                    cell.setForeground(QColor("#1f6f7a"))
                    cell.setToolTip(
                        "Dvojklik otevře URL v prohlížeči."
                        if column == 0
                        else "Dvojklik na řádek otevře testovanou doménu."
                    )

                if column == 1:
                    cell.setForeground(QColor(colours[item["verdict"]]))
                    cell.setFont(QFont("Segoe UI", 9, QFont.Bold))

                if column == 7:
                    shared = item.get("shared_ips", [])
                    cell.setToolTip(
                        f"IP adresy:\n{chr(10).join(item['ips']) or 'nezjištěny'}"
                        f"\n\nSpolečné s referencí:\n{chr(10).join(shared) or 'žádné'}"
                    )

                if item["verdict"] == "REFERENCE":
                    cell.setData(Qt.BackgroundRole, QBrush(QColor("#ffe38a")))

                self.table.setItem(index, column, cell)

            preview = QLabel()
            preview.setAlignment(Qt.AlignCenter)
            if item["verdict"] == "REFERENCE":
                preview.setStyleSheet("background: #ffe38a;")
            if item.get("image"):
                preview.setPixmap(
                    QPixmap.fromImage(QImage.fromData(item["image"])).scaled(
                        150, 84, Qt.KeepAspectRatio, Qt.SmoothTransformation
                    )
                )
            self.table.setCellWidget(index, 8, preview)

        self.table.setUpdatesEnabled(True)

        # Restore the previously selected domain after the table is refreshed.
        if selected_domain:
            for index, item in enumerate(self.rows):
                if item["domain"] == selected_domain:
                    self.table.selectRow(index)
                    break

        self.update_summary()

    def update_summary(self):
        redirects: dict[str, set[bool]] = {}
        for item in self.rows:
            if item["verdict"] != "PŘESMĚROVÁNÍ" and not item.get("is_reference"):
                continue
            host = item["domain"].lower()
            base = host.removeprefix("www.")
            redirects.setdefault(base, set()).add(host.startswith("www."))

        both = sorted(
            (base for base, flags in redirects.items() if flags == {False, True}),
            key=natural_domain_key,
        )
        only_www = sorted(
            (base for base, flags in redirects.items() if flags == {True}),
            key=natural_domain_key,
        )
        only_bare = sorted(
            (base for base, flags in redirects.items() if flags == {False}),
            key=natural_domain_key,
        )

        self.summary_lists = {
            "both": both,
            "only_www": only_www,
            "only_bare": only_bare,
        }

        self.summary_both.setText(f"Obě varianty: {len(both)}")
        self.summary_both.setToolTip(
            "Domény s přesměrováním obou variant:\n"
            + ("\n".join(both) or "žádné")
            + "\n\nPravé tlačítko → Kopírovat"
        )
        self.summary_only_www.setText(f"Pouze www: {len(only_www)}")
        self.summary_only_www.setToolTip(
            "Domény přesměrovávající pouze s www:\n"
            + ("\n".join(only_www) or "žádné")
            + "\n\nPravé tlačítko → Kopírovat"
        )
        self.summary_only_bare.setText(f"Pouze bez www: {len(only_bare)}")
        self.summary_only_bare.setToolTip(
            "Zjištěné domény:\n"
            + ("\n".join(only_bare) or "žádné")
            + "\n\nPravé tlačítko → Kopírovat"
        )

    def finished(self):
        self.run.setEnabled(True)
        self.stop.setEnabled(False)
        self.overall_progress.setValue(0 if self.stop_event.is_set() else 100)
        if self.stop_event.is_set():
            self.status.setText("Analýza zastavena")
            self.update_phase("Sken zastaven")
        else:
            self.status.setText("Analýza dokončena · 100 %")
            self.update_phase("Dokončeno")

    def export_xlsx(self):
        if not self.rows:
            QMessageBox.information(self, "Export", "Nejsou k dispozici žádné výsledky.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportovat výsledky",
            "mirrorwatch-results.xlsx",
            "Excel (*.xlsx)",
        )
        if not path:
            return

        try:
            export_rows = []
            for row in self.rows:
                redirects = row.get("redirects", [])
                export_rows.append({
                    "Doména": row.get("domain", ""),
                    "Verdikt": row.get("verdict", ""),
                    "Skóre": row.get("score", ""),
                    "Vizuál": row.get("visual", ""),
                    "Text": row.get("text", ""),
                    "HTTP": row.get("status", ""),
                    "Cílová URL": row.get("target", ""),
                    "IP adresy": ", ".join(row.get("ips", [])),
                    "Společné IP": ", ".join(row.get("shared_ips", [])),
                    "Počet redirectů": max(0, len(redirects) - 1),
                    "Redirect řetězec": " → ".join(redirects),
                    "Název stránky": row.get("title", ""),
                })

            with pd.ExcelWriter(path, engine="openpyxl") as writer:
                findings = pd.DataFrame(export_rows)
                findings.to_excel(writer, sheet_name="Nálezy", index=False)

                redirects_summary: dict[str, set[bool]] = {}
                for item in self.rows:
                    if item["verdict"] != "PŘESMĚROVÁNÍ":
                        continue
                    host = item["domain"].lower()
                    redirects_summary.setdefault(
                        host.removeprefix("www."), set()
                    ).add(host.startswith("www."))

                summary_rows = [
                    {
                        "Kategorie přesměrování": "Obě varianty",
                        "Počet domén": sum(
                            flags == {False, True}
                            for flags in redirects_summary.values()
                        ),
                    },
                    {
                        "Kategorie přesměrování": "Pouze www",
                        "Počet domén": sum(
                            flags == {True}
                            for flags in redirects_summary.values()
                        ),
                    },
                    {
                        "Kategorie přesměrování": "Pouze bez www",
                        "Počet domén": sum(
                            flags == {False}
                            for flags in redirects_summary.values()
                        ),
                    },
                ]
                pd.DataFrame(summary_rows).to_excel(
                    writer, sheet_name="Souhrn", index=False
                )

                # Basic Excel usability improvements.
                for worksheet in writer.book.worksheets:
                    worksheet.freeze_panes = "A2"
                    worksheet.auto_filter.ref = worksheet.dimensions
                    for column_cells in worksheet.columns:
                        max_length = max(
                            len(str(cell.value or ""))
                            for cell in column_cells
                        )
                        worksheet.column_dimensions[
                            column_cells[0].column_letter
                        ].width = min(max(max_length + 2, 10), 60)

                # Make URL columns clickable.
                worksheet = writer.book["Nálezy"]
                headers = {
                    cell.value: cell.column
                    for cell in worksheet[1]
                }
                for row_index in range(2, worksheet.max_row + 1):
                    domain_col = headers.get("Doména")
                    target_col = headers.get("Cílová URL")

                    if domain_col:
                        cell = worksheet.cell(row_index, domain_col)
                        domain = str(cell.value or "")
                        if domain:
                            cell.hyperlink = f"https://{domain}"
                            cell.style = "Hyperlink"

                    if target_col:
                        cell = worksheet.cell(row_index, target_col)
                        target = str(cell.value or "")
                        if target.startswith(("http://", "https://")):
                            cell.hyperlink = target
                            cell.style = "Hyperlink"

            # Windows: open the freshly exported workbook automatically.
            if sys.platform.startswith("win"):
                os.startfile(os.path.abspath(path))
            else:
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))

        except Exception as error:
            QMessageBox.warning(
                self,
                "Export se nezdařil",
                f"Soubor se nepodařilo vytvořit nebo otevřít:\n{error}",
            )


STYLESHEET = """
QMainWindow { background: #fbfbf9; color: #28313d; font-family: 'Segoe UI'; }
QLabel { color: #526071; font-size: 11px; font-weight: 600; }
QLabel#title { color: #202b36; font-size: 21px; font-weight: 750; }
QLabel#eyebrow { color: #84909c; font-size: 12px; font-weight: 500; }
QLabel#sectionTitle { color: #202b36; font-size: 18px; font-weight: 700; }
QLabel#hint { color: #8793a0; font-size: 11px; font-weight: 400; }
QLabel#status { color: #65738a; font-size: 12px; font-weight: 500; }
QLabel#phaseLabel { color: #65738a; font-size: 11px; font-weight: 600; }
QLabel#phaseStep { color: #7b8a94; font-size: 11px; font-weight: 600; }
QLabel#summaryBadge { background: #f3f7f7; border: 1px solid #e2ebec; border-radius: 6px; color: #3d6470; padding: 8px 10px; font-size: 12px; }
QLabel#summaryBadge:hover { background: #e7f0ff; border-color: #b6cef5; color: #2156a4; }
QFrame#sidebar { background: #edf7f8; border: 1px solid #dfebed; border-radius: 12px; min-width: 240px; max-width: 240px; }
QFrame#mainPanel { background: #ffffff; border: 1px solid #edf0f2; border-radius: 12px; }
QLineEdit, QSpinBox { background: #ffffff; border: 1px solid #d8e0e3; border-radius: 7px; color: #28313d; min-height: 32px; padding: 3px 9px; }
QLineEdit:focus, QSpinBox:focus { border: 1px solid #6b96a1; }
QCheckBox { color: #425362; spacing: 7px; font-weight: 500; }
QCheckBox::indicator { width: 15px; height: 15px; }
QCheckBox::indicator:unchecked { border: 1px solid #b8c8cc; border-radius: 4px; background: white; }
QCheckBox::indicator:checked { border: 1px solid #3f7482; border-radius: 4px; background: #4b8795; }
QPushButton { background: transparent; border: 1px solid #d5dfe2; border-radius: 7px; color: #3d5260; font-weight: 650; min-height: 34px; padding: 0 12px; }
QPushButton:hover { background: #f7fafa; }
QPushButton#primary { background: #2f6877; border-color: #2f6877; color: white; }
QPushButton#primary:hover { background: #285b68; }
QPushButton:disabled { color: #a4afb6; background: #f5f7f7; border-color: #e5eaeb; }
QProgressBar { background: #edf1f2; border: 0; border-radius: 4px; min-height: 26px; }
QTableWidget { background: white; alternate-background-color: #fbfcfc; border: 1px solid #e8edef; border-radius: 8px; color: #344555; gridline-color: #f0f3f4; }
QTableWidget::item { padding: 6px; border-bottom: 1px solid #f0f3f4; }
QTableWidget::item:selected { background: #dceff3; color: #24333d; }
QTableWidget::item:selected:active { background: #dceff3; color: #24333d; }
QHeaderView::section { background: #f8faf9; border: 0; border-bottom: 1px solid #e3e8e9; color: #7a8995; font-size: 10px; font-weight: 700; padding: 10px 7px; }
"""


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("MirrorWatch")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
