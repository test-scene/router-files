"""Wi-Fi lab notebook: discovery, saved credentials and existing attack controls."""
from __future__ import annotations

import csv
import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from network_store import NetworkStore, StoreError, credential_flags
from relay_store import RelayStore
from ui_relay import CloudProfilesPanel, RouterSettingsDialog
from ui_route import RouteBuilderPage
from ui_icons import status_image
from ui_widgets import SectionTabs

from oui_lookup import NOTICE_LOCAL, NOTICE_UNKNOWN, VendorDatabase
from table_ops import filter_and_sort, fit_cell_text, network_column_widths
from wifi_scanner import AccessPoint, list_wifi_adapters, scan_wifi
from wifi_connection import PasswordRequired, UnsupportedAuthentication, connect_and_verify
from cracker import (METHOD_HANDSHAKE, METHOD_PMKID, METHOD_PIXIE_DUST,
                     METHOD_WPS_BRUTEFORCE, CrackResult, run_attacks)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

BG = "#0C131C"
PANEL = "#141F2C"
PANEL_2 = "#1E2D3E"
TEXT = "#EDF3F7"
MUTED = "#9AAAB7"
ACCENT = "#3FC7AD"
GREEN = "#55D99B"


class WiFiVendorApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Wi-Fi сети · Производители")
        self.geometry("1440x900")
        self.minsize(1100, 720)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self._close)

        self.networks: list[AccessPoint] = []
        self.store = NetworkStore()
        self.relay_store = RelayStore()
        self._clouds_open = False
        self._close_after_relay = False
        self._list_mode = "available"
        self._route_window = None
        self._route_open = False
        self._credentials_dirty = False
        self._loading_credentials = False
        self._save_job = None
        self._network_password = tk.StringVar()
        self._username = tk.StringVar()
        self._user_password = tk.StringVar()
        self._show_passwords = tk.BooleanVar(value=False)
        self._status_icons = {(password, account): status_image(password, account, self)
                              for password in (False, True) for account in (False, True)}
        self.vendor_db = VendorDatabase()
        self._vendor_enabled = False
        self._busy = False
        self._closing = False
        self._first_adapter_load = True
        self._queue: queue.Queue = queue.Queue()
        self._last_scan: datetime | None = None
        self._ascending = True
        self._tree_points: dict[str, AccessPoint] = {}
        self.selected_point: AccessPoint | None = None
        self._details_open = False
        self._crack_stop: threading.Event | None = None
        self._method_handshake = tk.BooleanVar(value=True)
        self._method_pmkid = tk.BooleanVar(value=False)
        self._crack_results: list[CrackResult] = []
        self._sort_by = "Имя сети"
        self._status_value = tk.StringVar(value="")
        self._method_pixie = tk.BooleanVar(value=False)
        self._method_wps_brute = tk.BooleanVar(value=False)
        self._query_value = tk.StringVar()
        self._query_value.trace_add("write", lambda *_: self._render_rows())
        self._build_layout()
        self._build_details()
        self.cloud_view = CloudProfilesPanel(self.page_host, self.relay_store, self._refresh_relay_sources)
        self.cloud_view.grid(row=0, column=0, sticky="nsew")
        self.cloud_view.grid_remove()
        self._render_rows()
        for variable in (self._network_password, self._username, self._user_password):
            variable.trace_add("write", self._credentials_changed)
        self._poll_queue()
        if self.store.load_error:
            self.after(100, lambda: messagebox.showerror("Журнал сетей", self.store.load_error, parent=self))
        self.after(250, self._refresh_adapters)


    def _build_layout(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        shell = ctk.CTkFrame(self, fg_color="transparent")
        shell.grid(row=0, column=0, sticky="nsew")
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)
        sidebar = ctk.CTkFrame(shell, width=212, corner_radius=0, fg_color="#101A25")
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(7, weight=1)
        self.available_nav = ctk.CTkButton(sidebar, text="Доступные сети", height=44, anchor="w",
            fg_color="#233E48", hover_color=PANEL_2, font=ctk.CTkFont(size=13),
            command=lambda: self._set_list_mode("available"))
        self.available_nav.grid(row=2, column=0, sticky="ew", padx=12, pady=(28, 6))
        self.known_nav = ctk.CTkButton(sidebar, text="Известные сети", height=44, anchor="w",
            fg_color="transparent", hover_color=PANEL_2, font=ctk.CTkFont(size=13),
            command=lambda: self._set_list_mode("known"))
        self.known_nav.grid(row=3, column=0, sticky="ew", padx=12)
        self.cloud_nav = ctk.CTkButton(sidebar, text="Облачные хранилища", height=44, anchor="w",
            fg_color="transparent", hover_color=PANEL_2, font=ctk.CTkFont(size=13), command=self._show_clouds)
        self.cloud_nav.grid(row=4, column=0, sticky="ew", padx=12, pady=(6, 0))
        ctk.CTkFrame(sidebar, height=1, fg_color=PANEL_2).grid(row=5, column=0, sticky="ew", padx=22, pady=(24, 14))
        utility = ctk.CTkFrame(sidebar, fg_color="transparent")
        utility.grid(row=6, column=0, sticky="ew", padx=12)
        utility.grid_columnconfigure(0, weight=1)
        for row, (attribute, text, command) in enumerate((
            ("vendor_button", "Определить производителей", self._find_vendors),
            ("update_db_button", "Обновить базу IEEE", self._update_ieee),
            ("import_button", "Импорт IEEE CSV", self._import_ieee))):
            button = ctk.CTkButton(utility, text=text, height=37, anchor="w", fg_color="transparent",
                hover_color=PANEL_2, text_color=MUTED, font=ctk.CTkFont(size=11))
            button.configure(command=command)
            button.grid(row=row, column=0, sticky="ew", pady=2)
            setattr(self, attribute, button)
        self.route_button = ctk.CTkButton(sidebar, text="Построение\nмаршрута отправки", width=188, height=58,
            fg_color="#258B77", hover_color="#2BA18A",
            text_color=TEXT, anchor="center", border_spacing=6, corner_radius=10,
            font=ctk.CTkFont(size=12, weight="bold"), command=self._open_route_builder)
        self.route_button.grid(row=8, column=0, sticky="ew", padx=12, pady=(12, 22))

        self.workspace = ctk.CTkFrame(shell, fg_color="transparent")
        self.workspace.grid(row=0, column=1, sticky="nsew")
        self.workspace.grid_columnconfigure(0, weight=1)
        self.workspace.grid_rowconfigure(0, weight=1)
        self.bind("<Alt-Left>", lambda _event: self._go_back())

        self.page_host = ctk.CTkFrame(self.workspace, fg_color="transparent")
        self.page_host.grid(row=0, column=0, sticky="nsew", padx=18, pady=(22, 0))
        self.page_host.grid_rowconfigure(0, weight=1)
        self.page_host.grid_columnconfigure(0, weight=1)
        container = self.main_view = ctk.CTkFrame(self.page_host, fg_color="transparent")
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(3, weight=1)
        hero = ctk.CTkFrame(container, fg_color="transparent")
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        hero.grid_columnconfigure(0, weight=1)
        self.list_title = ctk.CTkLabel(hero, text="Wi-Fi сети поблизости", text_color=TEXT,
            anchor="w", font=ctk.CTkFont(size=27, weight="bold"))
        self.list_title.grid(row=0, column=0, sticky="w")
        self.scan_button = ctk.CTkButton(hero, text="↻  Обновить сети", width=170, height=44,
            fg_color="#258B77", hover_color="#2BA18A", font=ctk.CTkFont(size=13, weight="bold"),
            command=self._scan)
        self.scan_button.grid(row=0, column=1, sticky="e", padx=(20, 0))

        toolbar = ctk.CTkFrame(container, fg_color=PANEL, corner_radius=12)
        toolbar.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        toolbar.grid_columnconfigure(0, weight=1)
        search_row = ctk.CTkFrame(toolbar, fg_color="transparent")
        search_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))
        search_row.grid_columnconfigure(0, weight=1)
        self.query_entry = ctk.CTkEntry(search_row, textvariable=self._query_value,
            placeholder_text="Поиск по SSID, MAC или производителю", height=40, width=240,
            fg_color=BG, border_color="#304557")
        self.query_entry.grid(row=0, column=0, sticky="ew", padx=(0, 20))
        ctk.CTkLabel(search_row, text="Адаптер", text_color=MUTED,
            font=ctk.CTkFont(size=11)).grid(row=0, column=1, padx=(0, 10))
        self.adapter_picker = ctk.CTkOptionMenu(search_row, values=["Все адаптеры"], width=176, height=38,
            fg_color=PANEL_2, button_color="#304557", button_hover_color="#3D566B")
        self.adapter_picker.grid(row=0, column=2)
        self.adapter_picker.set("Все адаптеры")
        self.adapter_button = ctk.CTkButton(search_row, text="↻", width=38, height=38,
            fg_color=PANEL_2, hover_color="#304858", command=self._refresh_adapters)
        self.adapter_button.grid(row=0, column=3, padx=(6, 0))
        sort_row = ctk.CTkFrame(toolbar, fg_color="transparent")
        sort_row.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))
        sort_row.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(sort_row, text="Сортировка", text_color=MUTED,
            font=ctk.CTkFont(size=11)).grid(row=0, column=0, padx=(0, 12))
        self.sort_picker = ctk.CTkOptionMenu(sort_row, values=["Имя сети", "Производитель", "Сигнал"],
            width=164, height=32, fg_color=PANEL_2, button_color="#304557",
            button_hover_color="#3D566B", command=self._on_sort_changed)
        self.sort_picker.grid(row=0, column=1)
        self.sort_picker.set("Имя сети")
        self.direction_button = ctk.CTkButton(sort_row, text="↑ По возрастанию", height=32, width=154,
            fg_color="transparent", hover_color=PANEL_2, text_color=MUTED, command=self._toggle_direction)
        self.direction_button.grid(row=0, column=2, padx=(8, 0))
        self.csv_button = ctk.CTkButton(sort_row, text="Экспорт CSV", width=118, height=32,
            fg_color=PANEL_2, hover_color="#304858", command=self._export_csv)
        self.csv_button.grid(row=0, column=4)
        self._build_network_table(container)

        footer = ctk.CTkFrame(self.workspace, fg_color="transparent")
        footer.grid(row=1, column=0, sticky="ew", padx=26, pady=(12, 14))
        footer.grid_columnconfigure(1, weight=1)
        self.progress = ctk.CTkProgressBar(footer, width=66, mode="indeterminate", height=4, progress_color=ACCENT)
        self.progress.grid(row=0, column=0, padx=(0, 12))
        self.progress.set(0)
        self.status_label = ctk.CTkLabel(footer, textvariable=self._status_value, text_color=MUTED,
            anchor="w", font=ctk.CTkFont(size=11), wraplength=520, justify="left")
        self.status_label.grid(row=0, column=1, sticky="ew")
        self.timestamp_label = ctk.CTkLabel(footer, text="", text_color=MUTED, font=ctk.CTkFont(size=11))
        self.timestamp_label.grid(row=0, column=2, padx=(12, 0))

    def _build_network_table(self, parent) -> None:
        card = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=0, border_width=0)
        card.grid(row=3, column=0, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))
        top.grid_columnconfigure(0, weight=1)
        self.filtered_label = ctk.CTkLabel(top, text="0 записей", text_color=MUTED, font=ctk.CTkFont(size=11))
        self.filtered_label.grid(row=0, column=0, sticky="w")
        inner = tk.Frame(card, bg=PANEL, borderwidth=0, highlightthickness=0, relief="flat")
        inner.grid(row=1, column=0, sticky="nsew")
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(0, weight=1)
        self._table_font = ctk.CTkFont(family="Segoe UI", size=13)
        self._table_heading_font = ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
        self._column_widths = network_column_widths(1000)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Wifi.Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
            borderwidth=0, relief="flat", bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL,
            rowheight=44, font=self._table_font, indent=0)
        style.configure("Wifi.Treeview.Heading", background=PANEL_2, foreground=MUTED,
            font=self._table_heading_font, padding=(2, 12), relief="flat",
            bordercolor=PANEL_2, lightcolor=PANEL_2, darkcolor=PANEL_2)
        # Draw only the content area: the theme's field and focus border are omitted.
        style.layout("Wifi.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.layout("Wifi.Treeview.Heading", [
            ("Treeheading.cell", {"sticky": "nswe"}),
            ("Treeheading.padding", {"sticky": "nswe", "children": [
                ("Treeheading.image", {"side": "right", "sticky": ""}),
                ("Treeheading.text", {"sticky": "we"})]})])
        style.map("Wifi.Treeview", background=[("selected", "#214D50")], foreground=[("selected", "#FFFFFF")])
        style.map("Wifi.Treeview.Heading", background=[("active", "#304858")])
        self.tree = ttk.Treeview(inner, columns=("ssid", "vendor", "bssid", "signal", "security", "adapter"),
            show="tree headings", style="Wifi.Treeview", selectmode="browse")
        # Flat status cell: no invisible expand indicator or tree indentation.
        style.layout("Wifi.Treeview.Item", [("Treeitem.padding", {"sticky": "nswe", "children": [
            ("Treeitem.image", {"side": "left", "sticky": ""})]})])
        self.tree.heading("#0", text="Данные", anchor="w")
        self.tree.column("#0", width=self._column_widths["#0"], minwidth=1, stretch=False, anchor="w")
        for field, label in (("ssid", "SSID"), ("vendor", "Производитель"),
                              ("bssid", "BSSID (MAC)"), ("signal", "Сигнал"),
                              ("security", "Защита / WPS"), ("adapter", "Адаптер")):
            anchor = "center" if field == "signal" else "w"
            self.tree.heading(field, text=label, anchor=anchor, command=lambda col=field: self._click_heading(col))
            self.tree.column(field, width=self._column_widths[field], minwidth=1, anchor=anchor, stretch=False)
        self.tree.tag_configure("odd", background=PANEL)
        self.tree.tag_configure("even", background="#182534")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Button-1>", lambda event: "break" if
                       self.tree.identify_region(event.x, event.y) == "separator" else None)
        self.tree.bind("<Configure>", self._resize_network_columns)
        self.tree.bind("<ButtonRelease-1>", self._on_row_click)
        self.tree.bind("<Return>", lambda _event: self._open_selected())
        self.empty_label = tk.Label(self.tree, text="Нет сетей",
            bg=PANEL, fg=MUTED, font=("Segoe UI", 12), justify="center")
        self.empty_label.place(relx=0.5, rely=0.5, anchor="center")

    def _build_details(self) -> None:
        self.detail_view = ctk.CTkFrame(self.page_host, fg_color="transparent")
        self.detail_view.grid(row=0, column=0, sticky="nsew")
        self.detail_view.grid_columnconfigure(0, weight=1)
        self.detail_view.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self.detail_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.grid_columnconfigure(1, weight=1)
        self.back_button = ctk.CTkButton(header, text="←", width=38, height=38,
            fg_color=PANEL_2, hover_color="#304858", font=ctk.CTkFont(size=22), command=self._go_back)
        self.back_button.grid(row=0, column=0, padx=(0, 14))
        self.detail_name = ctk.CTkLabel(header, text="—", text_color=TEXT, anchor="w", justify="left",
            wraplength=560, font=ctk.CTkFont(size=22, weight="bold"))
        self.detail_name.grid(row=0, column=1, sticky="w")
        self.detail_presence = ctk.CTkLabel(header, text="", text_color=GREEN, font=ctk.CTkFont(size=11))
        self.detail_presence.grid(row=0, column=2, sticky="e", padx=(16, 0))

        self.detail_tabs = SectionTabs(self.detail_view, fg_color=PANEL, corner_radius=12)
        self.detail_tabs.grid(row=1, column=0, sticky="nsew")
        data_tab = self.detail_tabs.add("Сеть")
        attack_tab = self.detail_tabs.add("Атаки")
        data_tab.grid_columnconfigure(0, weight=1)
        # The page fills its host; only the final empty row expands vertically.
        data_tab.grid_rowconfigure(4, weight=1)
        info = ctk.CTkFrame(data_tab, fg_color="transparent")
        info.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 0))
        info.grid_columnconfigure((0, 1), weight=1, uniform="metadata")
        self.detail_fields: dict[str, ctk.CTkLabel] = {}
        for index, (title, key) in enumerate((
            ("BSSID", "bssid"), ("Защита", "security"),
            ("Производитель", "vendor"), ("Сигнал", "signal"),
            ("Адаптер", "adapter"), ("Первая встреча", "first_seen"),
            ("Последняя встреча", "last_seen"))):
            row, column = divmod(index, 2)
            cell = ctk.CTkFrame(info, fg_color="transparent")
            cell.grid(row=row, column=column, sticky="nsew", padx=(0, 16) if column == 0 else (16, 0), pady=(0, 6))
            cell.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(cell, text=title, width=130, height=24, anchor="w", text_color=MUTED,
                font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, sticky="nw", padx=(0, 8))
            value = ctk.CTkLabel(cell, text="—", height=24, text_color=TEXT, wraplength=220,
                anchor="w", justify="left", font=ctk.CTkFont(size=12))
            value.grid(row=0, column=1, sticky="ew")
            self.detail_fields[key] = value
        ctk.CTkFrame(data_tab, height=1, fg_color=PANEL_2).grid(
            row=1, column=0, sticky="ew", padx=20, pady=(10, 16))
        form = ctk.CTkFrame(data_tab, fg_color="transparent")
        form.grid(row=2, column=0, sticky="ew", padx=20)
        form.grid_columnconfigure((0, 1, 2), weight=1, uniform="credentials")
        self.credential_entries = []
        for column, (title, variable, secret) in enumerate((
            ("Пароль от сети", self._network_password, True),
            ("Имя пользователя", self._username, False),
            ("Пароль пользователя", self._user_password, True))):
            pad = (0, 8) if column == 0 else (8, 0) if column == 2 else (8, 8)
            ctk.CTkLabel(form, text=title, text_color=TEXT, anchor="w", height=22,
                font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=column, sticky="w", padx=pad, pady=(0, 6))
            entry = ctk.CTkEntry(form, textvariable=variable, show="*" if secret else "", height=36,
                fg_color=BG, border_color="#304557", corner_radius=7, font=ctk.CTkFont(size=13))
            entry.grid(row=1, column=column, sticky="ew", padx=pad)
            entry.bind("<Control-s>", lambda _event: self._save_credentials())
            if secret:
                self.credential_entries.append(entry)
        actions = ctk.CTkFrame(data_tab, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", padx=20, pady=(16, 18))
        actions.grid_columnconfigure(2, weight=1)
        self.save_button = ctk.CTkButton(actions, text="Сохранить", height=34, width=126,
            fg_color="#258B77", hover_color="#2BA18A", font=ctk.CTkFont(size=12), command=self._save_credentials)
        self.save_button.grid(row=0, column=0)
        ctk.CTkButton(actions, text="Отменить изменения", height=34, width=156,
            fg_color="transparent", hover_color=PANEL_2, text_color=MUTED, font=ctk.CTkFont(size=12),
            command=self._discard_credentials).grid(row=0, column=1, padx=(8, 0))
        ctk.CTkCheckBox(actions, text="Показать пароли", variable=self._show_passwords,
            command=self._toggle_password_visibility, checkbox_width=16, checkbox_height=16,
            font=ctk.CTkFont(size=11)).grid(row=0, column=3, sticky="e", padx=(16, 0))
        ctk.CTkButton(actions, text="Подключение роутера", height=34, width=166,
            fg_color=PANEL_2, hover_color="#304858", font=ctk.CTkFont(size=12),
            command=self._configure_selected_router).grid(row=0, column=2, sticky="w", padx=12)
        self.save_status = ctk.CTkLabel(actions, text="", text_color="#FFAC9D", anchor="w",
            wraplength=700, justify="left", font=ctk.CTkFont(size=11))
        self.save_status.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.save_status.grid_remove()

        # The existing operations remain behind their own tab and explicit start button.
        attack_tab.grid_columnconfigure(0, weight=1)
        attack_tab.grid_rowconfigure(2, weight=1)
        methods = ctk.CTkFrame(attack_tab, fg_color=PANEL_2, corner_radius=10)
        methods.grid(row=1, column=0, sticky="ew", padx=18, pady=(18, 0))
        methods.grid_columnconfigure((0, 1), weight=1)
        for index, (attribute, title, variable) in enumerate((
            ("hs_check", "Handshake", self._method_handshake),
            ("pmkid_check", "PMKID", self._method_pmkid),
            ("pixie_check", "Pixie Dust", self._method_pixie),
            ("wps_brute_check", "WPS PIN Bruteforce", self._method_wps_brute))):
            check = ctk.CTkCheckBox(methods, text=title, variable=variable,
                font=ctk.CTkFont(size=12), checkbox_width=16, checkbox_height=16)
            check.grid(row=index // 2, column=index % 2, sticky="w", padx=16, pady=12)
            setattr(self, attribute, check)
        self.log_box = ctk.CTkTextbox(attack_tab, height=150, activate_scrollbars=False,
            font=ctk.CTkFont(family="Consolas", size=12), fg_color="#09121A", text_color="#CFE3F5", wrap="word")
        self.log_box.grid(row=2, column=0, sticky="nsew", padx=18, pady=14)
        self.log_box.configure(state="disabled")
        self.connection_status = ctk.CTkLabel(attack_tab, text="", text_color=MUTED,
            anchor="w", wraplength=430, justify="left", font=ctk.CTkFont(size=12))
        self.connection_status.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 8))
        buttons = ctk.CTkFrame(attack_tab, fg_color="transparent")
        buttons.grid(row=4, column=0, sticky="ew", padx=18, pady=(0, 18))
        self.connect_button = ctk.CTkButton(buttons, text="Запустить выбранные", height=40,
            width=190, command=self._connect_selected)
        self.connect_button.pack(side="left")
        self.stop_button = ctk.CTkButton(buttons, text="Остановить", height=40, width=120,
            fg_color="#803F49", hover_color="#A34D5B", state="disabled", command=self._stop_cracking)
        self.stop_button.pack(side="right", padx=(8, 0))
        self.detail_view.grid_remove()

    def _open_route_builder(self) -> None:
        existing = self._route_window is not None and self._route_window.winfo_exists()
        if existing and self._route_window.running:
            self._route_window.focus_execution()
            return
        if not self._save_credentials() or not self.cloud_view.flush():
            return
        source = self.selected_point.bssid if self._details_open and self.selected_point is not None else None
        if not existing:
            self._route_window = RouteBuilderPage(self.page_host, self)
            if source:
                for candidate in self._route_window.model.candidates()[0]:
                    if candidate.get('id') == source:
                        self._route_window.model.choose(candidate)
                        break
        self.main_view.grid_remove()
        self.detail_view.grid_remove()
        self.cloud_view.grid_remove()
        self._details_open = False
        self._clouds_open = False
        self._route_open = True
        self.available_nav.configure(fg_color="transparent")
        self.known_nav.configure(fg_color="transparent")
        self.cloud_nav.configure(fg_color="transparent")
        self._route_window.show_editor()

    def _close_route_builder(self) -> None:
        if self._route_window is not None and self._route_window.winfo_exists():
            self._route_window.close()

    def _refresh_relay_sources(self) -> None:
        if self._route_window is not None and self._route_window.winfo_exists():
            self._route_window.refresh_sources()

    def _show_clouds(self) -> None:
        if self._busy or not self._save_credentials():
            return
        self.main_view.grid_remove()
        self.detail_view.grid_remove()
        if self._route_window is not None and self._route_window.winfo_exists():
            self._route_window.grid_remove()
        self._route_open = False
        self.cloud_view.grid()
        self.cloud_view.tkraise()
        self._details_open = False
        self._clouds_open = True
        self.available_nav.configure(fg_color="transparent")
        self.known_nav.configure(fg_color="transparent")
        self.cloud_nav.configure(fg_color="#233E48")

    def _configure_selected_router(self) -> None:
        if self._busy or self.selected_point is None or not self._save_credentials():
            return
        RouterSettingsDialog(self, self.selected_point.bssid, self._refresh_relay_sources)

    def _relay_credentials_saved(self, bssid, user, password) -> None:
        if self.selected_point is not None and self.selected_point.bssid == bssid:
            self._loading_credentials = True
            self._username.set(user)
            self._user_password.set(password)
            self._loading_credentials = False
            self._credentials_dirty = False
        self._render_rows()
        self._refresh_relay_sources()

    def _on_row_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) in ("tree", "cell"):
            row = self.tree.identify_row(event.y)
            if row:
                self.tree.selection_set(row)
                self._open_selected()

    def _source_points(self) -> list[AccessPoint]:
        if self._list_mode == "available":
            return self.networks
        # Prefer live measurements for points that are in the latest scan.
        live = {point.bssid: point for point in self.networks}
        return [live.get(point.bssid, point) for point in self.store.points()]

    def _set_list_mode(self, mode: str) -> None:
        if self._busy or not self._save_credentials():
            return
        if self._route_open and self._route_window is not None:
            self._route_window.grid_remove()
            self._route_open = False
        if self._clouds_open:
            if not self.cloud_view.flush():
                return
            self.cloud_view.grid_remove()
            self._clouds_open = False
        if self._details_open:
            self._go_back()
        self.cloud_nav.configure(fg_color="transparent")
        self.main_view.grid()
        self._list_mode = mode
        known = mode == "known"
        self.list_title.configure(text="Известные сети" if known else "Wi-Fi сети поблизости")
        self.available_nav.configure(fg_color="transparent" if known else "#233E48")
        self.known_nav.configure(fg_color="#233E48" if known else "transparent")
        self._render_rows()

    def _remember_points(self, points: list[AccessPoint], *, seen: bool = True) -> bool:
        try:
            self.store.remember(points, seen=seen)
            return True
        except StoreError as exc:
            self._status_value.set(str(exc))
            messagebox.showerror("Ошибка журнала сетей", str(exc), parent=self)
            return False

    @staticmethod
    def _shown_date(value: str) -> str:
        try:
            return datetime.fromisoformat(value).astimezone().strftime("%d.%m.%Y  %H:%M")
        except (ValueError, TypeError):
            return "—"

    def _open_selected(self) -> None:
        if self._busy or not self._save_credentials():
            return
        chosen = self.tree.selection()
        if not chosen:
            self._status_value.set("Сначала выделите сеть в таблице.")
            return
        point = self._tree_points.get(chosen[0])
        if point is None:
            return
        if not self.store.get(point.bssid):
            self._remember_points([point])
        same_point = self.selected_point is not None and self.selected_point.bssid == point.bssid
        self.selected_point = point
        record = self.store.get(point.bssid)
        self.detail_name.configure(text=point.shown_ssid)
        values = {"vendor": point.shown_vendor, "bssid": point.bssid,
                  "signal": point.shown_signal, "security": point.shown_security,
                  "adapter": point.adapter,
                  "first_seen": self._shown_date(record.get("first_seen", "")),
                  "last_seen": self._shown_date(record.get("last_seen", ""))}
        for field, value in values.items():
            self.detail_fields[field].configure(text=value)
        online = any(p.bssid == point.bssid for p in self.networks)
        self.detail_presence.configure(text="Доступна" if online else "В истории",
                                       text_color=GREEN if online else MUTED)
        self._loading_credentials = True
        try:
            self._network_password.set(record.get("network_password", ""))
            self._username.set(record.get("username", ""))
            self._user_password.set(record.get("user_password", ""))
        finally:
            self._loading_credentials = False
        self._credentials_dirty = False
        self._show_passwords.set(False)
        self._toggle_password_visibility()
        self.save_status.configure(text="")
        self.save_status.grid_remove()
        self.connection_status.configure(text="", text_color=MUTED)
        self.connect_button.configure(state="normal" if point.ssid and point.ssid != "--" else "disabled")
        self.main_view.grid_remove()
        if not same_point:
            self._clear_log()
            self._crack_results = []
        self.detail_tabs.set("Сеть")
        self.detail_view.grid()
        self.detail_view.tkraise()
        self._details_open = True
        self.back_button.configure(state="normal")

    def _go_back(self) -> None:
        if not self._details_open or not self._save_credentials():
            return
        self.detail_view.grid_remove()
        self.main_view.grid()
        self.main_view.tkraise()
        self._details_open = False
        self.back_button.configure(state="disabled")
        self._render_rows()

    def _toggle_password_visibility(self) -> None:
        for entry in self.credential_entries:
            entry.configure(show="" if self._show_passwords.get() else "*")

    def _credentials_changed(self, *_args) -> None:
        if self._loading_credentials or not self._details_open:
            return
        self._credentials_dirty = True
        self.save_status.configure(text="")
        self.save_status.grid_remove()
        if self._save_job is not None:
            self.after_cancel(self._save_job)
        self._save_job = self.after(700, self._save_credentials)

    def _save_credentials(self) -> bool:
        if self._save_job is not None:
            self.after_cancel(self._save_job)
            self._save_job = None
        if not self._credentials_dirty or self.selected_point is None:
            return True
        try:
            self.store.save_credentials(self.selected_point.bssid, self._network_password.get(),
                                        self._username.get(), self._user_password.get())
        except StoreError as exc:
            self.save_status.configure(text=f"Не сохранено: {exc}", text_color="#FFAC9D")
            self.save_status.grid()
            return False
        self._credentials_dirty = False
        self.save_status.configure(text="")
        self.save_status.grid_remove()
        self._render_rows()
        return True

    def _discard_credentials(self) -> None:
        if self.selected_point is None:
            return
        if self._save_job is not None:
            self.after_cancel(self._save_job)
            self._save_job = None
        record = self.store.get(self.selected_point.bssid)
        self._loading_credentials = True
        try:
            self._network_password.set(record.get("network_password", ""))
            self._username.set(record.get("username", ""))
            self._user_password.set(record.get("user_password", ""))
        finally:
            self._loading_credentials = False
        self._credentials_dirty = False
        self.save_status.configure(text="")
        self.save_status.grid_remove()

    def _os_connect_with_password(self, password: str | None = None) -> None:
        point = self.selected_point
        if point is None or self._busy:
            return

        def completed(result: tuple[str, bool]) -> None:
            message, connected = result
            if connected:
                self.connection_status.configure(text=f"✓ Подключено к точке {point.shown_ssid} ({point.bssid}).",
                                                  text_color="#75D4AC")
                self._status_value.set("Wi-Fi подключён: " + point.shown_ssid)
            else:
                self.connection_status.configure(text=message +
                    " Подтверждение подключения к этому BSSID пока не получено. Проверьте состояние Wi-Fi в ОС.",
                                                 text_color=MUTED)
                self._status_value.set("Запрос на подключение отправлен, связь не подтверждена.")

        self._run("Подключение к Wi-Fi…", lambda: connect_and_verify(point, password), completed)

    def _connect_selected(self) -> None:
        point = self.selected_point
        if point is None or self._busy:
            return

        if not point.ssid or point.ssid == "--":
            self._log_line("[!] Скрытая сеть: атака по ESSID невозможна.")
            return

        methods = []
        if self._method_handshake.get():
            methods.append(METHOD_HANDSHAKE)
        if self._method_pmkid.get():
            methods.append(METHOD_PMKID)
        if self._method_pixie.get():
            methods.append(METHOD_PIXIE_DUST)
        if self._method_wps_brute.get():
            methods.append(METHOD_WPS_BRUTEFORCE)
        if not methods:
            self._log_line("[!] Отметьте хотя бы один способ восстановления пароля.")
            return

        interface = self._resolve_attack_interface()
        if not interface:
            self._log_line(
                "[!] Не удалось определить Wi-Fi интерфейс. "
                "Выберите его в поле «Wi-Fi адаптер» и обновите список сетей."
            )
            return

        self._clear_log()
        self._crack_results = []
        self._crack_stop = threading.Event()
        self.stop_button.configure(state="normal")
        self.connect_button.configure(state="disabled")
        self._set_busy(True, "Восстановление пароля…")
        self._log_line(f"Цель: {point.shown_ssid} ({point.bssid})")
        self._log_line(f"Интерфейс: {interface}")
        self._log_line(f"Методы: {', '.join(methods)}")

        essid = point.ssid
        target = point

        def worker():
            try:
                results = run_attacks(
                    interface=interface,
                    essid=essid,
                    methods=methods,
                    log=lambda line: self._queue.put(("log", line)),
                    stop_event=self._crack_stop,
                )
                self._queue.put(("crack_done", results, target))
            except Exception as exc:  # noqa: BLE001
                self._queue.put(("error", f"Сбой атаки: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def _resolve_attack_interface(self) -> str:
        """Возвращает имя реального Wi-Fi интерфейса для атак."""
        # 1. Из выбранной точки — если там записано настоящее имя.
        point = self.selected_point
        if point is not None and point.adapter and point.adapter != "Все адаптеры":
            return point.adapter

        # 2. Из пикера адаптеров — если выбран конкретный.
        chosen = self.adapter_picker.get()
        if chosen and chosen != "Все адаптеры":
            return chosen

        # 3. Фолбэк: спросить у ОС список Wi-Fi интерфейсов и взять первый.
        try:
            adapters = list_wifi_adapters()
        except Exception as exc:  # noqa: BLE001
            self._log_line(f"[!] Не удалось получить список адаптеров: {exc}")
            return ""
        if not adapters:
            return ""
        if len(adapters) > 1:
            self._log_line(
                f"[i] Найдено несколько адаптеров: {', '.join(adapters)}. "
                f"Использую «{adapters[0]}». Чтобы выбрать другой, укажите его в поле «Wi-Fi адаптер»."
            )
        else:
            self._log_line(f"[i] Wi-Fi интерфейс определён автоматически: {adapters[0]}")
        return adapters[0]

    def _ask_password(self, reason: str) -> None:
        if not self._details_open or self.selected_point is None:
            return
        dialog = ctk.CTkToplevel(self)
        dialog.title("Пароль Wi-Fi")
        dialog.geometry("440x225")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.after(100, lambda: dialog.grab_set() if dialog.winfo_exists() else None)
        ctk.CTkLabel(dialog, text=f"Пароль сети: {self.selected_point.shown_ssid}",
                     font=ctk.CTkFont(size=17, weight="bold")).pack(pady=(18, 3))
        ctk.CTkLabel(dialog, text="Введите пароль для разового подключения через ОС.",
                     text_color=MUTED, font=ctk.CTkFont(size=12)).pack(pady=(0, 9))
        entry = ctk.CTkEntry(dialog, show="*", width=365, placeholder_text="Пароль сети")
        entry.pack(pady=4)
        row = ctk.CTkFrame(dialog, fg_color="transparent")
        row.pack(pady=15)

        def submit(_event=None):
            value = entry.get()
            if not value:
                return
            dialog.grab_release()
            dialog.destroy()
            self._os_connect_with_password(value)

        def cancel():
            dialog.grab_release()
            dialog.destroy()
            self.connection_status.configure(text="Подключение отменено.")

        ctk.CTkButton(row, text="Подключиться", width=140, command=submit).pack(side="left", padx=5)
        ctk.CTkButton(row, text="Отмена", width=100, fg_color=PANEL_2,
                      command=cancel).pack(side="left", padx=5)
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        entry.bind("<Return>", submit)
        entry.focus_set()
        self.connection_status.configure(text=reason, text_color=MUTED)

    def _log_line(self, text: str) -> None:
        if not hasattr(self, "log_box"):
            return
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self) -> None:
        if not hasattr(self, "log_box"):
            return
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _stop_cracking(self) -> None:
        if self._crack_stop is not None:
            self._crack_stop.set()
        self._log_line("[!] Запрошена остановка текущей операции…")
        self.stop_button.configure(state="disabled")

    def _set_busy(self, busy: bool, label: str = "") -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.scan_button, self.vendor_button, self.adapter_button, self.update_db_button, self.import_button):
            button.configure(state=state)
        if hasattr(self, "connect_button"):
            self.connect_button.configure(state="disabled" if busy else "normal")
        if busy:
            self._status_value.set(label)
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)

    def _run(self, message: str, work, finished) -> None:
        if self._busy or self._closing:
            return
        self._set_busy(True, message)

        def worker():
            try:
                result = work()
                self._queue.put(("done", finished, result))
            except PasswordRequired as exc:
                self._queue.put(("password", str(exc)))
            except Exception as exc:
                self._queue.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_queue(self) -> None:
        if self._closing:
            return
        while True:
            try:
                event = self._queue.get_nowait()
            except queue.Empty:
                break
            if event[0] == "progress":
                self._status_value.set(event[1])
            elif event[0] == "error":
                self._set_busy(False)
                self._status_value.set("Ошибка: " + event[1])
                if self._details_open:
                    self.connection_status.configure(text="Ошибка подключения: " + event[1], text_color="#FFAC9D")
            elif event[0] == "password":
                self._set_busy(False)
                self._ask_password(event[1])
            elif event[0] == "log":
                self._log_line(event[1])
            elif event[0] == "crack_done":
                self._set_busy(False)
                self.stop_button.configure(state="disabled")
                self.connect_button.configure(state="normal")
                results, target = event[1], event[2]
                self._crack_results = results
                passwords = [r.password for r in results if r.password]
                if passwords:
                    password = passwords[0]
                    pin_info = ""
                    for r in results:
                        if r.pin:
                            pin_info = f" (PIN: {r.pin})"
                            break
                    self._log_line("")
                    self._log_line(f"[+] Итог: пароль «{password}»{pin_info}")
                    self.connection_status.configure(
                        text=f"✓ Найден пароль: {password}{pin_info}",
                        text_color="#75D4AC")
                    self._status_value.set("Пароль найден.")
                else:
                    pins = [r.pin for r in results if r.pin]
                    if pins:
                        self._log_line(f"[i] PIN найден: {pins[0]}, но PSK не получен.")
                        self.connection_status.configure(
                            text=f"PIN: {pins[0]} — PSK не удалось получить автоматически.",
                            text_color="#FFD180")
                    else:
                        self._log_line("[-] Пароль не найден ни одним из выбранных методов.")
                        self.connection_status.configure(
                            text="Пароль не найден. Попробуйте другой словарь или метод.",
                            text_color="#FFAC9D")
                    self._status_value.set("Пароль не найден.")
            elif event[0] == "done":
                self._set_busy(False)
                try:
                    event[1](event[2])
                except Exception as exc:
                    self._status_value.set(f"Ошибка обновления интерфейса: {exc}")
        self.after(120, self._poll_queue)

    def _refresh_adapters(self) -> None:
        def complete(adapters: list[str]):
            old = self.adapter_picker.get()
            choices = ["Все адаптеры", *adapters]
            self.adapter_picker.configure(values=choices)
            self.adapter_picker.set(old if old in choices else choices[0])
            self._status_value.set("")
            if self._first_adapter_load:
                self._first_adapter_load = False
                self.after(100, self._scan)
            self._log_line(f"Доступные Wi-Fi адаптеры: {', '.join(adapters) or '—'}")

        self._run("Поиск Wi-Fi адаптеров…", list_wifi_adapters, complete)

    def _scan(self) -> None:
        chosen = self.adapter_picker.get()
        adapter = "" if chosen == "Все адаптеры" else chosen

        def complete(points: list[AccessPoint]):
            if self._vendor_enabled and self.vendor_db.count:
                for point in points:
                    point.vendor = self.vendor_db.lookup(point.bssid)
            self.networks = points
            self._remember_points(points)
            self._last_scan = datetime.now()
            self.timestamp_label.configure(text=f"Сканирование: {self._last_scan:%H:%M:%S}")
            self._render_rows()
            self._status_value.set("")

        self._run("Сканирование доступных Wi-Fi сетей…", lambda: scan_wifi(adapter), complete)

    def _find_vendors(self) -> None:
        if not self.networks:
            self._status_value.set("Список пуст. Сначала нажмите «Обновить сети».")
            return
        points = self.networks[:]

        def progress(msg: str):
            self._queue.put(("progress", msg))

        def work():
            errors = []
            if len([n for n in (6, 7, 9) if self.vendor_db.data[n]]) < 3:
                _updated, errors = self.vendor_db.update(force=False, progress=progress)
            vendors = [(point.bssid, self.vendor_db.lookup(point.bssid)) for point in points]
            return vendors, errors

        def complete(result):
            vendors, errors = result
            table = dict(vendors)
            for point in self.networks:
                point.vendor = table.get(point.bssid, NOTICE_UNKNOWN)
            self._vendor_enabled = True
            self._remember_points(self.networks, seen=False)
            self._render_rows()
            recognized = sum(p.vendor not in (NOTICE_LOCAL, NOTICE_UNKNOWN) for p in self.networks)
            self._status_value.set(f"Определены производители: {recognized} из {len(self.networks)}. "
                                   + (f"Часть справочников не загружена ({len(errors)}). Проверьте интернет." if errors else "База IEEE сохранена локально."))

        self._run("Определение производителей по IEEE…", work, complete)

    def _update_ieee(self) -> None:
        def progress(msg: str):
            self._queue.put(("progress", msg))

        def complete(result):
            num, errors = result
            if self._vendor_enabled:
                for point in self.networks:
                    point.vendor = self.vendor_db.lookup(point.bssid)
            self._remember_points(self.networks, seen=False)
            self._render_rows()
            self._status_value.set(f"Обновлено реестров IEEE: {num} из 3. Всего записей: {self.vendor_db.count}. "
                                   + (f"Ошибки: {'; '.join(errors)[:250]}" if errors else ""))

        self._run("Обновление локальной базы производителей IEEE…",
                  lambda: self.vendor_db.update(force=True, progress=progress), complete)

    def _import_ieee(self) -> None:
        filename = filedialog.askopenfilename(title="Выбрать CSV IEEE (MA-L, MA-M или MA-S)",
                                              filetypes=[("CSV-файлы", "*.csv"), ("Все файлы", "*.*")])
        if not filename:
            return

        def complete(result):
            name, count = result
            if self._vendor_enabled:
                for point in self.networks:
                    point.vendor = self.vendor_db.lookup(point.bssid)
            self._remember_points(self.networks, seen=False)
            self._render_rows()
            self._status_value.set(f"Импортирован {name}: {count} записей IEEE.")

        self._run("Импорт реестра IEEE…", lambda: self.vendor_db.import_ieee_file(Path(filename)), complete)

    def _on_sort_changed(self, selection: str):
        self._sort_by = selection
        self._render_rows()

    def _toggle_direction(self):
        self._ascending = not self._ascending
        self.direction_button.configure(text="↑ По возрастанию" if self._ascending else "↓ По убыванию")
        self._render_rows()

    def _click_heading(self, field: str) -> None:
        label = {"ssid": "Имя сети", "vendor": "Производитель", "signal": "Сигнал"}.get(field)
        if label:
            if self._sort_by == label:
                self._toggle_direction()
            else:
                self._sort_by = label
                self.sort_picker.set(label)
                self._ascending = True
                self.direction_button.configure(text="↑ По возрастанию")
                self._render_rows()

    def _resize_network_columns(self, event) -> None:
        if event.width < 16:
            return
        self._column_widths = network_column_widths(event.width - 1)
        for field, width in self._column_widths.items():
            self.tree.column(field, width=width, minwidth=1, stretch=False)
        for item_id, point in self._tree_points.items():
            self.tree.item(item_id, values=self._row_values(point))

    def _row_values(self, point: AccessPoint) -> tuple[str, ...]:
        values = (point.shown_ssid, point.shown_vendor, point.bssid,
                  point.shown_signal, point.shown_security, point.adapter)
        columns = ("ssid", "vendor", "bssid", "signal", "security", "adapter")
        return tuple(fit_cell_text(value, self._column_widths[field] - 8, self._table_font.measure)
                     for field, value in zip(columns, values))

    def _visible_points(self) -> list[AccessPoint]:
        return filter_and_sort(self._source_points(), self._query_value.get(), self._sort_by, self._ascending)

    def _render_rows(self) -> None:
        if not hasattr(self, "tree"):
            return
        points = self._visible_points()
        if points:
            self.empty_label.place_forget()
        else:
            self.empty_label.configure(text="Нет совпадений" if self._query_value.get().strip() else "Нет сетей")
            self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        selected = self.tree.selection()
        selected_key = None
        if selected and selected[0] in self._tree_points:
            old = self._tree_points[selected[0]]
            selected_key = (old.bssid, old.adapter)
        self._tree_points.clear()
        for child in self.tree.get_children():
            self.tree.delete(child)
        new_selection = None
        for idx, point in enumerate(points):
            item_id = f"ap-{idx}"
            self._tree_points[item_id] = point
            flags = credential_flags(self.store.get(point.bssid))
            self.tree.insert("", "end", iid=item_id, image=self._status_icons[flags],
                             values=self._row_values(point),
                             tags=("even" if idx % 2 else "odd",))
            if selected_key == (point.bssid, point.adapter):
                new_selection = item_id
        if new_selection:
            self.tree.selection_set(new_selection)
        source = self._source_points()
        count = len(source)
        self.filtered_label.configure(text=f"{len(points)} / {count}")

    def _export_csv(self) -> None:
        if not self._source_points():
            self._status_value.set("Нет записей для экспорта.")
            return
        filename = filedialog.asksaveasfilename(title="Экспорт списка Wi-Fi", defaultextension=".csv",
                                                initialfile="wifi_networks.csv", filetypes=[("CSV", "*.csv")])
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8-sig", newline="") as file:
                writer = csv.writer(file, delimiter=";")
                writer.writerow(["SSID", "Производитель (IEEE)", "BSSID", "Сигнал, %", "Защита / WPS", "Адаптер"])
                for p in self._visible_points():
                    writer.writerow([p.shown_ssid, p.vendor or NOTICE_UNKNOWN, p.bssid,
                                     p.signal if p.signal is not None else "", p.shown_security, p.adapter])
            self._status_value.set(f"CSV сохранён: {filename}")
        except OSError as exc:
            messagebox.showerror("Ошибка сохранения CSV", str(exc))

    def _close(self) -> None:
        if not self._save_credentials() or not self.cloud_view.flush():
            return
        if self._route_window is not None and self._route_window.winfo_exists() and self._route_window.running:
            self._close_after_relay = True
            self._route_window.request_stop()
            self._status_value.set("Остановка передачи…")
            return
        if not getattr(self.cloud_view, 'close_feeds', lambda: True)():
            self._status_value.set("Остановка скачивания…")
            self.after(100, self._close)
            return
        self._closing = True
        if self._save_job is not None:
            self.after_cancel(self._save_job)
        if self._crack_stop is not None:
            self._crack_stop.set()
        self.destroy()


if __name__ == "__main__":
    WiFiVendorApp().mainloop()
