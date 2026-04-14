
import base64
import csv
import json
import os
import secrets
import textwrap
import zlib
import hashlib
import hmac
from datetime import datetime, timedelta

import requests
import rsa
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.utils import get_color_from_hex
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import FadeTransition, Screen, ScreenManager
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.graphics import Color, RoundedRectangle

BG = "#000000"
CARD = "#0b0b0b"
TEXT = "#b1bad3"
SUBTEXT = "#8f9bb3"
GREEN = "#00e701"
RED = "#ff4e4e"
BLUE = "#3498db"
PURPLE = "#9b59b6"
ORANGE = "#e67e22"
Window.clearcolor = get_color_from_hex(BG)

PRIVATE_KEY_FILE = "license_private.pem"
PUBLIC_KEY_FILE = "license_public.pem"
LICENSE_DB_FILE = "licenses_db.json"
REVOKED_EXPORT_FILE = "revoked_licenses.json"
AUTHORITY_BACKUP_FILE = "authority_backup.ctp"
LICENSE_LIST_BACKUP_FILE = "license_list_backup.ctlist"
FULL_BACKUP_FILE = "full_backup.ctfull"
GITHUB_CONFIG_FILE = "github_upload_config.json"
BACKUP_BUNDLE_APP = "casino_tools_license_manager"

DEFAULT_GITHUB_UPLOAD = {
    "owner": "therealwolfman97",
    "repo": "casino-tools-revocations",
    "branch": "main",
    "path": REVOKED_EXPORT_FILE,
    "token": "",
}


PRODUCT_SCOPE_SHARED = "shared"
PRODUCT_SCOPE_CTP = "ctp"
PRODUCT_SCOPE_SSP = "ssp"
PRODUCT_SCOPE_CHOICES = (PRODUCT_SCOPE_SHARED, PRODUCT_SCOPE_CTP, PRODUCT_SCOPE_SSP)
PRODUCT_SCOPE_LABELS = {
    PRODUCT_SCOPE_SHARED: "Shared / Universal",
    PRODUCT_SCOPE_CTP: "Casino Tools Pro",
    PRODUCT_SCOPE_SSP: "Strategy Suite Pro",
}
PRODUCT_SCOPE_ACCENTS = {
    PRODUCT_SCOPE_SHARED: PURPLE,
    PRODUCT_SCOPE_CTP: GREEN,
    PRODUCT_SCOPE_SSP: BLUE,
}
PRODUCT_SCOPE_UI_VALUES = tuple(PRODUCT_SCOPE_LABELS[k] for k in PRODUCT_SCOPE_CHOICES)


def normalize_product_scope(value):
    value = str(value or "").strip().lower()
    if value in PRODUCT_SCOPE_CHOICES:
        return value
    return PRODUCT_SCOPE_SHARED


def product_scope_label(value):
    return PRODUCT_SCOPE_LABELS.get(normalize_product_scope(value), PRODUCT_SCOPE_LABELS[PRODUCT_SCOPE_SHARED])


def product_scope_from_ui(value):
    txt = str(value or '').strip()
    for key, label in PRODUCT_SCOPE_LABELS.items():
        if txt == label:
            return key
    return normalize_product_scope(txt)


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def app_data_dir():
    app = App.get_running_app()
    if app and getattr(app, "user_data_dir", None):
        path = app.user_data_dir
    else:
        path = os.path.join(os.path.expanduser("~"), ".casino_tools_license_manager")
    os.makedirs(path, exist_ok=True)
    return path


def file_path(name):
    return os.path.join(app_data_dir(), name)


def downloads_base_dir():
    candidates = [
        "/storage/emulated/0/Download",
        "/sdcard/Download",
        os.path.join(os.path.expanduser("~"), "Download"),
    ]
    for path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except Exception:
            continue
    fallback = app_data_dir()
    os.makedirs(fallback, exist_ok=True)
    return fallback


def admin_export_dir(*parts):
    path = os.path.join(downloads_base_dir(), "Casino Tools Pro Admin", *parts)
    os.makedirs(path, exist_ok=True)
    return path



def _timestamped_export_path(directory, filename):
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base, ext = os.path.splitext(filename)
    return os.path.join(directory, f"{base}_{stamp}{ext}")


def list_backup_files(directory, suffixes):
    candidates = []
    suffixes = tuple(str(s).lower() for s in (suffixes or []))
    try:
        for name in os.listdir(directory):
            lower = name.lower()
            if suffixes and not lower.endswith(suffixes):
                continue
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                candidates.append(path)
    except Exception:
        return []
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates


def authority_backup_dir():
    return admin_export_dir("Authority Backups")


def authority_backup_export_path():
    return _timestamped_export_path(authority_backup_dir(), AUTHORITY_BACKUP_FILE)


def list_authority_backup_files():
    return list_backup_files(authority_backup_dir(), [".ctp", ".shva", ".ctfull"])


def license_list_backup_dir():
    return admin_export_dir("License List Backups")


def license_list_backup_export_path():
    return _timestamped_export_path(license_list_backup_dir(), LICENSE_LIST_BACKUP_FILE)


def list_license_list_backup_files():
    return list_backup_files(license_list_backup_dir(), [".ctlist", ".json", ".txt", ".ctfull"])


def full_backup_dir():
    return admin_export_dir("Full Backups")


def full_backup_export_path():
    return _timestamped_export_path(full_backup_dir(), FULL_BACKUP_FILE)


def list_full_backup_files():
    return list_backup_files(full_backup_dir(), [".ctfull", ".ctp", ".shva", ".ctlist"])


def revocation_backup_dir():
    return admin_export_dir("Revocation Jsons")


def revocation_export_path():
    return _timestamped_export_path(revocation_backup_dir(), REVOKED_EXPORT_FILE)


def list_revocation_backup_files():
    return list_backup_files(revocation_backup_dir(), [".json", ".txt"])


def license_export_dir():
    return admin_export_dir("License Exports")


def license_export_path():
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return os.path.join(license_export_dir(), f"licenses_export_{stamp}.csv")


def github_config_path():
    return file_path(GITHUB_CONFIG_FILE)


def load_github_upload_config():
    data = load_json(github_config_path(), {})
    merged = dict(DEFAULT_GITHUB_UPLOAD)
    if isinstance(data, dict):
        for key in ("owner", "repo", "branch", "path"):
            value = str(data.get(key, "")).strip()
            if value:
                merged[key] = value
    return merged


def save_github_upload_config(data):
    clean = {}
    for key in ("owner", "repo", "branch", "path"):
        clean[key] = str(data.get(key, DEFAULT_GITHUB_UPLOAD.get(key, ""))).strip()
    save_json(github_config_path(), clean)


def build_github_raw_url(owner, repo, branch, path):
    owner = str(owner).strip().strip("/")
    repo = str(repo).strip().strip("/")
    branch = str(branch).strip().strip("/") or "main"
    path = str(path).strip().lstrip("/")
    if not owner or not repo or not path:
        return ""
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def info_popup(title, message):
    content = BoxLayout(orientation="vertical", padding=dp(14), spacing=dp(10))
    lbl = Label(
        text=message,
        color=get_color_from_hex(TEXT),
        halign="left",
        valign="top",
        text_size=(dp(300), None),
        size_hint_y=None,
    )
    lbl.bind(texture_size=lambda inst, val: setattr(inst, "height", max(val[1], dp(80))))
    btn = RoundedButton(
        text="OK",
        size_hint_y=None,
        height=dp(46),
        bg_hex=GREEN,
    )
    content.add_widget(lbl)
    content.add_widget(btn)
    popup = Popup(
        title=title,
        content=content,
        size_hint=(0.9, 0.6),
        separator_color=get_color_from_hex(GREEN),
        background_color=get_color_from_hex(CARD),
    )
    btn.bind(on_release=popup.dismiss)
    popup.open()


def copy_to_clipboard(label, value):
    Clipboard.copy(value or "")
    info_popup("Copied", f"{label} copied to clipboard.")



def load_existing_keypair():
    priv_path = file_path(PRIVATE_KEY_FILE)
    pub_path = file_path(PUBLIC_KEY_FILE)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open(pub_path, "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        return public_key, private_key
    return None, None


def initialize_authority_keypair():
    priv_path = file_path(PRIVATE_KEY_FILE)
    pub_path = file_path(PUBLIC_KEY_FILE)
    if os.path.exists(priv_path) or os.path.exists(pub_path):
        raise RuntimeError("Authority already exists on this device.")
    public_key, private_key = rsa.newkeys(2048)
    with open(priv_path, "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))
    with open(pub_path, "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    return public_key, private_key


def _pbkdf(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)


def _xor_stream(key: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        take = min(len(block), len(data) - len(out))
        chunk = data[len(out):len(out)+take]
        out.extend(bytes(a ^ b for a, b in zip(chunk, block[:take])))
        counter += 1
    return bytes(out)



def build_secure_backup_blob(password: str, bundle_type: str, payload: dict):
    if not password:
        raise ValueError("Backup password is required.")
    raw_payload = {
        "schema": 2,
        "app": BACKUP_BUNDLE_APP,
        "bundle_type": bundle_type,
        "exported_at": utc_now_iso(),
        "payload": payload,
    }
    raw = canonical_json(raw_payload)
    salt = os.urandom(16)
    enc_key = _pbkdf(password, salt)
    ciphertext = _xor_stream(enc_key, raw)
    mac = hmac.new(enc_key, salt + ciphertext, hashlib.sha256).digest()
    bundle = {
        "schema": 2,
        "app": BACKUP_BUNDLE_APP,
        "bundle_type": bundle_type,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "mac": base64.urlsafe_b64encode(mac).decode("ascii"),
    }
    return json.dumps(bundle, indent=2)


def parse_secure_backup_blob(blob_text: str, password: str):
    if not blob_text.strip():
        raise ValueError("Backup text is empty.")
    if not password:
        raise ValueError("Backup password is required.")
    bundle = json.loads(blob_text)
    salt = base64.urlsafe_b64decode(bundle["salt"].encode("ascii"))
    ciphertext = base64.urlsafe_b64decode(bundle["ciphertext"].encode("ascii"))
    mac = base64.urlsafe_b64decode(bundle["mac"].encode("ascii"))
    enc_key = _pbkdf(password, salt)
    expected = hmac.new(enc_key, salt + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Backup password is incorrect or backup is corrupted.")
    raw = _xor_stream(enc_key, ciphertext)
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, dict) and "payload" in data and "bundle_type" in data:
        return data
    legacy_payload = {}
    if "private_key_pem" in data:
        legacy_payload["private_key_pem"] = data.get("private_key_pem", "")
    if "public_key_pem" in data:
        legacy_payload["public_key_pem"] = data.get("public_key_pem", "")
    if "licenses" in data:
        legacy_payload["licenses"] = data.get("licenses", [])
    if "revoked_bundle" in data:
        legacy_payload["revoked_bundle"] = data.get("revoked_bundle", {})
    return {
        "schema": data.get("schema", 1),
        "app": data.get("app", BACKUP_BUNDLE_APP),
        "bundle_type": "legacy_full_backup",
        "exported_at": data.get("exported_at", ""),
        "payload": legacy_payload,
    }


def build_authority_backup_blob(password: str):
    public_key, private_key = load_existing_keypair()
    if not public_key or not private_key:
        raise ValueError("No authority loaded. Initialize or import authority first.")
    payload = {
        "private_key_pem": private_key.save_pkcs1("PEM").decode("utf-8"),
        "public_key_pem": public_key.save_pkcs1("PEM").decode("utf-8"),
    }
    return build_secure_backup_blob(password, "authority_only", payload)


def build_license_list_backup_blob(password: str, records):
    payload = {
        "licenses": records,
    }
    return build_secure_backup_blob(password, "license_list_only", payload)


def build_full_backup_blob(password: str, records):
    public_key, private_key = load_existing_keypair()
    if not public_key or not private_key:
        raise ValueError("No authority loaded. Initialize or import authority first.")
    revoked_bundle = build_revocation_bundle(records, private_key)
    payload = {
        "private_key_pem": private_key.save_pkcs1("PEM").decode("utf-8"),
        "public_key_pem": public_key.save_pkcs1("PEM").decode("utf-8"),
        "licenses": records,
        "revoked_bundle": revoked_bundle,
    }
    return build_secure_backup_blob(password, "full_backup", payload)


def sign_payload(private_key, payload_dict):
    sig = rsa.sign(canonical_json(payload_dict), private_key, "SHA-256")
    return base64.urlsafe_b64encode(sig).decode("ascii")


def verify_signature(public_key, payload_dict, sig_b64):
    try:
        sig = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
        rsa.verify(canonical_json(payload_dict), sig, public_key)
        return True
    except Exception:
        return False


def encode_activation_code(payload_dict, signature_b64):
    blob = {"p": payload_dict, "s": signature_b64}
    raw = canonical_json(blob)
    compressed = zlib.compress(raw, level=9)
    token = base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")
    chunks = textwrap.wrap(token, 24)
    return "CTP6A-" + ".".join(chunks)


def decode_activation_code(code):
    cleaned = code.strip().replace("\n", "").replace(" ", "")
    if cleaned.startswith("CTP6A-"):
        cleaned = cleaned[6:]
    cleaned = cleaned.replace(".", "")
    cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
    raw = base64.urlsafe_b64decode(cleaned.encode("ascii"))
    data = json.loads(zlib.decompress(raw).decode("utf-8"))
    return data["p"], data["s"]


def build_revocation_bundle(records, private_key):
    revoked_ids = sorted([r["license_id"] for r in records if r.get("status") == "revoked"])
    payload = {
        "app": "casino_tools_pro",
        "version": 1,
        "updated_at": utc_now_iso(),
        "revoked_ids": revoked_ids,
    }
    signature = sign_payload(private_key, payload)
    return {"payload": payload, "signature": signature}


class LicenseStore:
    def __init__(self):
        self.path = file_path(LICENSE_DB_FILE)
        self.records = load_json(self.path, [])

    def save(self):
        save_json(self.path, self.records)

    def add(self, record):
        self.records.insert(0, record)
        self.save()

    def update(self, license_id, updater):
        for rec in self.records:
            if rec["license_id"] == license_id:
                updater(rec)
                self.save()
                return True
        return False

    def delete(self, license_id):
        before = len(self.records)
        self.records = [rec for rec in self.records if rec.get("license_id") != license_id]
        changed = len(self.records) != before
        if changed:
            self.save()
        return changed

    def delete_many(self, license_ids):
        wanted = {str(x) for x in (license_ids or []) if str(x)}
        if not wanted:
            return 0
        before = len(self.records)
        self.records = [rec for rec in self.records if rec.get("license_id") not in wanted]
        removed = before - len(self.records)
        if removed:
            self.save()
        return removed

    def find(self, license_id):
        for rec in self.records:
            if rec["license_id"] == license_id:
                return rec
        return None



class RoundedButton(Button):
    def __init__(self, bg_hex=GREEN, text_color=None, radius=16, **kwargs):
        kwargs.setdefault("background_normal", "")
        kwargs.setdefault("background_down", "")
        kwargs.setdefault("background_color", (0, 0, 0, 0))
        super().__init__(**kwargs)
        self._bg_hex = bg_hex
        self._radius = radius
        if text_color is None:
            text_color = (0, 0, 0, 1) if bg_hex == GREEN else (1, 1, 1, 1)
        self.color = text_color
        self.bold = True
        with self.canvas.before:
            self._bg_color_instruction = Color(rgba=get_color_from_hex(bg_hex))
            self._rounded_bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(radius)])
        self.bind(pos=self._update_bg, size=self._update_bg)

    def _update_bg(self, *_):
        self._rounded_bg.pos = self.pos
        self._rounded_bg.size = self.size

    def set_bg_hex(self, bg_hex, text_color=None):
        self._bg_hex = bg_hex
        self._bg_color_instruction.rgba = get_color_from_hex(bg_hex)
        if text_color is None:
            text_color = (0, 0, 0, 1) if bg_hex == GREEN else (1, 1, 1, 1)
        self.color = text_color



class SectionCard(BoxLayout):
    def __init__(self, title, subtitle="", **kwargs):
        super().__init__(orientation="vertical", spacing=dp(8), padding=dp(12), size_hint_y=None, **kwargs)
        self.bind(minimum_height=self.setter("height"))
        from kivy.graphics import Color, RoundedRectangle
        with self.canvas.before:
            Color(rgba=get_color_from_hex(CARD))
            self._bg = RoundedRectangle(radius=[18], pos=self.pos, size=self.size)
        self.bind(pos=self._update_bg, size=self._update_bg)

        title_lbl = Label(
            text=title,
            bold=True,
            color=get_color_from_hex(TEXT),
            size_hint_y=None,
            height=dp(24),
            halign="left",
            valign="middle",
            text_size=(dp(320), None),
        )
        self.add_widget(title_lbl)

        if subtitle:
            subtitle_lbl = Label(
                text=subtitle,
                color=get_color_from_hex(SUBTEXT),
                size_hint_y=None,
                halign="left",
                valign="middle",
                text_size=(dp(320), None),
            )
            subtitle_lbl.bind(texture_size=lambda inst, val: setattr(inst, "height", max(dp(18), val[1])))
            self.add_widget(subtitle_lbl)

    def _update_bg(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size


def make_label(text, color=TEXT, bold=False, height=dp(24)):
    return Label(
        text=text,
        color=get_color_from_hex(color),
        bold=bold,
        size_hint_y=None,
        height=height,
        halign="left",
        valign="middle",
        text_size=(dp(320), None),
    )


def make_input(hint="", multiline=False, readonly=False, password=False):
    return TextInput(
        hint_text=hint,
        multiline=multiline,
        readonly=readonly,
        password=password,
        size_hint_y=None,
        height=dp(46) if not multiline else dp(100),
        background_color=get_color_from_hex("#111111"),
        foreground_color=get_color_from_hex(TEXT),
        cursor_color=get_color_from_hex(GREEN),
        hint_text_color=get_color_from_hex(SUBTEXT),
        padding=[dp(10), dp(12), dp(10), dp(12)],
    )


def make_button(text, color=GREEN):
    return RoundedButton(
        text=text,
        size_hint_y=None,
        height=dp(46),
        bg_hex=color,
        text_color=(0, 0, 0, 1) if color == GREEN else (1, 1, 1, 1),
    )


def make_nav_button(text):
    btn = RoundedButton(
        text=text,
        size_hint=(1, None),
        height=dp(44),
        bg_hex="#182432",
        text_color=get_color_from_hex(TEXT),
        radius=22,
    )
    return btn


class LicenseManagerScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.store = LicenseStore()
        self.public_key, self.private_key = load_existing_keypair()
        self.github_config = load_github_upload_config()
        self._last_license_id = ""
        self.active_product_scope = PRODUCT_SCOPE_SHARED
        self.add_widget(BoxLayout())
        Clock.schedule_once(self.build_ui, 0)


    def build_ui(self, *_):
        self.clear_widgets()
        root = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(10))

        top_bar = BoxLayout(size_hint_y=None, height=dp(56), spacing=dp(8))
        title_wrap = BoxLayout(orientation="vertical", spacing=dp(2))
        self.title_label = Label(
            text="SHV Ecosystem License Manager",
            color=get_color_from_hex(TEXT),
            bold=True,
            halign="left",
            valign="middle",
            font_size='18sp',
        )
        self.title_label.bind(size=lambda inst, val: setattr(inst, "text_size", val))
        self.scope_subtitle = Label(
            text="Shared / Universal view",
            color=get_color_from_hex(SUBTEXT),
            halign="left",
            valign="middle",
            font_size='12sp',
            size_hint_y=None,
            height=dp(18),
        )
        self.scope_subtitle.bind(size=lambda inst, val: setattr(inst, "text_size", val))
        title_wrap.add_widget(self.title_label)
        title_wrap.add_widget(self.scope_subtitle)
        top_bar.add_widget(title_wrap)
        exit_btn = make_button("EXIT", RED)
        exit_btn.size_hint_x = None
        exit_btn.width = dp(100)
        exit_btn.bind(on_release=lambda *_: App.get_running_app().stop())
        top_bar.add_widget(exit_btn)
        root.add_widget(top_bar)

        selector_row = GridLayout(cols=3, spacing=dp(8), size_hint_y=None, height=dp(46))
        self.product_scope_buttons = {}
        for key in PRODUCT_SCOPE_CHOICES:
            btn = make_nav_button(product_scope_label(key))
            btn.bind(on_release=lambda *_ , scope_key=key: self.switch_product_scope(scope_key))
            self.product_scope_buttons[key] = btn
            selector_row.add_widget(btn)
        root.add_widget(selector_row)

        nav_grid = GridLayout(cols=3, spacing=dp(8), size_hint_y=None, height=dp(92))
        self.tab_buttons = {}
        self.tab_titles = {
            "dashboard": "Dashboard",
            "authority": "Authority",
            "generate": "Generate",
            "licenses": "Licenses",
            "revocations": "Revocations",
        }
        for key in ("dashboard", "authority", "generate", "licenses", "revocations"):
            btn = make_nav_button(self.tab_titles[key])
            btn.bind(on_release=lambda *_ , tab_key=key: self.switch_tab(tab_key))
            self.tab_buttons[key] = btn
            nav_grid.add_widget(btn)
        root.add_widget(nav_grid)

        self.content_host = BoxLayout()
        root.add_widget(self.content_host)
        self.add_widget(root)

        self.tab_views = {
            "dashboard": self.build_dashboard_view(),
            "authority": self.build_authority_view(),
            "generate": self.build_generate_view(),
            "licenses": self.build_licenses_view(),
            "revocations": self.build_revocation_view(),
        }

        self.switch_tab("dashboard")
        self.switch_product_scope(self.active_product_scope)
        self.update_authority_status()
        self.refresh_dashboard()
        self.refresh_license_list()
        self.refresh_revocation_box()

    def switch_product_scope(self, scope_key):
        self.active_product_scope = normalize_product_scope(scope_key)
        if hasattr(self, 'scope_subtitle'):
            self.scope_subtitle.text = f"{product_scope_label(self.active_product_scope)} view"
        active_bg = PRODUCT_SCOPE_ACCENTS.get(self.active_product_scope, PURPLE)
        inactive_bg = "#24364a"
        for key, btn in getattr(self, 'product_scope_buttons', {}).items():
            chosen = active_bg if key == self.active_product_scope else inactive_bg
            if hasattr(btn, 'set_bg_hex'):
                btn.set_bg_hex(chosen)
            else:
                btn.background_color = get_color_from_hex(chosen)
        if hasattr(self, 'generate_scope_spinner'):
            self.generate_scope_spinner.text = product_scope_label(self.active_product_scope)
        self.refresh_dashboard()
        self.refresh_license_list()

    def current_scope_accent(self):
        return PRODUCT_SCOPE_ACCENTS.get(normalize_product_scope(getattr(self, 'active_product_scope', PRODUCT_SCOPE_SHARED)), PURPLE)

    def record_matches_active_scope(self, rec):
        scope = normalize_product_scope(rec.get('product_scope', PRODUCT_SCOPE_SHARED))
        active = normalize_product_scope(getattr(self, 'active_product_scope', PRODUCT_SCOPE_SHARED))
        if active == PRODUCT_SCOPE_SHARED:
            return True
        if scope == PRODUCT_SCOPE_SHARED:
            return True
        return scope == active

    def paste_device_code_from_clipboard(self):
        self._paste_into_widget(self.device_input, 'There is no device code in the clipboard.')
        try:
            self.device_input.text = self.device_input.text.strip().upper()
        except Exception:
            pass

    def switch_tab(self, key):
        if not hasattr(self, "content_host"):
            return
        self.content_host.clear_widgets()
        view = self.tab_views.get(key)
        if view is not None:
            self.content_host.add_widget(view)

        active_bg = GREEN
        inactive_bg = "#24364a"
        for btn_key, btn in self.tab_buttons.items():
            chosen = active_bg if btn_key == key else inactive_bg
            if hasattr(btn, 'set_bg_hex'):
                btn.set_bg_hex(chosen)
            else:
                btn.background_color = get_color_from_hex(chosen)

    def switch_license_subtab(self, key):
        if not hasattr(self, 'license_subtab_host'):
            return
        self.license_subtab_host.clear_widgets()
        if key == 'tools':
            self.license_subtab_host.add_widget(self.license_tools_view)
        else:
            self.license_subtab_host.add_widget(self.license_list_view)
        active_bg = GREEN
        inactive_bg = "#24364a"
        for btn_key, btn in getattr(self, 'license_subtab_buttons', {}).items():
            chosen = active_bg if btn_key == key else inactive_bg
            if hasattr(btn, 'set_bg_hex'):
                btn.set_bg_hex(chosen)
            else:
                btn.background_color = get_color_from_hex(chosen)

    def build_dashboard_view(self):
        scroll = ScrollView(do_scroll_x=False)
        self.dashboard_box = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8), 0, dp(8)])
        self.dashboard_box.bind(minimum_height=self.dashboard_box.setter("height"))
        scroll.add_widget(self.dashboard_box)
        return scroll


    def build_authority_view(self):
        scroll = ScrollView(do_scroll_x=False)
        box = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8), 0, dp(8)])
        box.bind(minimum_height=box.setter("height"))

        card = SectionCard("Authority only backup", "Share the same signing authority across apps without replacing this app's local license list.")
        self.auth_status_label = make_label("", color=SUBTEXT, height=dp(44))
        card.add_widget(self.auth_status_label)

        card.add_widget(make_label("Backup Password"))
        self.backup_password_input = make_input("Enter backup password")
        card.add_widget(self.backup_password_input)

        row1 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        init_btn = make_button("Initialize Authority", BLUE)
        copy_pub_btn = make_button("Copy Public Key PEM", PURPLE)
        row1.add_widget(init_btn)
        row1.add_widget(copy_pub_btn)
        init_btn.bind(on_release=lambda *_: self.initialize_authority())
        copy_pub_btn.bind(on_release=lambda *_: self.copy_public_key())
        card.add_widget(row1)

        row2 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        gen_backup_btn = make_button("Generate Authority Backup", GREEN)
        copy_backup_btn = make_button("Copy Authority Backup", ORANGE)
        row2.add_widget(gen_backup_btn)
        row2.add_widget(copy_backup_btn)
        gen_backup_btn.bind(on_release=lambda *_: self.generate_authority_backup())
        copy_backup_btn.bind(on_release=lambda *_: copy_to_clipboard("Authority backup", getattr(self, "backup_output", make_input()).text if hasattr(self, "backup_output") else ""))
        card.add_widget(row2)

        self.backup_output = make_input("Generated encrypted authority-only backup will appear here", multiline=True, readonly=True)
        self.backup_output.height = dp(220)
        card.add_widget(self.backup_output)

        row3 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        save_backup_btn = make_button("Save Authority File", BLUE)
        import_backup_btn = make_button("Import Authority", GREEN)
        row3.add_widget(save_backup_btn)
        row3.add_widget(import_backup_btn)
        save_backup_btn.bind(on_release=lambda *_: self.save_authority_backup())
        import_backup_btn.bind(on_release=lambda *_: self.import_authority_backup())
        card.add_widget(row3)

        card.add_widget(make_label("Paste Authority Backup To Import"))
        self.import_backup_input = make_input("Paste encrypted authority backup here", multiline=True)
        self.import_backup_input.height = dp(180)
        card.add_widget(self.import_backup_input)

        row4 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        paste_btn = make_button("Paste", BLUE)
        import_file_btn = make_button("Import Auth File", PURPLE)
        paste_btn.bind(on_release=lambda *_: self.paste_backup_from_clipboard())
        import_file_btn.bind(on_release=lambda *_: self.open_auth_file_picker())
        row4.add_widget(paste_btn)
        row4.add_widget(import_file_btn)
        card.add_widget(row4)
        box.add_widget(card)

        full_card = SectionCard("Full backup", "Back up authority + this app's local license list + a revocation snapshot in one encrypted file.")
        full_card.add_widget(make_label("Uses the same backup password above.", color=SUBTEXT, height=dp(28)))

        full_row1 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        gen_full_btn = make_button("Generate Full Backup", GREEN)
        copy_full_btn = make_button("Copy Full Backup", ORANGE)
        gen_full_btn.bind(on_release=lambda *_: self.generate_full_backup())
        copy_full_btn.bind(on_release=lambda *_: copy_to_clipboard("Full backup", getattr(self, "full_backup_output", make_input()).text if hasattr(self, "full_backup_output") else ""))
        full_row1.add_widget(gen_full_btn)
        full_row1.add_widget(copy_full_btn)
        full_card.add_widget(full_row1)

        self.full_backup_output = make_input("Generated encrypted full backup will appear here", multiline=True, readonly=True)
        self.full_backup_output.height = dp(220)
        full_card.add_widget(self.full_backup_output)

        full_row2 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        save_full_btn = make_button("Save Full Backup", BLUE)
        import_full_btn = make_button("Import Full Backup", GREEN)
        save_full_btn.bind(on_release=lambda *_: self.save_full_backup())
        import_full_btn.bind(on_release=lambda *_: self.import_full_backup())
        full_row2.add_widget(save_full_btn)
        full_row2.add_widget(import_full_btn)
        full_card.add_widget(full_row2)

        full_card.add_widget(make_label("Paste Full Backup To Import"))
        self.import_full_backup_input = make_input("Paste encrypted full backup here", multiline=True)
        self.import_full_backup_input.height = dp(180)
        full_card.add_widget(self.import_full_backup_input)

        full_row3 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        paste_full_btn = make_button("Paste", BLUE)
        import_full_file_btn = make_button("Import Full File", PURPLE)
        paste_full_btn.bind(on_release=lambda *_: self.paste_full_backup_from_clipboard())
        import_full_file_btn.bind(on_release=lambda *_: self.open_full_backup_file_picker())
        full_row3.add_widget(paste_full_btn)
        full_row3.add_widget(import_full_file_btn)
        full_card.add_widget(full_row3)
        box.add_widget(full_card)

        scroll.add_widget(box)
        return scroll

    def build_generate_view(self):
        scroll = ScrollView(do_scroll_x=False)
        box = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8), 0, dp(8)])
        box.bind(minimum_height=box.setter("height"))

        card = SectionCard("Generate activation code", "Create device-bound Demo / Pro / Pro+ licenses for Casino Tools Pro, Strategy Suite Pro, or both.")
        self.device_input = make_input("Device Code (ex: CTP6-DEV-83F1A7C9)")
        self.generate_scope_spinner = Spinner(text=product_scope_label(self.active_product_scope), values=PRODUCT_SCOPE_UI_VALUES, size_hint_y=None, height=dp(46))
        self.tier_spinner = Spinner(text="pro", values=("demo", "pro", "pro_plus"), size_hint_y=None, height=dp(46))
        self.source_spinner = Spinner(text="crypto", values=("crypto", "bank", "promo", "partner", "personal", "test"), size_hint_y=None, height=dp(46))
        self.label_input = make_input("Label (optional)")
        self.note_input = make_input("Customer note / payment note (optional)", multiline=True)
        self.expiry_input = make_input("Expiry date YYYY-MM-DD (optional)")

        card.add_widget(make_label("Applies To"))
        card.add_widget(self.generate_scope_spinner)
        card.add_widget(make_label("Device Code"))
        device_row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        self.device_input.size_hint_x = 1
        paste_device_btn = make_button("Paste", BLUE)
        paste_device_btn.size_hint_x = None
        paste_device_btn.width = dp(96)
        paste_device_btn.bind(on_release=lambda *_: self.paste_device_code_from_clipboard())
        device_row.add_widget(self.device_input)
        device_row.add_widget(paste_device_btn)
        card.add_widget(device_row)

        for title, widget in [
            ("Tier", self.tier_spinner),
            ("Payment / Source", self.source_spinner),
            ("Label", self.label_input),
            ("Note", self.note_input),
            ("Expiry", self.expiry_input),
        ]:
            card.add_widget(make_label(title))
            card.add_widget(widget)

        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        gen_btn = make_button("Generate License")
        clear_btn = make_button("Clear", BLUE)
        gen_btn.bind(on_release=lambda *_: self.generate_license())
        clear_btn.bind(on_release=lambda *_: self.clear_generate_form())
        row.add_widget(gen_btn)
        row.add_widget(clear_btn)
        card.add_widget(row)

        test_btn = make_button("Generate 7-Day Test Pro+", PURPLE)
        test_btn.bind(on_release=lambda *_: self.generate_test_license())
        card.add_widget(test_btn)

        self.generated_code_input = make_input("Generated activation code will appear here", multiline=True, readonly=True)
        self.generated_code_input.height = dp(160)
        card.add_widget(make_label("Activation Code"))
        card.add_widget(self.generated_code_input)

        row2 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        copy_btn = make_button("Copy Code", ORANGE)
        copy_id_btn = make_button("Copy License ID", PURPLE)
        copy_btn.bind(on_release=lambda *_: copy_to_clipboard("Activation code", self.generated_code_input.text))
        copy_id_btn.bind(on_release=lambda *_: copy_to_clipboard("License ID", self._last_license_id))
        row2.add_widget(copy_btn)
        row2.add_widget(copy_id_btn)
        card.add_widget(row2)

        box.add_widget(card)
        scroll.add_widget(box)
        return scroll


    def build_licenses_view(self):
        root = BoxLayout(orientation='vertical', spacing=dp(8), padding=[0, dp(4), 0, dp(4)])

        tab_row = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(46))
        self.license_subtab_buttons = {}
        for key, title in (("tools", "Tools"), ("list", "License List")):
            btn = make_nav_button(title)
            btn.bind(on_release=lambda *_ , tab_key=key: self.switch_license_subtab(tab_key))
            self.license_subtab_buttons[key] = btn
            tab_row.add_widget(btn)
        root.add_widget(tab_row)

        self.license_subtab_host = BoxLayout()
        root.add_widget(self.license_subtab_host)

        # Tools subtab
        tools_scroll = ScrollView(do_scroll_x=False, scroll_type=['bars', 'content'], bar_width=dp(6))
        tools_outer = GridLayout(cols=1, spacing=dp(8), size_hint_y=None, padding=[0, 0, 0, dp(8)])
        tools_outer.bind(minimum_height=tools_outer.setter('height'))

        backup_card = SectionCard("License list backup")
        backup_row1 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        gen_backup_btn = make_button("Generate Backup", GREEN)
        copy_backup_btn = make_button("Copy Backup", ORANGE)
        gen_backup_btn.bind(on_release=lambda *_: self.generate_license_list_backup())
        copy_backup_btn.bind(on_release=lambda *_: copy_to_clipboard("License list backup", getattr(self, "license_backup_output", make_input()).text if hasattr(self, "license_backup_output") else ""))
        backup_row1.add_widget(gen_backup_btn)
        backup_row1.add_widget(copy_backup_btn)
        backup_card.add_widget(backup_row1)

        self.license_backup_output = make_input("Generated encrypted license-list backup will appear here", multiline=True, readonly=True)
        self.license_backup_output.height = dp(160)
        backup_card.add_widget(self.license_backup_output)

        backup_row2 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        save_backup_btn = make_button("Save Backup", BLUE)
        import_backup_btn = make_button("Import Backup", GREEN)
        save_backup_btn.bind(on_release=lambda *_: self.save_license_list_backup())
        import_backup_btn.bind(on_release=lambda *_: self.import_license_list_backup())
        backup_row2.add_widget(save_backup_btn)
        backup_row2.add_widget(import_backup_btn)
        backup_card.add_widget(backup_row2)

        self.import_license_backup_input = make_input("Paste encrypted license-list backup here", multiline=True)
        self.import_license_backup_input.height = dp(120)
        backup_card.add_widget(self.import_license_backup_input)

        backup_row3 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        paste_btn = make_button("Paste", BLUE)
        import_file_btn = make_button("Import File", PURPLE)
        paste_btn.bind(on_release=lambda *_: self.paste_license_backup_from_clipboard())
        import_file_btn.bind(on_release=lambda *_: self.open_license_backup_file_picker())
        backup_row3.add_widget(paste_btn)
        backup_row3.add_widget(import_file_btn)
        backup_card.add_widget(backup_row3)
        tools_outer.add_widget(backup_card)
        tools_scroll.add_widget(tools_outer)
        self.license_tools_view = tools_scroll

        search_card = SectionCard("License filters")
        self.search_input = make_input("Search by ID / device / label / payment / notes")
        self.search_input.height = dp(42)
        self.search_input.bind(text=lambda *_: self.refresh_license_list())
        search_card.add_widget(self.search_input)

        filters = GridLayout(cols=4, spacing=dp(6), size_hint_y=None, height=dp(42))
        self.license_status_spinner = Spinner(text="all", values=("all", "active", "revoked"), size_hint_y=None, height=dp(42))
        self.license_tier_spinner = Spinner(text="all", values=("all", "demo", "pro", "pro_plus"), size_hint_y=None, height=dp(42))
        self.license_source_spinner = Spinner(text="all", values=("all", "crypto", "bank", "promo", "partner", "personal", "test"), size_hint_y=None, height=dp(42))
        self.license_sort_spinner = Spinner(text="newest", values=("newest", "oldest", "tier", "status"), size_hint_y=None, height=dp(42))
        self.license_status_spinner.bind(text=lambda *_: self.refresh_license_list())
        self.license_tier_spinner.bind(text=lambda *_: self.refresh_license_list())
        self.license_source_spinner.bind(text=lambda *_: self.refresh_license_list())
        self.license_sort_spinner.bind(text=lambda *_: self.refresh_license_list())
        filters.add_widget(self.license_status_spinner)
        filters.add_widget(self.license_tier_spinner)
        filters.add_widget(self.license_source_spinner)
        filters.add_widget(self.license_sort_spinner)
        search_card.add_widget(filters)

        actions = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(44))
        export_btn = make_button("Export Visible CSV", BLUE)
        delete_filtered_btn = make_button("Delete Visible", RED)
        export_btn.height = dp(44)
        delete_filtered_btn.height = dp(44)
        export_btn.bind(on_release=lambda *_: self.export_visible_licenses_csv())
        delete_filtered_btn.bind(on_release=lambda *_: self.confirm_delete_visible_licenses())
        actions.add_widget(export_btn)
        actions.add_widget(delete_filtered_btn)
        search_card.add_widget(actions)

        hint = make_label("Tip: set Source = test before using Delete Visible.", color=SUBTEXT, height=dp(24))
        search_card.add_widget(hint)

        # List subtab
        list_scroll = ScrollView(do_scroll_x=False, scroll_type=['bars', 'content'], bar_width=dp(6))
        list_outer = GridLayout(cols=1, spacing=dp(8), size_hint_y=None, padding=[0, 0, 0, dp(8)])
        list_outer.bind(minimum_height=list_outer.setter('height'))
        list_outer.add_widget(search_card)
        results_card = SectionCard("License list", "Tap Details to inspect, copy, revoke, or restore.")
        self.license_box = GridLayout(cols=1, spacing=dp(8), size_hint_y=None, padding=[0, 0, 0, dp(8)])
        self.license_box.bind(minimum_height=self.license_box.setter("height"))
        results_card.add_widget(self.license_box)
        list_outer.add_widget(results_card)
        list_scroll.add_widget(list_outer)
        self.license_list_view = list_scroll

        self.switch_license_subtab('list')
        return root


    def build_revocation_view(self):
        scroll = ScrollView(do_scroll_x=False)
        box = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8), 0, dp(8)])
        box.bind(minimum_height=box.setter("height"))

        card = SectionCard("Revocation export", "Generate, save, copy, or manually import the signed revoked list for the customer app.")
        export_btn = make_button("Generate Signed Revocation File")
        export_btn.bind(on_release=lambda *_: self.refresh_revocation_box())
        card.add_widget(export_btn)

        self.revocation_output = make_input("", multiline=True, readonly=True)
        self.revocation_output.height = dp(220)
        card.add_widget(self.revocation_output)

        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        save_btn = make_button("Save revoked_licenses.json", BLUE)
        copy_btn = make_button("Copy JSON", ORANGE)
        save_btn.bind(on_release=lambda *_: self.save_revocation_bundle())
        copy_btn.bind(on_release=lambda *_: copy_to_clipboard("Revocation JSON", self.revocation_output.text))
        row.add_widget(save_btn)
        row.add_widget(copy_btn)
        card.add_widget(row)

        pub_btn = make_button("Copy Public Key PEM", PURPLE)
        pub_btn.bind(on_release=lambda *_: self.copy_public_key())
        card.add_widget(pub_btn)

        card.add_widget(make_label("Paste Revocation JSON To Import"))
        self.import_revocation_input = make_input("Paste signed revocation JSON here", multiline=True)
        self.import_revocation_input.height = dp(180)
        card.add_widget(self.import_revocation_input)

        row_import = GridLayout(cols=3, spacing=dp(8), size_hint_y=None, height=dp(46))
        paste_btn = make_button("Paste", BLUE)
        import_btn = make_button("Import JSON", GREEN)
        import_file_btn = make_button("Import File", PURPLE)
        paste_btn.bind(on_release=lambda *_: self.paste_revocation_from_clipboard())
        import_btn.bind(on_release=lambda *_: self.import_revocation_bundle())
        import_file_btn.bind(on_release=lambda *_: self.open_revocation_file_picker())
        row_import.add_widget(paste_btn)
        row_import.add_widget(import_btn)
        row_import.add_widget(import_file_btn)
        card.add_widget(row_import)
        box.add_widget(card)

        gh = SectionCard("GitHub upload", "Store the revocation JSON online so customer apps can read the fixed raw URL")
        self.github_owner_input = make_input("GitHub owner / username")
        self.github_repo_input = make_input("Repository name")
        self.github_branch_input = make_input("Branch", readonly=False)
        self.github_path_input = make_input("Path inside repo (ex: revoked_licenses.json)")
        self.github_token_input = make_input("GitHub token with contents:write access")
        self.github_raw_url_input = make_input("Raw URL", readonly=True)

        self.github_owner_input.text = self.github_config.get('owner', '')
        self.github_repo_input.text = self.github_config.get('repo', '')
        self.github_branch_input.text = self.github_config.get('branch', 'main') or 'main'
        self.github_path_input.text = self.github_config.get('path', REVOKED_EXPORT_FILE) or REVOKED_EXPORT_FILE
        self.github_token_input.text = self.github_config.get('token', '')

        for title, widget in [
            ("Owner", self.github_owner_input),
            ("Repo", self.github_repo_input),
            ("Branch", self.github_branch_input),
            ("Path", self.github_path_input),
            ("Token", self.github_token_input),
            ("Raw URL", self.github_raw_url_input),
        ]:
            gh.add_widget(make_label(title))
            gh.add_widget(widget)

        for widget in (self.github_owner_input, self.github_repo_input, self.github_branch_input, self.github_path_input):
            widget.bind(text=self.update_github_raw_url)
        self.update_github_raw_url()

        row2 = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        save_cfg_btn = make_button("Save Upload Settings", BLUE)
        upload_btn = make_button("Upload Revocation JSON", GREEN)
        save_cfg_btn.bind(on_release=lambda *_: self.save_github_settings())
        upload_btn.bind(on_release=lambda *_: self.upload_revocation_to_github())
        row2.add_widget(save_cfg_btn)
        row2.add_widget(upload_btn)
        gh.add_widget(row2)
        box.add_widget(gh)

        scroll.add_widget(box)
        return scroll

    def update_authority_status(self):
        if hasattr(self, "auth_status_label"):
            if self.public_key and self.private_key:
                self.auth_status_label.text = f"Authority loaded. Public key fingerprint: {hashlib.sha256(self.public_key.save_pkcs1('PEM')).hexdigest()[:16].upper()}"
                self.auth_status_label.color = get_color_from_hex(GREEN)
            else:
                self.auth_status_label.text = "No authority loaded. Import your backup or initialize authority."
                self.auth_status_label.color = get_color_from_hex(RED)

    def require_authority(self):
        if self.public_key and self.private_key:
            return True
        info_popup("Authority required", "No signing authority is loaded. Import your authority backup or initialize authority first.")
        return False

    def initialize_authority(self):
        if self.public_key and self.private_key:
            info_popup("Authority exists", "This device already has an authority loaded.")
            return
        try:
            self.public_key, self.private_key = initialize_authority_keypair()
            self.update_authority_status()
            self.refresh_dashboard()
            info_popup("Authority initialized", "A new signing authority was created on this device. Back it up immediately.")
        except Exception as e:
            info_popup("Initialize failed", str(e))


    def copy_public_key(self):
        if not self.require_authority():
            return
        copy_to_clipboard("Public key PEM", self.public_key.save_pkcs1("PEM").decode("utf-8"))

    def _refresh_everything(self):
        self.refresh_dashboard()
        self.refresh_license_list()
        self.refresh_revocation_box()

    def _write_authority_payload(self, payload):
        private_pem = str(payload.get("private_key_pem", "")).strip()
        public_pem = str(payload.get("public_key_pem", "")).strip()
        if not private_pem or not public_pem:
            raise ValueError("Backup does not contain a valid authority keypair.")
        with open(file_path(PRIVATE_KEY_FILE), "wb") as f:
            f.write(private_pem.encode("utf-8"))
        with open(file_path(PUBLIC_KEY_FILE), "wb") as f:
            f.write(public_pem.encode("utf-8"))
        self.public_key, self.private_key = load_existing_keypair()
        self.update_authority_status()

    def _write_license_payload(self, payload):
        records = payload.get("licenses", [])
        if not isinstance(records, list):
            raise ValueError("Backup does not contain a valid license list.")
        save_json(file_path(LICENSE_DB_FILE), records)
        self.store = LicenseStore()

    def _apply_revocation_bundle_to_store(self, bundle):
        if not isinstance(bundle, dict):
            raise ValueError("Revocation JSON is invalid.")
        payload = bundle.get("payload") if isinstance(bundle.get("payload"), dict) else bundle
        revoked_ids = payload.get("revoked_ids", []) if isinstance(payload, dict) else []
        revoked_ids = {str(x).strip() for x in revoked_ids if str(x).strip()}
        changed = False
        if revoked_ids:
            for rec in self.store.records:
                lid = str(rec.get("license_id", "")).strip()
                if lid in revoked_ids and rec.get("status") != "revoked":
                    rec["status"] = "revoked"
                    rec["revoked_at"] = utc_now_iso()
                    changed = True
            if changed:
                self.store.save()
        save_json(file_path(REVOKED_EXPORT_FILE), bundle)
        return len(revoked_ids), changed

    def _finish_authority_import(self, bundle):
        payload = bundle.get("payload", {}) if isinstance(bundle, dict) else {}
        self._write_authority_payload(payload)
        self._refresh_everything()

    def _finish_license_list_import(self, bundle):
        payload = bundle.get("payload", {}) if isinstance(bundle, dict) else {}
        self._write_license_payload(payload)
        self._refresh_everything()

    def _finish_full_backup_import(self, bundle):
        payload = bundle.get("payload", {}) if isinstance(bundle, dict) else {}
        self._write_authority_payload(payload)
        self._write_license_payload(payload)
        revoked_bundle = payload.get("revoked_bundle", {})
        if revoked_bundle:
            self._apply_revocation_bundle_to_store(revoked_bundle)
        self._refresh_everything()

    def _paste_into_widget(self, widget, empty_message="There is no backup content in the clipboard."):
        try:
            pasted = Clipboard.paste() or ""
            if not pasted.strip():
                info_popup("Clipboard empty", empty_message)
                return
            widget.text = pasted
        except Exception as e:
            info_popup("Paste failed", str(e))

    def _open_backup_file_picker(self, title_text, folder, backup_files, on_select):
        if not backup_files:
            info_popup("No backup file found", f"No backup file was found in:\n{folder}")
            return

        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(12))
        title = Label(
            text=f"Select backup file from:\n{folder}",
            color=get_color_from_hex(TEXT),
            halign="left",
            valign="middle",
            text_size=(dp(300), None),
            size_hint_y=None,
        )
        title.bind(texture_size=lambda inst, val: setattr(inst, "height", max(dp(48), val[1] + dp(8))))
        content.add_widget(title)

        scroll = ScrollView(do_scroll_x=False, size_hint=(1, 1))
        file_box = GridLayout(cols=1, spacing=dp(8), size_hint_y=None)
        file_box.bind(minimum_height=file_box.setter("height"))

        popup = Popup(
            title=title_text,
            content=content,
            size_hint=(0.92, 0.8),
            separator_color=get_color_from_hex(GREEN),
            background_color=get_color_from_hex(CARD),
        )

        for path in backup_files:
            name = os.path.basename(path)
            try:
                stamp = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
            except Exception:
                stamp = "Unknown time"
            btn = RoundedButton(
                text=f"{name}\n{stamp}",
                size_hint_y=None,
                height=dp(68),
                halign="left",
                valign="middle",
                text_size=(dp(260), None),
                bg_hex="#182432",
                text_color=get_color_from_hex(TEXT),
            )
            btn.bind(on_release=lambda *_ , selected_path=path, pop=popup: on_select(selected_path, pop))
            file_box.add_widget(btn)

        scroll.add_widget(file_box)
        content.add_widget(scroll)

        close_btn = make_button("Close", RED)
        close_btn.bind(on_release=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()

    def generate_authority_backup(self):
        if not self.require_authority():
            return
        try:
            blob = build_authority_backup_blob(self.backup_password_input.text.strip())
            self.backup_output.text = blob
            info_popup("Backup generated", "Encrypted authority-only backup generated successfully.")
        except Exception as e:
            info_popup("Backup failed", str(e))

    def save_authority_backup(self):
        text = self.backup_output.text.strip() if hasattr(self, "backup_output") else ""
        if not text:
            info_popup("Nothing to save", "Generate an authority backup first.")
            return
        path = authority_backup_export_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        info_popup("Saved", f"Authority backup saved to:\n{path}")

    def import_authority_backup(self):
        try:
            blob_text = self.import_backup_input.text.strip()
            bundle = parse_secure_backup_blob(blob_text, self.backup_password_input.text.strip())
            self._finish_authority_import(bundle)
            info_popup("Import successful", "Authority backup imported successfully. Local license list was not changed.")
        except Exception as e:
            info_popup("Import failed", str(e))

    def paste_backup_from_clipboard(self):
        self._paste_into_widget(self.import_backup_input)

    def open_auth_file_picker(self):
        self._open_backup_file_picker("Import Auth File", authority_backup_dir(), list_authority_backup_files(), self.import_authority_from_file)

    def import_authority_from_file(self, backup_path, popup=None):
        try:
            with open(backup_path, "r", encoding="utf-8") as f:
                blob_text = f.read().strip()
            if hasattr(self, "import_backup_input"):
                self.import_backup_input.text = blob_text
            bundle = parse_secure_backup_blob(blob_text, self.backup_password_input.text.strip())
            self._finish_authority_import(bundle)
            if popup is not None:
                popup.dismiss()
            info_popup("Import successful", f"Authority file imported successfully from:\n{backup_path}\n\nLocal license list was not changed.")
        except Exception as e:
            info_popup("Import failed", str(e))

    def generate_license_list_backup(self):
        try:
            blob = build_license_list_backup_blob(self.backup_password_input.text.strip(), self.store.records)
            self.license_backup_output.text = blob
            info_popup("Backup generated", "Encrypted license-list backup generated successfully.")
        except Exception as e:
            info_popup("Backup failed", str(e))

    def save_license_list_backup(self):
        text = self.license_backup_output.text.strip() if hasattr(self, "license_backup_output") else ""
        if not text:
            info_popup("Nothing to save", "Generate a license-list backup first.")
            return
        path = license_list_backup_export_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        info_popup("Saved", f"License-list backup saved to:\n{path}")

    def import_license_list_backup(self):
        try:
            blob_text = self.import_license_backup_input.text.strip()
            bundle = parse_secure_backup_blob(blob_text, self.backup_password_input.text.strip())
            self._finish_license_list_import(bundle)
            info_popup("Import successful", "License-list backup imported successfully. Authority keys were not changed.")
        except Exception as e:
            info_popup("Import failed", str(e))

    def paste_license_backup_from_clipboard(self):
        self._paste_into_widget(self.import_license_backup_input)

    def open_license_backup_file_picker(self):
        self._open_backup_file_picker("Import License Backup", license_list_backup_dir(), list_license_list_backup_files(), self.import_license_backup_from_file)

    def import_license_backup_from_file(self, backup_path, popup=None):
        try:
            with open(backup_path, "r", encoding="utf-8") as f:
                blob_text = f.read().strip()
            if hasattr(self, "import_license_backup_input"):
                self.import_license_backup_input.text = blob_text
            bundle = parse_secure_backup_blob(blob_text, self.backup_password_input.text.strip())
            self._finish_license_list_import(bundle)
            if popup is not None:
                popup.dismiss()
            info_popup("Import successful", f"License-list backup imported successfully from:\n{backup_path}")
        except Exception as e:
            info_popup("Import failed", str(e))

    def generate_full_backup(self):
        if not self.require_authority():
            return
        try:
            blob = build_full_backup_blob(self.backup_password_input.text.strip(), self.store.records)
            self.full_backup_output.text = blob
            info_popup("Backup generated", "Encrypted full backup generated successfully.")
        except Exception as e:
            info_popup("Backup failed", str(e))

    def save_full_backup(self):
        text = self.full_backup_output.text.strip() if hasattr(self, "full_backup_output") else ""
        if not text:
            info_popup("Nothing to save", "Generate a full backup first.")
            return
        path = full_backup_export_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        info_popup("Saved", f"Full backup saved to:\n{path}")

    def import_full_backup(self):
        try:
            blob_text = self.import_full_backup_input.text.strip()
            bundle = parse_secure_backup_blob(blob_text, self.backup_password_input.text.strip())
            self._finish_full_backup_import(bundle)
            info_popup("Import successful", "Full backup imported successfully.")
        except Exception as e:
            info_popup("Import failed", str(e))

    def paste_full_backup_from_clipboard(self):
        self._paste_into_widget(self.import_full_backup_input)

    def open_full_backup_file_picker(self):
        self._open_backup_file_picker("Import Full Backup", full_backup_dir(), list_full_backup_files(), self.import_full_backup_from_file)

    def import_full_backup_from_file(self, backup_path, popup=None):
        try:
            with open(backup_path, "r", encoding="utf-8") as f:
                blob_text = f.read().strip()
            if hasattr(self, "import_full_backup_input"):
                self.import_full_backup_input.text = blob_text
            bundle = parse_secure_backup_blob(blob_text, self.backup_password_input.text.strip())
            self._finish_full_backup_import(bundle)
            if popup is not None:
                popup.dismiss()
            info_popup("Import successful", f"Full backup imported successfully from:\n{backup_path}")
        except Exception as e:
            info_popup("Import failed", str(e))

    def paste_revocation_from_clipboard(self):
        self._paste_into_widget(self.import_revocation_input, "There is no revocation JSON in the clipboard.")

    def open_revocation_file_picker(self):
        self._open_backup_file_picker("Import Revocation JSON", revocation_backup_dir(), list_revocation_backup_files(), self.import_revocation_from_file)

    def import_revocation_from_file(self, backup_path, popup=None):
        try:
            with open(backup_path, "r", encoding="utf-8") as f:
                blob_text = f.read().strip()
            if hasattr(self, "import_revocation_input"):
                self.import_revocation_input.text = blob_text
            self._finish_revocation_import(blob_text)
            if popup is not None:
                popup.dismiss()
        except Exception as e:
            info_popup("Import failed", str(e))

    def _finish_revocation_import(self, blob_text):
        bundle = json.loads(blob_text)
        revoked_count, matched_updates = self._apply_revocation_bundle_to_store(bundle)
        self._refresh_everything()
        info_popup("Revocation import complete", f"Imported revocation JSON with {revoked_count} revoked ID(s). Matching local licenses updated: {'yes' if matched_updates else 'no'}.")

    def import_revocation_bundle(self):
        try:
            blob_text = self.import_revocation_input.text.strip()
            self._finish_revocation_import(blob_text)
        except Exception as e:
            info_popup("Import failed", str(e))

    def get_compact_device_label(self, device_code):
            device_code = str(device_code or '').strip()
            if not device_code:
                return 'No device'
            return device_code[-8:] if len(device_code) > 8 else device_code

    def get_compact_issued_label(self, issued_at):
            txt = str(issued_at or '').strip()
            if not txt:
                return 'No issue date'
            return txt.replace('T', ' ')[:16].replace('Z', '')

    def show_license_details(self, rec):
            details = [
                f"License ID: {rec.get('license_id', '')}",
                f"Tier: {str(rec.get('tier', '')).upper()}",
                f"Status: {str(rec.get('status', 'active')).upper()}",
                f"Source: {rec.get('source', '')}",
                f"Applies To: {product_scope_label(rec.get('product_scope', PRODUCT_SCOPE_SHARED))}",
                f"Device Code: {rec.get('device_code', '') or 'Not bound'}",
                f"Issued: {rec.get('issued_at', '')}",
            ]
            if rec.get('expiry'):
                details.append(f"Expiry: {rec.get('expiry')}")
            if rec.get('label'):
                details.append(f"Label: {rec.get('label')}")
            if rec.get('customer_note'):
                details.append(f"Note: {rec.get('customer_note')}")

            content = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(10))
            body = Label(
                text='\n'.join(details),
                color=get_color_from_hex(TEXT),
                halign='left',
                valign='top',
                text_size=(dp(300), None),
                size_hint_y=None,
            )
            body.bind(texture_size=lambda inst, val: setattr(inst, 'height', max(dp(120), val[1])))
            content.add_widget(body)

            row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
            copy_id_btn = make_button('Copy ID', BLUE)
            copy_code_btn = make_button('Copy Code', ORANGE)
            delete_btn = make_button('Delete', RED)
            row.add_widget(copy_id_btn)
            row.add_widget(copy_code_btn)
            row.add_widget(delete_btn)
            content.add_widget(row)

            close_btn = make_button('Close', PURPLE)
            content.add_widget(close_btn)

            popup = Popup(
                title='License Details',
                content=content,
                size_hint=(0.92, 0.68),
                separator_color=get_color_from_hex(GREEN),
                background_color=get_color_from_hex(CARD),
            )
            copy_id_btn.bind(on_release=lambda *_: copy_to_clipboard('License ID', rec.get('license_id', '')))
            copy_code_btn.bind(on_release=lambda *_: copy_to_clipboard('Activation code', rec.get('activation_code', '')))
            delete_btn.bind(on_release=lambda *_: self.confirm_delete_license(rec.get('license_id', ''), popup))
            close_btn.bind(on_release=popup.dismiss)
            popup.open()

    def collect_github_settings(self):
            return {
                'owner': self.github_owner_input.text.strip(),
                'repo': self.github_repo_input.text.strip(),
                'branch': self.github_branch_input.text.strip() or 'main',
                'path': self.github_path_input.text.strip().lstrip('/'),
                'token': self.github_token_input.text.strip(),
            }

    def update_github_raw_url(self, *_):
            if not hasattr(self, 'github_raw_url_input'):
                return
            cfg = self.collect_github_settings() if hasattr(self, 'github_owner_input') else dict(self.github_config)
            self.github_raw_url_input.text = build_github_raw_url(cfg.get('owner', ''), cfg.get('repo', ''), cfg.get('branch', 'main'), cfg.get('path', REVOKED_EXPORT_FILE))

    def save_github_settings(self):
            cfg = self.collect_github_settings()
            save_github_upload_config(cfg)
            self.github_config = load_github_upload_config()
            self.update_github_raw_url()
            info_popup('Saved', 'GitHub upload settings saved on this admin device.')

    def upload_revocation_to_github(self):
            if not self.require_authority():
                return
            cfg = self.collect_github_settings()
            missing = [name for name, value in [('owner', cfg['owner']), ('repo', cfg['repo']), ('branch', cfg['branch']), ('path', cfg['path']), ('token', cfg['token'])] if not value]
            if missing:
                info_popup('Missing fields', f"Fill these GitHub fields first: {', '.join(missing)}")
                return

            bundle = build_revocation_bundle(self.store.records, self.private_key)
            payload_text = json.dumps(bundle, indent=2)
            api_url = f"https://api.github.com/repos/{cfg['owner']}/{cfg['repo']}/contents/{cfg['path']}"
            headers = {
                'Accept': 'application/vnd.github+json',
                'Authorization': f"Bearer {cfg['token']}",
                'X-GitHub-Api-Version': '2022-11-28',
            }
            body = {
                'message': f"Update revoked licenses at {utc_now_iso()}",
                'content': base64.b64encode(payload_text.encode('utf-8')).decode('ascii'),
                'branch': cfg['branch'],
            }
            try:
                existing = requests.get(api_url, headers=headers, timeout=20)
                if existing.status_code == 200:
                    existing_data = existing.json()
                    if existing_data.get('sha'):
                        body['sha'] = existing_data['sha']
                elif existing.status_code not in (404,):
                    raise RuntimeError(f"GitHub lookup failed: {existing.status_code} {existing.text[:180]}")

                resp = requests.put(api_url, headers=headers, json=body, timeout=25)
                if resp.status_code not in (200, 201):
                    raise RuntimeError(f"GitHub upload failed: {resp.status_code} {resp.text[:220]}")

                save_github_upload_config(cfg)
                self.github_config = load_github_upload_config()
                self.refresh_revocation_box()
                self.update_github_raw_url()
                info_popup('Uploaded', f"Revocation file uploaded successfully to:\n{self.github_raw_url_input.text}")
            except Exception as e:
                info_popup('Upload failed', str(e))

    def build_and_store_license(self, tier, source, device_code, label='', note='', expiry='', product_scope=PRODUCT_SCOPE_SHARED):
            if tier not in ('demo', 'pro', 'pro_plus'):
                raise ValueError('Choose demo, pro, or pro_plus.')
            if source not in ('crypto', 'bank', 'promo', 'partner', 'personal', 'test'):
                raise ValueError('Choose one of the payment/source types.')
            if not device_code:
                raise ValueError("Enter the customer's Device Code from the app.")
            product_scope = normalize_product_scope(product_scope)

            license_id = 'LIC-' + secrets.token_hex(4).upper()
            payload = {
                'app': 'casino_tools_pro',
                'schema': 1,
                'license_id': license_id,
                'tier': tier,
                'source': source,
                'device_code': device_code,
                'label': label,
                'issued_at': utc_now_iso(),
            }
            if note:
                payload['note'] = note
            if expiry:
                payload['expires_at'] = expiry

            signature = sign_payload(self.private_key, payload)
            activation_code = encode_activation_code(payload, signature)
            record = {
                'license_id': license_id,
                'tier': tier,
                'source': source,
                'device_code': device_code,
                'label': label,
                'customer_note': note,
                'expiry': expiry,
                'expires_at': expiry,
                'issued_at': payload['issued_at'],
                'status': 'active',
                'activation_code': activation_code,
                'signature_valid': verify_signature(self.public_key, payload, signature),
                'product_scope': product_scope,
            }
            self.store.add(record)
            self._last_license_id = license_id
            self.generated_code_input.text = activation_code
            self.refresh_dashboard()
            self.refresh_license_list()
            self.refresh_revocation_box()
            return record

    def generate_test_license(self):
            if not self.require_authority():
                return
            try:
                device_code = self.device_input.text.strip().upper()
                if not device_code:
                    raise ValueError("Enter the customer's Device Code before generating a test license.")
                expiry = self.expiry_input.text.strip() or (datetime.utcnow() + timedelta(days=7)).strftime('%Y-%m-%d')
                label = self.label_input.text.strip() or 'Internal Test'
                note = self.note_input.text.strip() or 'Admin-generated test key'
                self.build_and_store_license('pro_plus', 'test', device_code, label=label, note=note, expiry=expiry, product_scope=product_scope_from_ui(self.generate_scope_spinner.text))
                info_popup('Test license generated', f"7-day style test Pro+ license created successfully for {product_scope_label(product_scope_from_ui(self.generate_scope_spinner.text))}. Change the expiry field first if you want a different end date.")
            except Exception as e:
                info_popup('Test license failed', str(e))

    def refresh_dashboard(self):
        if not hasattr(self, "dashboard_box"):
            return
        self.dashboard_box.clear_widgets()
        records = self.store.records
        total = len(records)
        active = len([r for r in records if r.get("status") == "active"])
        revoked = len([r for r in records if r.get("status") == "revoked"])
        demo = len([r for r in records if r.get("tier") == "demo"])
        pro = len([r for r in records if r.get("tier") == "pro"])
        pro_plus = len([r for r in records if r.get("tier") == "pro_plus"])

        authority_card = SectionCard("Authority status")
        if self.public_key and self.private_key:
            authority_card.add_widget(make_label("Authority loaded", GREEN))
            authority_card.add_widget(make_label(f"Data folder: {app_data_dir()}", height=dp(38)))
        else:
            authority_card.add_widget(make_label("No authority loaded. Import your backup or initialize authority.", RED, height=dp(38)))
        self.dashboard_box.add_widget(authority_card)

        visible_records = [r for r in records if self.record_matches_active_scope(r)]
        stats = SectionCard("License totals")
        stats.add_widget(make_label(f"Current view: {product_scope_label(self.active_product_scope)}", PRODUCT_SCOPE_ACCENTS.get(self.active_product_scope, TEXT)))
        for t in [
            f"Total licenses: {total}",
            f"Visible in this view: {len(visible_records)}",
            f"Active: {active}",
            f"Revoked: {revoked}",
            f"Demo: {demo}",
            f"Pro: {pro}",
            f"Pro+: {pro_plus}",
        ]:
            stats.add_widget(make_label(t, GREEN if "Active" in t else (RED if "Revoked" in t else TEXT)))
        self.dashboard_box.add_widget(stats)

        latest = SectionCard("Latest issued")
        if visible_records:
            for rec in visible_records[:8]:
                latest.add_widget(make_label(
                    f"{rec['license_id']}  |  {rec['tier']}  |  {rec.get('source','')}  |  {product_scope_label(rec.get('product_scope', PRODUCT_SCOPE_SHARED))}",
                    height=dp(22),
                ))
        else:
            latest.add_widget(make_label("No licenses yet."))
        self.dashboard_box.add_widget(latest)

    def get_filtered_license_records(self):
        query = (self.search_input.text or "").strip().lower() if hasattr(self, "search_input") else ""
        status_filter = getattr(getattr(self, 'license_status_spinner', None), 'text', 'all').strip().lower()
        tier_filter = getattr(getattr(self, 'license_tier_spinner', None), 'text', 'all').strip().lower()
        source_filter = getattr(getattr(self, 'license_source_spinner', None), 'text', 'all').strip().lower()
        sort_mode = getattr(getattr(self, 'license_sort_spinner', None), 'text', 'newest').strip().lower()

        visible = []
        for rec in self.store.records:
            hay = " ".join([
                rec.get("license_id", ""),
                rec.get("device_code", ""),
                rec.get("tier", ""),
                rec.get("source", ""),
                rec.get("label", ""),
                rec.get("customer_note", ""),
                rec.get("status", ""),
            ]).lower()
            if query and query not in hay:
                continue
            if status_filter != 'all' and str(rec.get('status', 'active')).lower() != status_filter:
                continue
            if tier_filter != 'all' and str(rec.get('tier', '')).lower() != tier_filter:
                continue
            if source_filter != 'all' and str(rec.get('source', '')).lower() != source_filter:
                continue
            if not self.record_matches_active_scope(rec):
                continue
            visible.append(rec)

        if sort_mode == 'oldest':
            visible.sort(key=lambda r: str(r.get('issued_at', '')))
        elif sort_mode == 'tier':
            visible.sort(key=lambda r: (str(r.get('tier', '')), str(r.get('issued_at', ''))), reverse=False)
            visible.reverse()
        elif sort_mode == 'status':
            visible.sort(key=lambda r: (str(r.get('status', 'active')), str(r.get('issued_at', ''))), reverse=False)
            visible.reverse()
        else:
            visible.sort(key=lambda r: str(r.get('issued_at', '')), reverse=True)
        return visible

    def export_visible_licenses_csv(self):
        records = self.get_filtered_license_records()
        if not records:
            info_popup("Nothing to export", "There are no visible licenses to export with the current filters.")
            return
        export_path = license_export_path()
        fieldnames = [
            "license_id",
            "tier",
            "status",
            "source",
            "product_scope",
            "device_code",
            "label",
            "customer_note",
            "issued_at",
            "expiry",
            "expires_at",
            "revoked_at",
            "signature_valid",
        ]
        with open(export_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in records:
                row = {name: rec.get(name, "") for name in fieldnames}
                writer.writerow(row)
        info_popup("Exported", f"Visible licenses exported successfully to:\n{export_path}")

    def confirm_delete_license(self, license_id, parent_popup=None):
        rec = self.store.find(license_id)
        if not rec:
            info_popup("Not found", "That license could not be found anymore.")
            return

        content = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))
        message = Label(
            text=f"Delete this license permanently?\n\n{license_id}\n{str(rec.get('tier', '')).upper()} • {str(rec.get('status', 'active')).upper()}\n\nUse delete mainly for test keys and clutter. Revoked licenses removed from the database will also disappear from future revocation exports.",
            color=get_color_from_hex(TEXT),
            halign="left",
            valign="top",
            text_size=(dp(300), None),
            size_hint_y=None,
        )
        message.bind(texture_size=lambda inst, val: setattr(inst, "height", max(dp(140), val[1])))
        content.add_widget(message)

        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        cancel_btn = make_button("Cancel", BLUE)
        delete_btn = make_button("Delete", RED)
        row.add_widget(cancel_btn)
        row.add_widget(delete_btn)
        content.add_widget(row)

        popup = Popup(
            title="Delete License",
            content=content,
            size_hint=(0.92, 0.62),
            separator_color=get_color_from_hex(RED),
            background_color=get_color_from_hex(CARD),
        )

        cancel_btn.bind(on_release=popup.dismiss)

        def do_delete(*_):
            removed = self.store.delete(license_id)
            popup.dismiss()
            if parent_popup is not None:
                parent_popup.dismiss()
            if removed:
                self.refresh_dashboard()
                self.refresh_license_list()
                self.refresh_revocation_box()
                info_popup("Deleted", f"{license_id} was deleted from the license database.")
            else:
                info_popup("Not found", "That license could not be found anymore.")

        delete_btn.bind(on_release=do_delete)
        popup.open()

    def confirm_delete_visible_licenses(self):
        records = self.get_filtered_license_records()
        if not records:
            info_popup("Nothing to delete", "There are no visible licenses to delete with the current filters.")
            return

        count = len(records)
        ids = [rec.get("license_id", "") for rec in records if rec.get("license_id")]

        content = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))
        message = Label(
            text=f"Delete all {count} currently visible licenses?\n\nThis is best used after narrowing the list to test keys with search and filters. Any revoked licenses deleted here will also disappear from future revocation exports.",
            color=get_color_from_hex(TEXT),
            halign="left",
            valign="top",
            text_size=(dp(300), None),
            size_hint_y=None,
        )
        message.bind(texture_size=lambda inst, val: setattr(inst, "height", max(dp(130), val[1])))
        content.add_widget(message)

        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        cancel_btn = make_button("Cancel", BLUE)
        delete_btn = make_button("Delete Visible", RED)
        row.add_widget(cancel_btn)
        row.add_widget(delete_btn)
        content.add_widget(row)

        popup = Popup(
            title="Delete Visible Licenses",
            content=content,
            size_hint=(0.92, 0.58),
            separator_color=get_color_from_hex(RED),
            background_color=get_color_from_hex(CARD),
        )

        cancel_btn.bind(on_release=popup.dismiss)

        def do_delete(*_):
            removed = self.store.delete_many(ids)
            popup.dismiss()
            self.refresh_dashboard()
            self.refresh_license_list()
            self.refresh_revocation_box()
            info_popup("Deleted", f"Deleted {removed} visible license(s).")

        delete_btn.bind(on_release=do_delete)
        popup.open()

    def refresh_license_list(self):
        if not hasattr(self, "license_box"):
            return

        self.license_box.clear_widgets()
        visible = self.get_filtered_license_records()

        if not visible:
            self.license_box.add_widget(make_label("No matching licenses found."))
            return

        for rec in visible:
            status = str(rec.get('status', 'active')).upper()
            source = str(rec.get('source', '')).upper()
            device_short = self.get_compact_device_label(rec.get('device_code', ''))
            issued_short = self.get_compact_issued_label(rec.get('issued_at', ''))
            subtitle = f"{source}  •  {status}  •  {product_scope_label(rec.get('product_scope', PRODUCT_SCOPE_SHARED))}"
            if rec.get('label'):
                subtitle += f"  •  {rec.get('label')}"

            card = SectionCard(f"{rec['license_id']}  •  {rec['tier'].upper()}", subtitle)
            card.add_widget(make_label(f"Device suffix: {device_short}  •  Issued: {issued_short}", height=dp(22)))
            if rec.get('expiry'):
                card.add_widget(make_label(f"Expiry: {rec.get('expiry')}", height=dp(22)))

            row = BoxLayout(size_hint_y=None, height=dp(42), spacing=dp(8))
            details_btn = make_button("Details", PURPLE)
            id_btn = make_button("Copy ID", BLUE)
            revoke_btn = make_button("Revoke" if rec.get("status") != "revoked" else "Restore", RED if rec.get("status") != "revoked" else PURPLE)

            details_btn.bind(on_release=lambda *_ , record=rec: self.show_license_details(record))
            id_btn.bind(on_release=lambda *_ , lid=rec["license_id"]: copy_to_clipboard("License ID", lid))
            revoke_btn.bind(on_release=lambda *_ , lid=rec["license_id"], status=rec.get("status"): self.toggle_revoke(lid, status))

            row.add_widget(details_btn)
            row.add_widget(id_btn)
            row.add_widget(revoke_btn)
            card.add_widget(row)
            self.license_box.add_widget(card)

    def refresh_revocation_box(self):
        if not hasattr(self, "revocation_output"):
            return
        if not self.private_key:
            self.revocation_output.text = ""
            return
        bundle = build_revocation_bundle(self.store.records, self.private_key)
        self.revocation_output.text = json.dumps(bundle, indent=2)

    def clear_generate_form(self):
        self.device_input.text = ""
        self.tier_spinner.text = "pro"
        self.source_spinner.text = "crypto"
        self.label_input.text = ""
        self.note_input.text = ""
        self.expiry_input.text = ""
        self.generated_code_input.text = ""
        if hasattr(self, 'generate_scope_spinner'):
            self.generate_scope_spinner.text = product_scope_label(self.active_product_scope)
        self._last_license_id = ""

    def generate_license(self):
        if not self.require_authority():
            return
        try:
            tier = self.tier_spinner.text.strip()
            source = self.source_spinner.text.strip()
            device_code = self.device_input.text.strip().upper()
            label = self.label_input.text.strip()
            note = self.note_input.text.strip()
            expiry = self.expiry_input.text.strip()
            scope = product_scope_from_ui(self.generate_scope_spinner.text.strip())
            self.build_and_store_license(tier, source, device_code, label=label, note=note, expiry=expiry, product_scope=scope)
            info_popup("License generated", f"{tier.upper()} license created successfully for {product_scope_label(scope)}.")
        except Exception as e:
            info_popup("License failed", str(e))

    def toggle_revoke(self, license_id, status):
        target = "revoked" if status != "revoked" else "active"
        self.store.update(
            license_id,
            lambda rec: rec.update({"status": target, "revoked_at": utc_now_iso() if target == "revoked" else ""}),
        )
        self.refresh_dashboard()
        self.refresh_license_list()
        self.refresh_revocation_box()
        info_popup("License updated", f"{license_id} is now {target.upper()}.")

    def save_revocation_bundle(self):
        if not self.require_authority():
            return
        bundle = build_revocation_bundle(self.store.records, self.private_key)
        path = revocation_export_path()
        save_json(path, bundle)
        save_json(file_path(REVOKED_EXPORT_FILE), bundle)
        self.refresh_revocation_box()
        info_popup("Saved", f"Revocation file saved to:\n{path}")


class LicenseManagerApp(App):
    def build(self):
        self.title = "SHV Ecosystem License Manager"
        sm = ScreenManager(transition=FadeTransition())
        sm.add_widget(LicenseManagerScreen(name="main"))
        return sm


if __name__ == "__main__":
    LicenseManagerApp().run()
