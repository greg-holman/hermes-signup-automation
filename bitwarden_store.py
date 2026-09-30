from __future__ import annotations

import hashlib
import json
import os
import tempfile
import fcntl
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID


SETTINGS = Path(__file__).with_name("settings.json")


def _settings():
    local = SETTINGS.with_name("settings.local.json")
    config = json.loads((local if local.exists() else SETTINGS).read_text())
    if not config.get("bitwarden_project_id") or not config.get("bitwarden_organization_id"):
        raise RuntimeError("Configure Bitwarden project and organization IDs in settings.local.json")
    return config


def _client():
    from agent.secret_scope import get_secret
    from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict

    token = get_secret("BWS_ACCESS_TOKEN", "")
    if not token:
        raise RuntimeError("Bitwarden machine token is unavailable")
    cfg = _settings()
    client = BitwardenClient(client_settings_from_dict({
        "apiUrl": cfg["bitwarden_api_url"], "identityUrl": cfg["bitwarden_identity_url"],
        "deviceType": DeviceType.SDK, "userAgent": "HermesSignup/0.1",
    }))
    response = client.auth().login_access_token(token)
    if not response.success:
        raise RuntimeError("Bitwarden machine authentication failed")
    return client, cfg


def _key(origin: str, email: str) -> str:
    digest = hashlib.sha256((origin + "\0" + email.lower()).encode()).hexdigest()[:24]
    return "HERMES_WEBSITE_" + digest.upper()


def _note(origin: str, email: str) -> str:
    return f"Hermes website login for {origin} ({email})"


def _record(origin: str, email: str, password: str, otp_secret: str = "") -> str:
    return json.dumps({"version": 1, "origin": origin, "email": email,
                       "password": password, "otp_secret": otp_secret}, separators=(",", ":"))


def _mapping_path() -> Path:
    from hermes_constants import get_hermes_home
    return Path(get_hermes_home()) / "signup_bitwarden_ids.json"


def _mapping() -> dict:
    path = _mapping_path()
    return json.loads(path.read_text()) if path.exists() else {}


def _save_mapping(mapping: dict) -> None:
    path = _mapping_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".signup_bitwarden_ids.")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(mapping, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def create(origin: str, email: str, password: str) -> str:
    client, cfg = _client()
    response = client.secrets().create(UUID(cfg["bitwarden_organization_id"]), _key(origin, email),
                                       _record(origin, email, password), _note(origin, email),
                                       [UUID(cfg["bitwarden_project_id"])])
    if not response.success or not response.data:
        raise RuntimeError("Bitwarden rejected the new website credential")
    return str(response.data.id)


@contextmanager
def _mapping_lock():
    path = _mapping_path().with_suffix(".lock")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def link(handle: str, secret_id: str) -> None:
    with _mapping_lock():
        mapping = _mapping()
        mapping[handle] = secret_id
        _save_mapping(mapping)


def unlink(handle: str) -> None:
    with _mapping_lock():
        mapping = _mapping()
        if handle in mapping:
            del mapping[handle]
            _save_mapping(mapping)


def delete(secret_id: str) -> None:
    client, _ = _client()
    response = client.secrets().delete([secret_id])
    if not response.success:
        raise RuntimeError("Bitwarden rejected credential cleanup")


def update_totp(handle: str, origin: str, email: str, password: str, otp_secret: str) -> None:
    secret_id = _mapping().get(handle)
    if not secret_id:
        raise RuntimeError("This login has no linked Bitwarden secret")
    client, cfg = _client()
    response = client.secrets().update(cfg["bitwarden_organization_id"], secret_id,
                                       _key(origin, email), _record(origin, email, password, otp_secret),
                                       _note(origin, email), [UUID(cfg["bitwarden_project_id"])])
    if not response.success:
        raise RuntimeError("Bitwarden rejected the TOTP update")
    if read_totp(handle, origin, email, password) != otp_secret:
        raise RuntimeError("Bitwarden TOTP update could not be verified")

def read_totp(handle: str, origin: str, email: str, password: str) -> str:
    secret_id = _mapping().get(handle)
    if not secret_id:
        raise RuntimeError("This login has no linked Bitwarden secret")
    client, _ = _client()
    response = client.secrets().get(secret_id)
    if not response.success or not response.data:
        raise RuntimeError("Could not read the linked Bitwarden credential")
    record = json.loads(response.data.value)
    if (record.get("origin"), record.get("email"), record.get("password")) != (origin, email, password):
        raise RuntimeError("The linked Bitwarden credential does not match the local login")
    return str(record.get("otp_secret") or "")
