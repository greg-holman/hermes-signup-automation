from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urlparse

from . import bitwarden_store

_CHALLENGE_STARTED = {}

def _safe_challenge_start(now):
    from datetime import timedelta
    return now.replace(microsecond=0) + timedelta(seconds=1)

def _arm_marker(tid, origin, email):
    import time
    from datetime import datetime, timezone
    started = _safe_challenge_start(datetime.now(timezone.utc))
    time.sleep(max(0, (started - datetime.now(timezone.utc)).total_seconds()) + 0.01)
    _CHALLENGE_STARTED[(tid, origin, email.lower())] = started


def _result(**values):
    return json.dumps(values, ensure_ascii=False)


def _evaluate(task_id, expression, *, secret=False):
    from tools.browser_camofox import is_camofox_mode
    if is_camofox_mode():
        from tools.browser_camofox import _ensure_tab, _post, get_camofox_url
        from tools.browser_tool import _parse_eval_value
        base_url = get_camofox_url()
        if secret and urlparse(base_url).hostname not in {'localhost', '127.0.0.1', '::1'}:
            return {"success": False, "error_type": "local_browser_required", "error": "Secret fills require a local supervised browser"}
        try:
            tab = _ensure_tab(task_id)
            path = f"/tabs/{tab['tab_id']}/evaluate"
            body = {"expression": expression, "userId": tab["user_id"]}
            if secret:
                import requests
                from tools.browser_camofox import _auth_headers, _get_command_timeout
                reply = requests.post(base_url.rstrip('/') + path, json=body,
                                      headers=_auth_headers(), timeout=_get_command_timeout(), allow_redirects=False)
                if reply.status_code != 200:
                    return {"success": False, "error": "Local browser refused the secret fill"}
                response = reply.json()
            else:
                response = _post(path, body)
            return {"success": True, "result": _parse_eval_value(response.get("result"))}
        except Exception:
            return {"success": False, "error": "Camofox page evaluation failed"}
    from tools.browser_vault_tool import _eval_js, _eval_js_secret
    return _eval_js_secret(task_id, expression) if secret else _eval_js(task_id, expression)


def _page(task_id):
    from tools.browser_vault_tool import _current_page_origin
    from agent.vault_store import normalize_origin
    from tools.browser_camofox import is_camofox_mode
    tid = task_id or "default"
    if is_camofox_mode():
        result = _evaluate(tid, "window.location.href")
        try:
            return tid, normalize_origin(str(result.get("result") or "")) if result.get("success") else None
        except Exception:
            return tid, None
    return tid, _current_page_origin(tid)


def _local_login(handle, origin):
    from agent.vault_store import get_vault_store
    if not handle.startswith("vault_"):
        raise ValueError("a local signup login handle is required")
    store = get_vault_store()
    meta = store.get_meta(handle)
    if meta is None or meta.kind != "login" or meta.origin != origin:
        raise ValueError("the signup login is missing or bound to another website")
    return store, meta


def prepare_login(args, **kwargs):
    from agent.secret_scope import get_secret
    from agent.vault_store import get_vault_store

    tid, origin = _page(kwargs.get("task_id"))
    if not origin:
        return _result(success=False, error="Open the registration page in Hermes's browser first")
    probe = _evaluate(tid, "(() => { const p=location.pathname.toLowerCase(); return {origin:location.origin,signup:!!document.querySelector('input[autocomplete=\"new-password\"]') || ((p.includes('signup')||p.includes('register')) && !!document.querySelector('input[type=password]'))}; })()")
    if not probe.get("success") or not isinstance(probe.get("result"), dict) or probe["result"].get("origin") != origin or not probe["result"].get("signup"):
        return _result(success=False, error="The current page does not look like a registration form")
    email = str(args.get("email") or get_secret("EMAIL_ADDRESS", "") or "").strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return _result(success=False, error="Configure EMAIL_ADDRESS or provide a valid signup email")
    for existing in get_vault_store().list_items():
        if existing.kind == "login" and existing.origin == origin and existing.identifier == email:
            return _result(success=False, error="A login for this email and site is already saved", handle=existing.id)
    password = secrets.token_urlsafe(36)
    try:
        try:
            bitwarden_id = bitwarden_store.create(origin, email, password)
        except Exception:
            return _result(success=False, error_type="manual_reconciliation_required",
                           error="Bitwarden credential creation outcome is uncertain; check for an unlinked remote copy before retrying")
        meta = None
        try:
            meta = get_vault_store().add_item("login", urlparse(origin).hostname or origin,
                                             {"identifier_type": "email", "identifier": email, "password": password},
                                             origin=origin)
            bitwarden_store.link(meta.id, bitwarden_id)
        except Exception:
            try:
                bitwarden_store.delete(bitwarden_id)
            except Exception:
                return _result(success=False, error_type="manual_reconciliation_required",
                               error="Credential storage failed and the Bitwarden copy could not be removed; reconcile both stores before retrying",
                               handle=meta.id if meta is not None else None, bitwarden_secret_id=bitwarden_id)
            if meta is not None:
                try:
                    bitwarden_store.unlink(meta.id)
                    get_vault_store().remove_item(meta.id)
                except Exception:
                    return _result(success=False, error_type="manual_reconciliation_required",
                                   error="Bitwarden cleanup succeeded but local credential cleanup failed; reconcile before retrying",
                                   handle=meta.id)
            return _result(success=False, error="Could not complete credential storage; no website account was submitted")
        _arm_marker(tid, origin, email)
        return _result(success=True, handle=meta.id, email=email, origin=origin,
                       bitwarden_saved=True, next="Call signup_fill_registration with this handle, then submit the form")
    finally:
        del password


def _fill(args, task_id):
    from agent.redact import register_vault_redaction_value
    from tools.browser_vault_tool import _parse_json_result

    tid, origin = _page(task_id)
    if not origin:
        return _result(success=False, error="No registration page is open")
    try:
        store, meta = _local_login(str(args.get("handle") or ""), origin)
        password = str(store.resolve_secret(meta.id)["password"])
    except (ValueError, KeyError) as exc:
        return _result(success=False, error=str(exc))
    register_vault_redaction_value(password)
    payload = json.dumps({"origin": origin, "email": meta.identifier, "password": password})
    expression = """(() => {const x = PAYLOAD;
      if (location.origin !== x.origin) return {success:false,error:'origin changed'};
      const email=document.querySelector('input[autocomplete="email"],input[type="email"]');
      const passwords=[...document.querySelectorAll('input[type="password"]')].filter(e=>!e.disabled);
      if (!passwords.length || (!email && !(location.pathname.includes('/signup/') && (document.body.innerText||'').includes(x.email)))) return {success:false,error:'registration email or password field missing'};
      const set=(el,value)=>{const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
        setter.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
      if (email) set(email,x.email);set(passwords[0],x.password);
      if (passwords[1]) set(passwords[1],x.password);
      return {success:true,filled_fields:(email?1:0)+(passwords[1]?2:1),origin:x.origin};})()""".replace("PAYLOAD", payload)
    try:
        out = _evaluate(tid, expression, secret=True)
        if not out.get("success"):
            return _result(success=False, error_type=out.get("error_type"), error="supervised browser fill failed")
        parsed = _parse_json_result(out.get("result"))
        return _result(**parsed) if isinstance(parsed, dict) else _result(success=False, error="browser returned no fill result")
    finally:
        del password, payload, expression


def fill_registration(args, **kwargs):
    from tools.browser_vault_tool import _fenced_page_op
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: _fill(args, tid))


def _capture(args, task_id):
    from agent.vault_store import normalize_otp_secret
    from tools.browser_vault_tool import _parse_json_result

    tid, origin = _page(task_id)
    if not origin:
        return _result(success=False, error="No authenticator setup page is open")
    try:
        store, meta = _local_login(str(args.get("handle") or ""), origin)
    except ValueError as exc:
        return _result(success=False, error=str(exc))
    expression = """(async () => {const u=location.origin;
      const nodes=[...document.querySelectorAll('a[href],img[src],input[value],[data-otpauth]')];
      const vals=nodes.flatMap(e=>[e.href,e.src,e.value,e.getAttribute('data-otpauth')].filter(Boolean));
      const text=document.body.innerText||'';
      const uri=vals.concat([text]).map(v=>String(v).match(/otpauth:\/\/totp\/[^\\s"'<>]+/i)).find(Boolean);
      if(uri) return {origin:u,seed:uri[0]};
      const manual=[...document.querySelectorAll('code,kbd,[data-otp-secret]')]
        .map(e=>e.getAttribute('data-otp-secret')||e.textContent.trim())
        .find(v=>/^[A-Z2-7 -]{16,80}$/i.test(v));
      const images=[...document.querySelectorAll('img')].filter(e=>e.naturalWidth>=80&&e.naturalHeight>=80&&e.naturalWidth<=2048&&e.naturalHeight<=2048);
      const qrs=[];
      for(const img of images.slice(0,8)){try{const canvas=document.createElement('canvas');canvas.width=img.naturalWidth;canvas.height=img.naturalHeight;
        canvas.getContext('2d').drawImage(img,0,0);const qr=canvas.toDataURL('image/png');if(qr.length<=2800000)qrs.push(qr);}catch(e){}}
      return {origin:u,qrs,manual:manual||''};})()"""
    out = _evaluate(tid, expression)
    if not out.get("success"):
        return _result(success=False, error="Could not inspect authenticator setup page")
    data = _parse_json_result(out.get("result"))
    if not isinstance(data, dict) or data.get("origin") != origin:
        return _result(success=False, error="The page origin changed")
    raw_seed = str(data.get("seed") or "")
    source = "uri" if raw_seed else ""
    if data.get("qrs") or data.get("qr"):
        import base64
        from io import BytesIO
        from PIL import Image
        import zxingcpp
        for image in (data.get("qrs") or [data.get("qr")])[:8]:
            try:
                encoded = str(image).partition(",")[2]
                if len(encoded) > 2_800_000:
                    continue
                qr_bytes = base64.b64decode(encoded, validate=True)
                if len(qr_bytes) > 2_000_000:
                    continue
                decoded = zxingcpp.read_barcode(Image.open(BytesIO(qr_bytes)))
                if decoded and decoded.text.lower().startswith("otpauth://totp/"):
                    raw_seed = decoded.text
                    source = "qr"
                    break
            except Exception:
                continue
    if not raw_seed:
        raw_seed = str(data.get("manual") or "")
        source = "manual" if raw_seed else ""
    try:
        seed = normalize_otp_secret(raw_seed)
    except Exception:
        return _result(success=False, error="The page did not expose a usable TOTP setup key")
    if not seed:
        return _result(success=False, error="No TOTP setup key found; an opaque QR image needs a decoder")
    previous = str(store.resolve_secret(meta.id).get("otp_secret") or "")
    secret = store.resolve_secret(meta.id)
    password = str(secret["password"])
    try:
        bitwarden_store.update_totp(meta.id, origin, meta.identifier, password, seed)
    except Exception:
        try:
            remote = bitwarden_store.read_totp(meta.id, origin, meta.identifier, password)
            if remote != previous:
                if remote != seed:
                    raise RuntimeError("The remote TOTP differs from both expected values")
                bitwarden_store.update_totp(meta.id, origin, meta.identifier, password, previous)
                if bitwarden_store.read_totp(meta.id, origin, meta.identifier, password) != previous:
                    raise RuntimeError("Bitwarden did not restore the previous TOTP")
        except Exception:
            return _result(success=False, error_type="manual_reconciliation_required",
                           error="Bitwarden TOTP update outcome is uncertain; reconcile both credential copies before retrying", handle=meta.id)
        return _result(success=False, error="Could not save the authenticator key to Bitwarden; remote state matches the local copy")
    try:
        with store._locked():
            items = store._read_all()
            record = next((x for x in items if x.get("id") == meta.id), None)
            if record is None or record.get("origin") != origin:
                raise RuntimeError("The login changed while saving TOTP")
            record["secret"]["otp_secret"] = seed
            store._write_all(items)
    except Exception:
        try:
            bitwarden_store.update_totp(meta.id, origin, meta.identifier, password, previous)
            if bitwarden_store.read_totp(meta.id, origin, meta.identifier, password) != previous:
                raise RuntimeError("Bitwarden did not restore the previous TOTP")
            if str(store.resolve_secret(meta.id).get("otp_secret") or "") != previous:
                raise RuntimeError("The local credential changed despite the write failure")
        except Exception:
            return _result(success=False, error_type="manual_reconciliation_required",
                           error="TOTP storage failed and the two credential copies need reconciliation", handle=meta.id)
        return _result(success=False, error="Could not save the authenticator key locally; Bitwarden was restored")
    replaced_previous = bool(previous and previous != seed)
    del seed
    return _result(success=True, handle=meta.id, totp_saved=True, source=source,
                   replaced_previous=replaced_previous,
                   next="Call signup_fill_totp with this handle, then submit the TOTP confirmation form")


def capture_totp(args, **kwargs):
    from tools.browser_vault_tool import _fenced_page_op
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: _capture(args, tid))


def _fill_login(args, task_id):
    from agent.redact import register_vault_redaction_value
    from tools.browser_vault_tool import _parse_json_result
    tid, origin = _page(task_id)
    if not origin:
        return _result(success=False, error="No login page is open")
    try:
        store, meta = _local_login(str(args.get("handle") or ""), origin)
        password = str(store.resolve_secret(meta.id)["password"])
    except (ValueError, KeyError) as exc:
        return _result(success=False, error=str(exc))
    register_vault_redaction_value(password)
    payload = json.dumps({"origin": origin, "email": meta.identifier, "password": password})
    expression = """(() => {const x=PAYLOAD;if(location.origin!==x.origin)return {success:false,error:'origin changed'};
      const email=document.querySelector('input[autocomplete="username"],input[autocomplete="email"],input[type="email"]');
      const pass=document.querySelector('input[autocomplete="current-password"],input[type="password"]');
      if(!email||!pass)return {success:false,error:'login fields not found'};
      const set=(e,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,v);
        e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
      set(email,x.email);set(pass,x.password);return {success:true,filled_fields:2,origin:x.origin};})()""".replace("PAYLOAD", payload)
    try:
        out = _evaluate(tid, expression, secret=True)
        if not out.get("success"):
            return _result(success=False, error="supervised login fill failed")
        parsed = _parse_json_result(out.get("result"))
        return _result(**parsed) if isinstance(parsed, dict) else _result(success=False, error="browser returned no fill result")
    finally:
        del password, payload, expression


def fill_login(args, **kwargs):
    from tools.browser_vault_tool import _fenced_page_op
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: _fill_login(args, tid))


def _fill_totp(args, task_id):
    from agent.redact import register_vault_redaction_value
    from agent.vault_store import totp_now
    from tools.browser_vault_tool import _parse_json_result
    tid, origin = _page(task_id)
    if not origin:
        return _result(success=False, error="No authenticator code page is open")
    try:
        store, meta = _local_login(str(args.get("handle") or ""), origin)
        seed = str(store.resolve_secret(meta.id).get("otp_secret") or "")
        if not seed:
            return _result(success=False, error="No TOTP setup key is saved for this login")
        code = totp_now(seed)
    except ValueError as exc:
        return _result(success=False, error=str(exc))
    register_vault_redaction_value(code)
    payload = json.dumps({"origin": origin, "code": code})
    expression = """(() => {const x=PAYLOAD;if(location.origin!==x.origin)return {success:false,error:'origin changed'};
      const input=document.querySelector('input[autocomplete="one-time-code"],input[name*="otp" i],input[name*="code" i],input[id*="otp" i],input[id*="code" i]');
      if(!input)return {success:false,error:'code field not found'};
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,x.code);
      input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));
      return {success:true,filled_fields:1,origin:x.origin};})()""".replace("PAYLOAD", payload)
    try:
        out = _evaluate(tid, expression, secret=True)
        if not out.get("success"):
            return _result(success=False, error="supervised TOTP fill failed")
        parsed = _parse_json_result(out.get("result"))
        return _result(**parsed) if isinstance(parsed, dict) else _result(success=False, error="browser returned no fill result")
    finally:
        del seed, code, payload, expression


def fill_totp(args, **kwargs):
    from tools.browser_vault_tool import _fenced_page_op
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: _fill_totp(args, tid))


def _trusted_sender(hostname: str, sender: str) -> bool:
    domain = sender.lower().rsplit('@', 1)[-1]
    source = hostname.lower().removeprefix('www.')
    if domain == source or domain.endswith('.' + source):
        return True
    labels = source.split('.')
    if len(labels) > 2 and labels[0] in {'id', 'auth', 'accounts', 'login'}:
        parent = '.'.join(labels[1:])
        return domain == parent or domain.endswith('.' + parent)
    return False


def _imap_since(cutoff):
    from datetime import timedelta
    return (cutoff - timedelta(days=1)).strftime('%d-%b-%Y')

def arm_email_challenge(args, **kwargs):
    from agent.secret_scope import get_secret
    tid, origin = _page(kwargs.get('task_id'))
    if not origin:
        return _result(success=False, error='Open the website email challenge page first')
    try:
        handle = str(args.get('handle') or '')
        recipient = _local_login(handle, origin)[1].identifier if handle else get_secret('EMAIL_ADDRESS', '')
    except ValueError as exc:
        return _result(success=False, error=str(exc))
    if not recipient or recipient.lower() != get_secret('EMAIL_ADDRESS', '').lower():
        return _result(success=False, error='The configured agent inbox must match this challenge')
    expression = "(() => ({origin:location.origin,email:(document.body.innerText||'').includes(EMAIL)||[...document.querySelectorAll('input[type=email]')].some(e=>e.value===EMAIL)}))()".replace('EMAIL', json.dumps(recipient))
    probe = _evaluate(tid, expression)
    if not (probe.get('success') and isinstance(probe.get('result'), dict)
            and probe['result'].get('origin') == origin and probe['result'].get('email')):
        return _result(success=False, error='The challenge email is not visible on the current website page')
    _arm_marker(tid, origin, recipient)
    return _result(success=True, origin=origin, next='Request or resend the email code now, then call signup_fill_email_code')

def _authenticated_sender(msg, raw: bytes, sender: str, recipient: str) -> bool:
    from email.utils import getaddresses
    import dkim
    if any(len(msg.get_all(name, [])) != 1 for name in ('From', 'To', 'Subject')):
        return False
    if recipient.lower() not in {address.lower() for _, address in getaddresses(msg.get_all('To', []))}:
        return False
    delivered = msg.get_all('Delivered-To', [])
    if delivered and recipient.lower() not in {address.lower() for _, address in getaddresses(delivered)}:
        return False
    domain = sender.rsplit('@', 1)[-1].lower()
    for idx, signature in enumerate(msg.get_all('DKIM-Signature', [])[:8]):
        try:
            tags = dkim.parse_tag_value(signature.encode('ascii'))
            signed_headers = {part.strip().lower() for part in tags[b'h'].split(b':')}
            if not {b'from', b'to', b'subject'} <= signed_headers or b'l' in tags or b'bh' not in tags:
                continue
            signed_domain = tags[b'd'].decode('ascii').lower()
            if (domain == signed_domain or domain.endswith('.' + signed_domain)) and dkim.DKIM(raw).verify(idx=idx):
                return True
        except Exception:
            continue
    return False


def _recent_email_code(hostname: str, recipient: str, started=None) -> str:
    import email as email_module
    import html
    import imaplib
    from datetime import datetime, timedelta, timezone
    from email.utils import parseaddr, parsedate_to_datetime
    from agent.secret_scope import get_secret

    host = get_secret("EMAIL_IMAP_HOST", "")
    address = get_secret("EMAIL_ADDRESS", "")
    password = get_secret("EMAIL_PASSWORD", "")

    if not host or not address or not password or recipient.lower() != address.lower():
        raise RuntimeError("The agent inbox is unavailable for this signup email")
    cutoff = max(datetime.now(timezone.utc) - timedelta(minutes=90), started) if started else datetime.now(timezone.utc) - timedelta(minutes=90)
    candidates = []
    with imaplib.IMAP4_SSL(host, int(get_secret("EMAIL_IMAP_PORT", "993")), timeout=12) as conn:
        conn.login(address, password)
        since = _imap_since(cutoff)
        for box in ("INBOX", "Notification", "Spam", "Junk"):
            if conn.select('"' + box + '"', readonly=True)[0] != "OK":
                continue
            status, found = conn.search(None, "SINCE", since)
            if status != "OK":
                continue
            for uid in (found[0].split() if found and found[0] else [])[-30:]:
                typ, fetched = conn.fetch(uid, "(BODY.PEEK[] INTERNALDATE)")
                if typ != "OK":
                    continue
                item = next((part for part in fetched if isinstance(part, tuple)), None)
                if not item:
                    continue
                raw = item[1]
                delivery = re.search(rb'INTERNALDATE\s+"([^"]+)"', item[0], re.IGNORECASE)
                if not raw or not delivery:
                    continue
                try:
                    received_at = datetime.strptime(delivery.group(1).decode('ascii'), '%d-%b-%Y %H:%M:%S %z').astimezone(timezone.utc)
                except (ValueError, UnicodeDecodeError):
                    continue
                if received_at < cutoff or received_at > datetime.now(timezone.utc) + timedelta(minutes=5):
                    continue
                msg = email_module.message_from_bytes(raw)
                sender = parseaddr(msg.get("From", ""))[1].lower()
                subject = str(email_module.header.make_header(email_module.header.decode_header(msg.get("Subject", ""))))
                if not _trusted_sender(hostname, sender) or not _authenticated_sender(msg, raw, sender, recipient):
                    continue
                try:
                    stamp = parsedate_to_datetime(msg.get("Date", "")).astimezone(timezone.utc)
                except Exception:
                    continue
                if stamp < cutoff or stamp > datetime.now(timezone.utc) + timedelta(minutes=5):
                    continue
                subject_match = re.fullmatch(r"([A-Z0-9]{4,10}) is your [A-Za-z ]*verification code[.!]?", subject.strip(), re.IGNORECASE)
                if subject_match and any(c.isdigit() for c in subject_match.group(1)):
                    candidates.append((received_at, subject_match.group(1)))
                    continue
                chunks = []
                for part in msg.walk() if msg.is_multipart() else [msg]:
                    if part.get_content_maintype() != "text":
                        continue
                    data = part.get_payload(decode=True) or b""
                    chunks.append(data.decode(part.get_content_charset() or "utf-8", errors="replace"))
                body = html.unescape("\n".join(chunks))
                body = re.sub(r"<[^>]+>", " ", body)
                patterns = [r"(?:verification|verify|one.time|security|login|sign.in|your)\s*(?:code|pin|otp)?[^0-9]{0,80}\b([0-9]{6,8})\b",
                            r"\b([0-9]{6,8})\b[^A-Za-z]{0,20}(?:is your|verification|code)"]
                for pattern in patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        candidates.append((received_at, match.group(1)))
                        break
    if len({code for _, code in candidates}) > 1:
        raise RuntimeError("Multiple different codes arrived for this website; arm a fresh challenge and resend")
    return max(candidates, default=(None, ""), key=lambda pair: pair[0])[1]


def _fill_email_code(args, task_id):
    from agent.redact import register_vault_redaction_value
    from agent.secret_scope import get_secret
    from tools.browser_vault_tool import _parse_json_result
    tid, origin = _page(task_id)
    if not origin:
        return _result(success=False, error="No email verification page is open")
    try:
        handle = str(args.get("handle") or "")
        if handle:
            _, meta = _local_login(handle, origin)
            recipient = meta.identifier or ""
        else:
            recipient = get_secret('EMAIL_ADDRESS', '')
            expression = "(() => ({origin:location.origin,email:(document.body.innerText||'').includes(EMAIL)||[...document.querySelectorAll('input[type=email]')].some(e=>e.value===EMAIL),code:!!document.querySelector('input[autocomplete=\"one-time-code\"],input[name*=\"code\" i],input[id*=\"code\" i],input[name*=\"otp\" i],input[id*=\"otp\" i],input[aria-label*=\"otp\" i]')}))()"
            probe = _evaluate(tid, expression.replace('EMAIL', json.dumps(recipient)))
            if not (probe.get('success') and isinstance(probe.get('result'), dict)
                    and probe['result'].get('origin') == origin and probe['result'].get('email')
                    and probe['result'].get('code')):
                return _result(success=False, error='Open the agent email verification page first')
        from datetime import datetime, timedelta, timezone
        started = _CHALLENGE_STARTED.get((tid, origin, recipient.lower()))
        if started is None or datetime.now(timezone.utc) - started > timedelta(minutes=90):
            return _result(success=False, error_type="challenge_not_armed",
                           error="Arm the email challenge before requesting a new code, then retry after it arrives")
        hostname = urlparse(origin).hostname or ""
        code = _recent_email_code(hostname, recipient, started)
    except (ValueError, RuntimeError, OSError) as exc:
        return _result(success=False, error=str(exc))
    if not code:
        return _result(success=False, error_type="code_not_received", error="No recent verification code from this website is in the agent inbox yet")
    register_vault_redaction_value(code)
    payload = json.dumps({"origin": origin, "code": code})
    expression = """(() => {const x=PAYLOAD;if(location.origin!==x.origin)return {success:false,error:'origin changed'};
      const fields=[...document.querySelectorAll('input[autocomplete="one-time-code"],input[name*="code" i],input[id*="code" i],input[name*="otp" i],input[id*="otp" i],input[aria-label*="otp" i]')].filter(e=>!e.disabled);
      if(!fields.length)return {success:false,error:'verification code field not found'};
      const set=(e,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,v);
        e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
      if(fields.length>1&&fields.every(e=>e.maxLength===1)&&fields.length>=x.code.length){x.code.split('').forEach((c,i)=>set(fields[i],c));
        return {success:true,filled_fields:x.code.length,origin:x.origin};}
      set(fields[0],x.code);return {success:true,filled_fields:1,origin:x.origin};})()""".replace("PAYLOAD", payload)
    try:
        out = _evaluate(tid, expression, secret=True)
        if not out.get("success"):
            return _result(success=False, error="supervised email code fill failed")
        parsed = _parse_json_result(out.get("result"))
        if isinstance(parsed, dict) and parsed.get("success") and parsed.get("origin") == origin:
            _CHALLENGE_STARTED.pop((tid, origin, recipient.lower()), None)
        return _result(**parsed) if isinstance(parsed, dict) else _result(success=False, error="browser returned no fill result")
    finally:
        del code, payload, expression


def fill_email_code(args, **kwargs):
    from tools.browser_vault_tool import _fenced_page_op
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: _fill_email_code(args, tid))
