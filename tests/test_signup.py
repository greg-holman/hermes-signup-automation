import importlib.util
import ast
import base64
from io import BytesIO
import json
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch
from agent.vault_store import VaultStore
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signup_automation', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
PLUGIN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PLUGIN
SPEC.loader.exec_module(PLUGIN)
SIGNUP = PLUGIN.signup


class GuidanceTests(unittest.TestCase):
    def test_guidance_on_registration_only(self):
        self.assertIsNone(PLUGIN._signup_guidance(user_message='Read this page'))
        guidance = PLUGIN._signup_guidance(user_message='Register an account')
        self.assertIn('signup_prepare_login', guidance['context'])
        self.assertIn('Bitwarden Secrets Manager', guidance['context'])

    def test_register_exposes_seven_tools_and_hook(self):
        ctx = MagicMock()
        PLUGIN.register(ctx)
        names = [call.kwargs['name'] for call in ctx.register_tool.call_args_list]
        self.assertEqual(names, [
            'signup_prepare_login', 'signup_fill_registration', 'signup_capture_totp',
            'signup_fill_totp', 'signup_fill_login', 'signup_arm_email_challenge', 'signup_fill_email_code',
        ])
        self.assertEqual(ctx.register_hook.call_args.args[0], 'pre_llm_call')

    def test_email_code_tool_accepts_email_first_flow(self):
        ctx = MagicMock()
        PLUGIN.register(ctx)
        call = next(c for c in ctx.register_tool.call_args_list if c.kwargs['name'] == 'signup_fill_email_code')
        self.assertEqual(call.kwargs['schema']['parameters']['required'], [])


class EmailFirstTests(unittest.TestCase):
    def test_arm_marker_uses_next_whole_second(self):
        now = datetime(2026,9,29,3,0,0,350000,tzinfo=timezone.utc)
        start = SIGNUP._safe_challenge_start(now)
        self.assertEqual(start, datetime(2026,9,29,3,0,1,tzinfo=timezone.utc))

    def test_arm_email_challenge_requires_visible_email_and_binds_current_page(self):
        scope = types.ModuleType('agent.secret_scope')
        scope.get_secret = lambda key, default='': 'dev@example.org' if key == 'EMAIL_ADDRESS' else default
        with patch.dict(sys.modules, {'agent.secret_scope':scope}), patch.object(SIGNUP, '_page', return_value=('arm-task','https://login.example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://login.example.org','email':True}}):
            result = json.loads(SIGNUP.arm_email_challenge({}, task_id='arm-task'))
        self.assertTrue(result['success'])
        self.assertIn(('arm-task','https://login.example.org','dev@example.org'), SIGNUP._CHALLENGE_STARTED)

    def test_unarmed_email_challenge_never_reads_mail(self):
        scope = types.ModuleType('agent.secret_scope')
        scope.get_secret = lambda key, default='': 'dev@example.org' if key == 'EMAIL_ADDRESS' else default
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        with patch.dict(sys.modules, {'agent.secret_scope':scope,'tools.browser_vault_tool':browser}), patch.object(SIGNUP, '_page', return_value=('new-task','https://login.example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://login.example.org','email':True,'code':True}}), patch.object(SIGNUP, '_recent_email_code') as recent:
            result = json.loads(SIGNUP._fill_email_code({}, 'new-task'))
        self.assertEqual(result['error_type'], 'challenge_not_armed')
        recent.assert_not_called()

    def test_successful_email_code_fill_consumes_challenge(self):
        scope = types.ModuleType('agent.secret_scope')
        scope.get_secret = lambda key, default='': 'dev@example.org' if key == 'EMAIL_ADDRESS' else default
        scope.register_vault_redaction_value = lambda value: None
        redact = types.ModuleType('agent.redact')
        redact.register_vault_redaction_value = lambda value: None
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        key = ('one-shot-task', 'https://login.example.org', 'dev@example.org')
        SIGNUP._CHALLENGE_STARTED[key] = datetime.now(timezone.utc) - timedelta(seconds=2)
        def evaluated(_tid, _expression, secret=False):
            result = {'success': True, 'result': {'success': True, 'filled_fields': 1, 'origin': key[1]}} if secret else {'success': True, 'result': {'origin': key[1], 'email': True, 'code': True}}
            return result
        try:
            with patch.dict(sys.modules, {'agent.secret_scope': scope, 'agent.redact': redact, 'tools.browser_vault_tool': browser}), patch.object(SIGNUP, '_page', return_value=key[:2]), patch.object(SIGNUP, '_evaluate', side_effect=evaluated), patch.object(SIGNUP, '_recent_email_code', return_value='123456') as recent:
                first = json.loads(SIGNUP._fill_email_code({}, key[0]))
                second = json.loads(SIGNUP._fill_email_code({}, key[0]))
            self.assertTrue(first['success'])
            self.assertEqual(second['error_type'], 'challenge_not_armed')
            recent.assert_called_once()
        finally:
            SIGNUP._CHALLENGE_STARTED.pop(key, None)

    def test_email_first_accepts_address_only_in_email_input_on_code_page(self):
        expression = self._email_first_probe_expression()
        script = """const location={origin:'https://login.example.org'};
const document={body:{innerText:'Verify your account'},querySelectorAll:s=>s==='input[type=email]'?[{value:'dev@example.org'}]:[],querySelector:s=>s.includes('one-time-code')?{}:null};
console.log(JSON.stringify(EXPR));""".replace('EXPR', expression)
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True)
        self.assertTrue(json.loads(out.stdout)['email'])
        self.assertTrue(json.loads(out.stdout)['code'])

    def test_email_first_accepts_confirm_and_verification_paths_with_code_field(self):
        expression = self._email_first_probe_expression()
        for path in ('/signup/confirm', '/verification'):
            script = """const location={origin:'https://login.example.org',pathname:PATH};
const document={body:{innerText:'dev@example.org'},querySelector:s=>s.includes('one-time-code')?{}:null};
console.log(JSON.stringify(EXPR));""".replace('PATH', json.dumps(path)).replace('EXPR', expression)
            out = subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True)
            self.assertTrue(json.loads(out.stdout)['code'], path)

    @staticmethod
    def _email_first_probe_expression():
        source = Path(SIGNUP.__file__).read_text()
        tree = ast.parse(source)
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_fill_email_code')
        assignment = next(node for node in ast.walk(fn) if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and any(isinstance(t, ast.Name) and t.id == 'expression' for t in node.targets))
        return ast.literal_eval(assignment.value).replace('EMAIL', json.dumps('dev@example.org'))

    def test_uri_regex_preserves_secret_parameter(self):
        tree = ast.parse(Path(SIGNUP.__file__).read_text())
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_capture')
        assignment = next(node for node in ast.walk(fn) if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'expression' for t in node.targets))
        expression = ast.literal_eval(assignment.value)
        uri = 'otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP'
        script = """const location={origin:'https://example.org'};
const document={querySelectorAll:s=>[],body:{innerText:URI}};
(async()=>console.log(JSON.stringify(await EXPR)))();""".replace('URI', json.dumps(uri)).replace('EXPR', expression)
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(out.stdout)['seed'], uri)

    def test_mail_ignores_untrusted_and_future_dated_messages(self):
        now = datetime.now(timezone.utc)
        def message(sender, date, code, recipient='dev@example.org', authenticated=True):
            m = EmailMessage()
            m['From'] = sender
            m['To'] = recipient
            if authenticated:
                domain = sender.rsplit('@',1)[-1]
                m['DKIM-Signature'] = f'v=1; d={domain}; s=test; a=rsa-sha256; h=from:to:subject; bh=placeholder; b=placeholder'
            else:
                m['Authentication-Results'] = 'mx.example.net; dmarc=pass header.from=login.example.org; dkim=pass header.d=login.example.org'
            m['Subject'] = f'{code} is your verification code'
            m['Date'] = date.strftime('%a, %d %b %Y %H:%M:%S +0000')
            m.set_content('Use the verification code in the subject.')
            return m.as_bytes()
        messages = [message('noreply@login.example.org', now - timedelta(minutes=2), '111111'),
                    message('noreply@unrelated.example', now - timedelta(minutes=1), '222222'),
                    message('noreply@login.example.org', now + timedelta(days=1), '333333'),
                    message('noreply@login.example.org', now - timedelta(seconds=30), '444444', authenticated=False),
                    message('noreply@login.example.org', now - timedelta(seconds=20), '555555', recipient='someone@example.org'),
                    message('noreply@login.example.org', now - timedelta(seconds=10), '666666', authenticated=False),
                    message('noreply@login.example.org', now - timedelta(seconds=5), '777777')]
        class Mailbox:
            def __enter__(self): return self
            def __exit__(self, *unused): return None
            def login(self, *_): return 'OK'
            def select(self, *_args, **_kwargs): return 'OK', []
            def search(self, *_): return 'OK', [b'1 2 3 4 5 6 7']
            def fetch(self, uid, *_):
                delivered = now - (timedelta(minutes=20) if uid == b'7' else timedelta(minutes=2))
                stamp = delivered.strftime('%d-%b-%Y %H:%M:%S +0000')
                return 'OK', [(f'1 (INTERNALDATE "{stamp}" BODY[]'.encode(), messages[int(uid)-1])]
        scope = types.ModuleType('agent.secret_scope')
        scope.get_secret = lambda key, default='': {'EMAIL_IMAP_HOST':'imap.example','EMAIL_ADDRESS':'dev@example.org','EMAIL_PASSWORD':'dummy'}.get(key, default)
        with patch.dict(sys.modules, {'agent.secret_scope':scope}), patch('imaplib.IMAP4_SSL', return_value=Mailbox()), patch('dkim.DKIM.verify', return_value=True):
            self.assertEqual(SIGNUP._recent_email_code('login.example.org', 'dev@example.org', now - timedelta(minutes=3)), '111111')

    def test_ambiguous_codes_from_same_challenge_are_rejected(self):
        now = datetime.now(timezone.utc)
        messages = []
        for code in ('111111','222222'):
            m = EmailMessage()
            m['From'] = 'noreply@login.example.org'
            m['To'] = 'dev@example.org'
            m['DKIM-Signature'] = 'v=1; d=login.example.org; s=test; a=rsa-sha256; h=from:to:subject; bh=placeholder; b=placeholder'
            m['Date'] = now.strftime('%a, %d %b %Y %H:%M:%S +0000')
            m['Subject'] = f'{code} is your verification code'
            m.set_content('Verification challenge')
            messages.append(m.as_bytes())
        class Mailbox:
            def __enter__(self): return self
            def __exit__(self, *unused): return None
            def login(self, *_): return 'OK'
            def select(self, *_args, **_kwargs): return 'OK', []
            def search(self, *_): return 'OK', [b'1 2']
            def fetch(self, uid, *_):
                stamp = now.strftime('%d-%b-%Y %H:%M:%S +0000')
                return 'OK', [(f'1 (INTERNALDATE "{stamp}" BODY[]'.encode(), messages[int(uid)-1])]
        scope = types.ModuleType('agent.secret_scope')
        scope.get_secret = lambda key, default='': {'EMAIL_IMAP_HOST':'imap.example','EMAIL_ADDRESS':'dev@example.org','EMAIL_PASSWORD':'dummy'}.get(key, default)
        with patch.dict(sys.modules, {'agent.secret_scope':scope}), patch('imaplib.IMAP4_SSL', return_value=Mailbox()), patch('dkim.DKIM.verify', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'Multiple'):
                SIGNUP._recent_email_code('login.example.org', 'dev@example.org', now - timedelta(minutes=1))

    def test_dkim_from_only_signature_cannot_authenticate_code(self):
        m = EmailMessage()
        m['From'] = 'noreply@login.example.org'
        m['To'] = 'dev@example.org'
        m['Subject'] = '123456 is your verification code'
        m['DKIM-Signature'] = 'v=1; d=login.example.org; s=test; a=rsa-sha256; h=from; bh=placeholder; b=placeholder'
        m.set_content('Any body')
        with patch('dkim.DKIM.verify', return_value=True):
            self.assertFalse(SIGNUP._authenticated_sender(m, m.as_bytes(), 'noreply@login.example.org','dev@example.org'))

    def test_current_page_does_not_switch_to_stale_password_tab(self):
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._current_page_origin = lambda _: 'https://current.example'
        browser._focus_bound_origin = MagicMock()
        camofox = types.ModuleType('tools.browser_camofox')
        camofox.is_camofox_mode = lambda: False
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_origin = lambda value: value
        with patch.dict(sys.modules, {'tools.browser_vault_tool': browser, 'tools.browser_camofox': camofox, 'agent.vault_store': vault}):
            self.assertEqual(SIGNUP._page('task'), ('task', 'https://current.example'))
        browser._focus_bound_origin.assert_not_called()

    def test_imap_search_includes_cross_timezone_delivery(self):
        from datetime import datetime, timezone
        cutoff = datetime(2026, 9, 29, 0, 45, tzinfo=timezone.utc)
        self.assertEqual(SIGNUP._imap_since(cutoff), '28-Sep-2026')

    def test_remote_camofox_refuses_secret_expression(self):
        camofox = types.ModuleType('tools.browser_camofox')
        camofox.is_camofox_mode = lambda: True
        camofox.get_camofox_url = lambda: 'http://remote.example:9377'
        camofox._ensure_tab = MagicMock()
        camofox._post = MagicMock()
        with patch.dict(sys.modules, {'tools.browser_camofox': camofox}):
            result = SIGNUP._evaluate('test-task', 'secret-expression', secret=True)
        self.assertFalse(result['success'])
        camofox._post.assert_not_called()

    def test_local_camofox_secret_request_cannot_redirect(self):
        camofox = types.ModuleType('tools.browser_camofox')
        camofox.is_camofox_mode = lambda: True
        camofox.get_camofox_url = lambda: 'http://127.0.0.1:9377'
        camofox._ensure_tab = lambda _: {'tab_id':'test-tab','user_id':'test-user'}
        camofox._auth_headers = lambda: {}
        camofox._get_command_timeout = lambda: 5
        camofox._post = MagicMock(return_value={'result': None})
        browser = types.ModuleType('tools.browser_tool')
        browser._parse_eval_value = lambda value: value
        with patch.dict(sys.modules, {'tools.browser_camofox':camofox,'tools.browser_tool':browser}), patch('requests.post', return_value=types.SimpleNamespace(status_code=302)) as post:
            result = SIGNUP._evaluate('test-task','secret-expression',secret=True)
        self.assertFalse(result['success'])
        self.assertEqual(post.call_args.args[0], 'http://127.0.0.1:9377/tabs/test-tab/evaluate')
        self.assertFalse(post.call_args.kwargs['allow_redirects'])

    def test_trusted_sender_rejects_subject_only_brand_match(self):
        self.assertTrue(SIGNUP._trusted_sender('login.example.org', 'noreply@login.example.org'))
        self.assertTrue(SIGNUP._trusted_sender('login.example.org', 'noreply@example.org'))
        self.assertFalse(SIGNUP._trusted_sender('login.example.org', 'noreply@unrelated.example'))
        self.assertFalse(SIGNUP._trusted_sender('login.example.org', 'noreply@evil-example.org'))

    def test_email_first_fills_without_a_saved_login(self):
        secret_scope = types.ModuleType('agent.secret_scope')
        secret_scope.get_secret = lambda key, default='': 'dev@example.org' if key == 'EMAIL_ADDRESS' else default
        redact = types.ModuleType('agent.redact')
        redact.register_vault_redaction_value = MagicMock()
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        browser._fenced_page_op = lambda task_id, fn: fn()
        SIGNUP._CHALLENGE_STARTED[('test-task','https://login.example.org','dev@example.org')] = datetime.now(timezone.utc)
        with patch.dict(sys.modules, {'agent.secret_scope': secret_scope, 'agent.redact': redact, 'tools.browser_vault_tool': browser}), patch.object(SIGNUP, '_page', return_value=('test-task', 'https://login.example.org')), patch.object(SIGNUP, '_recent_email_code', return_value='TESTCODE') as recent, patch.object(SIGNUP, '_evaluate', side_effect=[{'success': True, 'result': {'origin': 'https://login.example.org', 'email': True, 'code': True}}, {'success': True, 'result': {'success': True, 'filled_fields': 8, 'origin': 'https://login.example.org'}}]) as evaluate:
            result = json.loads(SIGNUP.fill_email_code({}))
        self.assertTrue(result['success'])
        self.assertNotIn('TESTCODE', json.dumps(result))
        recent.assert_called_once()
        self.assertEqual(recent.call_args.args[:2], ('login.example.org', 'dev@example.org'))
        self.assertIsInstance(recent.call_args.args[2], datetime)
        self.assertTrue(evaluate.call_args.kwargs['secret'])


class RemoteStoreTests(unittest.TestCase):
    def test_read_totp_validates_linked_record(self):
        store = SIGNUP.bitwarden_store
        record = {'origin':'https://example.org','email':'dev@example.org','password':'test-password','otp_secret':'OLDSEED'}
        client = MagicMock()
        client.secrets.return_value.get.return_value = types.SimpleNamespace(success=True, data=types.SimpleNamespace(value=json.dumps(record)))
        with patch.object(store, '_mapping', return_value={'vault_test':'remote-id'}), patch.object(store, '_client', return_value=(client, {})):
            self.assertEqual(store.read_totp('vault_test', 'https://example.org','dev@example.org','test-password'), 'OLDSEED')
            with self.assertRaises(RuntimeError):
                store.read_totp('vault_test', 'https://other.example','dev@example.org','test-password')
        client.secrets.return_value.get.assert_called_with('remote-id')
    def test_update_totp_requires_remote_readback(self):
        store = SIGNUP.bitwarden_store
        client = MagicMock()
        client.secrets.return_value.update.return_value = types.SimpleNamespace(success=True)
        client.secrets.return_value.get.return_value = types.SimpleNamespace(success=True, data=types.SimpleNamespace(value=json.dumps({'origin':'https://example.org','email':'dev@example.org','password':'test-password','otp_secret':'OLDSEED'})))
        with patch.object(store, '_mapping', return_value={'vault_test':'remote-id'}), patch.object(store, '_client', return_value=(client, {'bitwarden_organization_id':'00000000-0000-0000-0000-000000000001','bitwarden_project_id':'00000000-0000-0000-0000-000000000002'})):
            with self.assertRaises(RuntimeError):
                store.update_totp('vault_test', 'https://example.org','dev@example.org','test-password','NEWSEED')


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.secret_scope = types.ModuleType('agent.secret_scope')
        self.secret_scope.get_secret = lambda key, default='': 'dev@example.org' if key == 'EMAIL_ADDRESS' else default
        self.vault_store = types.ModuleType('agent.vault_store')
        self.store = MagicMock()
        self.store.list_items.return_value = []
        self.vault_store.get_vault_store = lambda: self.store
        self.modules = patch.dict(sys.modules, {'agent.secret_scope': self.secret_scope, 'agent.vault_store': self.vault_store})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.page = patch.object(SIGNUP, '_page', return_value=('test-task', 'https://example.org'))
        self.evaluate = patch.object(SIGNUP, '_evaluate', return_value={
            'success': True, 'result': {'origin': 'https://example.org', 'signup': True},
        })
        self.page.start()
        self.evaluate.start()
        self.addCleanup(self.page.stop)
        self.addCleanup(self.evaluate.stop)

    def test_existing_login_never_creates_password(self):
        self.store.list_items.return_value = [types.SimpleNamespace(
            kind='login', origin='https://example.org', identifier='dev@example.org', id='vault_saved')]
        with patch.object(SIGNUP.secrets, 'token_urlsafe') as generate:
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertFalse(result['success'])
        self.assertEqual(result['handle'], 'vault_saved')
        generate.assert_not_called()

    def test_remote_create_timeout_requires_reconciliation(self):
        with patch.object(SIGNUP.bitwarden_store, 'create', side_effect=TimeoutError('response lost')):
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertEqual(result['error_type'], 'manual_reconciliation_required')
        self.store.add_item.assert_not_called()

    def test_bitwarden_failure_does_not_save_locally(self):
        with patch.object(SIGNUP.bitwarden_store, 'create', side_effect=RuntimeError('offline')):
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertFalse(result['success'])
        self.store.add_item.assert_not_called()

    def test_success_links_both_stores_without_exposing_password(self):
        self.store.add_item.return_value = types.SimpleNamespace(id='vault_test')
        with patch.object(SIGNUP.bitwarden_store, 'create', return_value='remote-id') as remote, patch.object(SIGNUP.bitwarden_store, 'link') as link:
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertEqual(result['handle'], 'vault_test')
        self.assertEqual(result['origin'], 'https://example.org')
        self.assertNotIn('password', result)
        remote.assert_called_once()
        self.assertTrue(remote.call_args.args[2])
        link.assert_called_once_with('vault_test', 'remote-id')

    def test_local_failure_removes_remote_credential(self):
        self.store.add_item.side_effect = RuntimeError('local disk error')
        with patch.object(SIGNUP.bitwarden_store, 'create', return_value='remote-id'), patch.object(SIGNUP.bitwarden_store, 'link'), patch.object(SIGNUP.bitwarden_store, 'unlink'), patch.object(SIGNUP.bitwarden_store, 'delete') as delete:
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertFalse(result['success'])
        delete.assert_called_once_with('remote-id')

    def test_cleanup_failure_is_reported_without_hiding_local_handle(self):
        self.store.add_item.return_value = types.SimpleNamespace(id='vault_test')
        self.store.remove_item.side_effect = RuntimeError('disk error')
        with patch.object(SIGNUP.bitwarden_store, 'create', return_value='remote-id'), patch.object(SIGNUP.bitwarden_store, 'link', side_effect=OSError('mapping failed')), patch.object(SIGNUP.bitwarden_store, 'unlink'), patch.object(SIGNUP.bitwarden_store, 'delete', side_effect=RuntimeError('remote unavailable')):
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertFalse(result['success'])
        self.assertEqual(result['handle'], 'vault_test')
        self.assertEqual(result['error_type'], 'manual_reconciliation_required')

    def test_remote_cleanup_failure_before_local_save_is_reported(self):
        self.store.add_item.side_effect = OSError('disk error')
        with patch.object(SIGNUP.bitwarden_store, 'create', return_value='remote-id'), patch.object(SIGNUP.bitwarden_store, 'delete', side_effect=RuntimeError('remote unavailable')):
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertFalse(result['success'])
        self.assertEqual(result['error_type'], 'manual_reconciliation_required')

    def test_totp_local_write_failure_restores_remote_previous_key(self):
        from contextlib import nullcontext
        self.store.get_meta.return_value = types.SimpleNamespace(id='vault_test',kind='login',origin='https://example.org',identifier='dev@example.org')
        self.store.resolve_secret.return_value = {'password':'test-password','otp_secret':'OLDSEED'}
        self.store._locked.return_value = nullcontext()
        self.store._read_all.return_value = [{'id':'vault_test','origin':'https://example.org','secret':{'password':'test-password','otp_secret':'OLDSEED'}}]
        self.store._write_all.side_effect = OSError('disk error')
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_otp_secret = lambda raw: raw
        vault.get_vault_store = lambda: self.store
        with patch.dict(sys.modules, {'tools.browser_vault_tool':browser,'agent.vault_store':vault}), patch.object(SIGNUP, '_page', return_value=('task','https://example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://example.org','seed':'NEWSEED'}}), patch.object(SIGNUP.bitwarden_store, 'update_totp') as update, patch.object(SIGNUP.bitwarden_store, 'read_totp', return_value='OLDSEED') as read:
            result = json.loads(SIGNUP._capture({'handle':'vault_test'},'task'))
        self.assertFalse(result['success'])
        self.assertEqual(update.call_count, 2)
        self.assertEqual(update.call_args.args[-1], 'OLDSEED')
        read.assert_called_once()

    def test_totp_rollback_failure_requires_reconciliation(self):
        from contextlib import nullcontext
        self.store.get_meta.return_value = types.SimpleNamespace(id='vault_test',kind='login',origin='https://example.org',identifier='dev@example.org')
        self.store.resolve_secret.return_value = {'password':'test-password','otp_secret':'OLDSEED'}
        self.store._locked.return_value = nullcontext()
        self.store._read_all.return_value = [{'id':'vault_test','origin':'https://example.org','secret':{'password':'test-password','otp_secret':'OLDSEED'}}]
        self.store._write_all.side_effect = OSError('disk error')
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_otp_secret = lambda raw: raw
        vault.get_vault_store = lambda: self.store
        with patch.dict(sys.modules, {'tools.browser_vault_tool':browser,'agent.vault_store':vault}), patch.object(SIGNUP, '_page', return_value=('task','https://example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://example.org','seed':'NEWSEED'}}), patch.object(SIGNUP.bitwarden_store, 'update_totp', side_effect=[None, RuntimeError('offline')]):
            result = json.loads(SIGNUP._capture({'handle':'vault_test'},'task'))
        self.assertEqual(result['error_type'], 'manual_reconciliation_required')

    def test_remote_update_timeout_after_write_restores_previous_key(self):
        self.store.get_meta.return_value = types.SimpleNamespace(id='vault_test',kind='login',origin='https://example.org',identifier='dev@example.org')
        self.store.resolve_secret.return_value = {'password':'test-password','otp_secret':'OLDSEED'}
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_otp_secret = lambda raw: raw
        vault.get_vault_store = lambda: self.store
        with patch.dict(sys.modules, {'tools.browser_vault_tool':browser,'agent.vault_store':vault}), patch.object(SIGNUP, '_page', return_value=('task','https://example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://example.org','seed':'NEWSEED'}}), patch.object(SIGNUP.bitwarden_store, 'update_totp', side_effect=[TimeoutError('response lost'), None]) as update, patch.object(SIGNUP.bitwarden_store, 'read_totp', side_effect=['NEWSEED','OLDSEED']) as read:
            result = json.loads(SIGNUP._capture({'handle':'vault_test'},'task'))
        self.assertFalse(result['success'])
        self.assertNotEqual(result.get('error_type'), 'manual_reconciliation_required')
        self.assertEqual(update.call_count, 2)
        self.assertEqual(update.call_args.args[-1], 'OLDSEED')
        self.assertEqual(read.call_count, 2)

    def test_remote_update_timeout_without_read_requires_reconciliation(self):
        self.store.get_meta.return_value = types.SimpleNamespace(id='vault_test',kind='login',origin='https://example.org',identifier='dev@example.org')
        self.store.resolve_secret.return_value = {'password':'test-password','otp_secret':'OLDSEED'}
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_otp_secret = lambda raw: raw
        vault.get_vault_store = lambda: self.store
        with patch.dict(sys.modules, {'tools.browser_vault_tool':browser,'agent.vault_store':vault}), patch.object(SIGNUP, '_page', return_value=('task','https://example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://example.org','seed':'NEWSEED'}}), patch.object(SIGNUP.bitwarden_store, 'update_totp', side_effect=TimeoutError('response lost')), patch.object(SIGNUP.bitwarden_store, 'read_totp', side_effect=OSError('offline')):
            result = json.loads(SIGNUP._capture({'handle':'vault_test'},'task'))
        self.assertEqual(result['error_type'], 'manual_reconciliation_required')

    def test_qr_capture_saves_key_without_returning_it(self):
        from contextlib import nullcontext
        image = BytesIO()
        Image.new('RGB', (100, 100)).save(image, format='PNG')
        qr = 'data:image/png;base64,' + base64.b64encode(image.getvalue()).decode('ascii')
        uri = 'otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP'
        self.store.get_meta.return_value = types.SimpleNamespace(id='vault_test',kind='login',origin='https://example.org',identifier='dev@example.org')
        self.store.resolve_secret.return_value = {'password':'test-password'}
        self.store._locked.return_value = nullcontext()
        self.store._read_all.return_value = [{'id':'vault_test','origin':'https://example.org','secret':{'password':'test-password'}}]
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_otp_secret = lambda raw: raw
        vault.get_vault_store = lambda: self.store
        decoder = types.ModuleType('zxingcpp')
        decoder.read_barcode = lambda img: types.SimpleNamespace(text=uri)
        with patch.dict(sys.modules, {'tools.browser_vault_tool':browser,'agent.vault_store':vault,'zxingcpp':decoder}), patch.object(SIGNUP, '_page', return_value=('task','https://example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://example.org','qr':qr}}), patch.object(SIGNUP.bitwarden_store, 'update_totp') as update:
            result = json.loads(SIGNUP._capture({'handle':'vault_test'},'task'))
        self.assertTrue(result['success'])
        self.assertEqual(result['source'], 'qr')
        self.assertNotIn(uri, json.dumps(result))
        update.assert_called_once()

    def test_qr_capture_skips_first_non_qr_image(self):
        from contextlib import nullcontext
        image = BytesIO()
        Image.new('RGB', (100, 100)).save(image, format='PNG')
        data = 'data:image/png;base64,' + base64.b64encode(image.getvalue()).decode('ascii')
        self.store.get_meta.return_value = types.SimpleNamespace(id='vault_test', kind='login', origin='https://example.org', identifier='dev@example.org')
        self.store.resolve_secret.return_value = {'password': 'test-password'}
        self.store._locked.return_value = nullcontext()
        self.store._read_all.return_value = [{'id':'vault_test','origin':'https://example.org','secret':{'password':'test-password'}}]
        browser = types.ModuleType('tools.browser_vault_tool')
        browser._parse_json_result = lambda value: value
        vault = types.ModuleType('agent.vault_store')
        vault.normalize_otp_secret = lambda raw: raw
        vault.get_vault_store = lambda: self.store
        decoder = types.ModuleType('zxingcpp')
        reads = iter([None, types.SimpleNamespace(text='otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP')])
        decoder.read_barcode = lambda img: next(reads)
        with patch.dict(sys.modules, {'tools.browser_vault_tool':browser,'agent.vault_store':vault,'zxingcpp':decoder}), patch.object(SIGNUP, '_page', return_value=('task','https://example.org')), patch.object(SIGNUP, '_evaluate', return_value={'success':True,'result':{'origin':'https://example.org','qrs':[data,data]}}), patch.object(SIGNUP.bitwarden_store, 'update_totp') as update:
            result = json.loads(SIGNUP._capture({'handle':'vault_test'},'task'))
        self.assertTrue(result['success'])
        self.assertEqual(result['source'], 'qr')
        update.assert_called_once()

    def test_browser_collects_multiple_qr_candidates(self):
        tree = ast.parse(Path(SIGNUP.__file__).read_text())
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_capture')
        assignment = next(node for node in ast.walk(fn) if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'expression' for t in node.targets))
        expression = ast.literal_eval(assignment.value)
        script = """const location={origin:'https://example.org'};
const images=[{naturalWidth:100,naturalHeight:100,getAttribute:()=>null},{naturalWidth:100,naturalHeight:100,getAttribute:()=>null}];
const document={body:{innerText:''},querySelectorAll:s=>s.includes('img')?images:[],createElement:s=>({getContext:()=>({drawImage:()=>{}}),toDataURL:()=> 'data:image/png;base64,AA=='})};
(async()=>console.log(JSON.stringify(await EXPR)))();""".replace('EXPR', expression)
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True)
        self.assertEqual(len(json.loads(out.stdout)['qrs']), 2)

    def test_registration_form_must_match_origin(self):
        with patch.object(SIGNUP, '_evaluate', return_value={
            'success': True, 'result': {'origin': 'https://other.example', 'signup': True},
        }), patch.object(SIGNUP.bitwarden_store, 'create') as remote:
            result = json.loads(SIGNUP.prepare_login({}))
        self.assertFalse(result['success'])
        remote.assert_not_called()

    def test_real_local_vault_and_mapping_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            local = VaultStore(base_dir=root / 'vault')
            with patch.object(self.vault_store, 'get_vault_store', return_value=local), patch.object(SIGNUP.bitwarden_store, '_mapping_path', return_value=root / 'mapping.json'), patch.object(SIGNUP.bitwarden_store, 'create', return_value='remote-test-id'):
                result = json.loads(SIGNUP.prepare_login({}))
                self.assertTrue(result['success'])
                self.assertEqual(local.get_meta(result['handle']).identifier, 'dev@example.org')
                self.assertEqual(SIGNUP.bitwarden_store._mapping()[result['handle']], 'remote-test-id')
                SIGNUP.bitwarden_store.unlink(result['handle'])
                self.assertNotIn(result['handle'], SIGNUP.bitwarden_store._mapping())


if __name__ == '__main__':
    unittest.main()
