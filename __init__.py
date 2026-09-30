import re

from .signup import arm_email_challenge, capture_totp, fill_email_code, fill_login, fill_registration, fill_totp, prepare_login


def _signup_guidance(*, user_message: str = "", **kwargs):
    if not re.search(r"\b(sign\s*up|signup|register|registration|create (?:an? )?(?:account|profile))\b",
                     user_message or "", re.IGNORECASE):
        return None
    return {"context": (
        "Hermes signup credential route: First discover the signup_automation tools with "
        "tool_search (or tool_describe), because plugin tools may be on demand rather than in "
        "the initial tool list. For a new website account, use signup_prepare_login "
        "on the site's email/password registration page, then signup_fill_registration and submit. "
        "These tools generate a password and save it in Bitwarden Secrets Manager plus the local "
        "Hermes vault without showing it to the model. A locked Bitwarden Password Manager CLI "
        "does not block this route. If the site offers TOTP setup, use signup_capture_totp and "
        "signup_fill_totp. For later login use signup_fill_login and signup_fill_totp. "
        "Before requesting an emailed code, call signup_arm_email_challenge on the site's "
        "email entry page (omit the handle for email-first signup). Then request or resend "
        "the code and use signup_fill_email_code to fill it without exposing it. "
        "Never request a pre-existing login for a brand-new account or switch to Google OAuth "
        "merely because the personal Bitwarden vault is locked."
    )}


def register(ctx):
    ctx.register_hook("pre_llm_call", _signup_guidance)
    ctx.register_tool(
        name="signup_prepare_login", toolset="signup_automation",
        schema={"name": "signup_prepare_login", "description": "On an open registration page, generate a strong password and save a login bound to the current website. Uses the configured agent email by default. Returns an opaque login handle and email; never returns the password. Call signup_fill_registration next. Do not use this for a site where an account already exists.", "parameters": {"type": "object", "properties": {"email": {"type": "string", "description": "Email to register. Omit to use the agent's configured EMAIL_ADDRESS."}}, "required": []}},
        handler=prepare_login, description="Prepare a new website login")
    ctx.register_tool(
        name="signup_fill_registration", toolset="signup_automation",
        schema={"name": "signup_fill_registration", "description": "Fill email and a generated password on the current signup page from a handle returned by signup_prepare_login. Fills password confirmation when present. Uses the supervised browser; never reveals the password. Submit the form yourself afterward.", "parameters": {"type": "object", "properties": {"handle": {"type": "string"}}, "required": ["handle"]}},
        handler=fill_registration, description="Fill signup credentials")
    ctx.register_tool(
        name="signup_capture_totp", toolset="signup_automation",
        schema={"name": "signup_capture_totp", "description": "On the site's authenticator setup page, decode its QR image or setup key into the existing Bitwarden and Hermes login without revealing it. Then call signup_fill_totp with the same handle to confirm TOTP enrollment.", "parameters": {"type": "object", "properties": {"handle": {"type": "string"}}, "required": ["handle"]}},
        handler=capture_totp, description="Save authenticator setup key")
    ctx.register_tool(
        name="signup_fill_totp", toolset="signup_automation",
        schema={"name": "signup_fill_totp", "description": "Generate a fresh TOTP code from the saved login and fill the current website's code field without revealing the code. Works with Camofox. Submit the code form afterward.", "parameters": {"type": "object", "properties": {"handle": {"type": "string"}}, "required": ["handle"]}},
        handler=fill_totp, description="Fill authenticator code")
    ctx.register_tool(
        name="signup_fill_login", toolset="signup_automation",
        schema={"name": "signup_fill_login", "description": "Fill email and password on the current website's login form from a saved signup handle. Works with Camofox; never reveals the password. Submit the form afterward.", "parameters": {"type": "object", "properties": {"handle": {"type": "string"}}, "required": ["handle"]}},
        handler=fill_login, description="Fill saved website login")
    ctx.register_tool(
        name="signup_arm_email_challenge", toolset="signup_automation",
        schema={"name": "signup_arm_email_challenge", "description": "Before requesting or resending an emailed code, arm the current website challenge for the configured agent inbox. The page must display the signup email. Omit handle for email-first signup; provide the saved login handle when available. Codes sent before arming are rejected. Then request/resend the code on the website and call signup_fill_email_code.", "parameters": {"type": "object", "properties": {"handle": {"type": "string", "description": "Saved login handle, if available"}}, "required": []}},
        handler=arm_email_challenge, description="Arm an emailed code challenge")
    ctx.register_tool(
        name="signup_fill_email_code", toolset="signup_automation",
        schema={"name": "signup_fill_email_code", "description": "On an email verification page, look for a recent code from this website in the configured agent inbox and fill it without exposing it. For email-first signup before password setup, omit handle; the page must display the configured agent email. For a saved account supply its handle. Submit the form afterward. Returns a no-code-yet result if mail has not arrived.", "parameters": {"type": "object", "properties": {"handle": {"type": "string", "description": "Saved login handle for this website; omit for email-first verification before password setup"}}, "required": []}},
        handler=fill_email_code, description="Fill emailed verification code")
