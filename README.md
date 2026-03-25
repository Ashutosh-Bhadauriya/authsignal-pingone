# Authsignal + PingOne Integration

Add Authsignal MFA and passwordless authentication to PingOne (Ping Identity) login flows.

## What This Does

This integration adds **Authsignal's MFA and passwordless capabilities** to **PingOne** authentication flows. A middleware server sits between PingOne (identity provider) and Authsignal (MFA provider) — PingOne handles "who are you?" and Authsignal handles "prove it's really you."

```
┌──────────┐      ┌──────────────┐      ┌─────────────┐      ┌─────────────┐
│  Browser  │ ──── │  Our Server   │ ──── │   PingOne    │      │  Authsignal  │
│           │      │  (Express)    │ ──── │  (Identity)  │      │  (MFA)       │
└──────────┘      └──────────────┘      └─────────────┘      └─────────────┘
```

### Supported Authentication Methods

- Email OTP (auto-enrolled from PingOne email)
- Passkeys (FIDO2 WebAuthn)
- SMS OTP
- TOTP (authenticator apps)
- Push notifications
- WhatsApp OTP

## Integration Patterns

### Pattern 1: Demo App (Primary)

Full login flow with frontend. PingOne OIDC login with Authsignal MFA step-up.

### Pattern 2: DaVinci API Bridge

REST endpoints that PingOne DaVinci flows call via HTTP connector nodes. For orgs using DaVinci's visual flow builder.

### Pattern 3: OIDC Bridge

For PingOne sign-on policies that need Authsignal as an "External IdP" step. PingOne redirects to the bridge, which federates to Authsignal via OIDC, then returns the result to PingOne.

---

## End-to-End Flow

### Step 1: User clicks "Sign in with PingOne"

```
Browser → GET /demo/login → Our Server
```

Our server generates:
- **state** — random string to prevent CSRF (stored server-side)
- **nonce** — random string to prevent token replay (stored server-side)
- **PKCE pair** — `code_verifier` (secret, stored server-side) and `code_challenge` (SHA-256 hash, sent to PingOne)

Then redirects the browser to PingOne:
```
Browser → 302 → https://auth.pingone.com/{envId}/as/authorize
  ?response_type=code
  &client_id=...
  &redirect_uri=http://localhost:3000/demo/callback
  &scope=openid profile email
  &state=abc123...
  &nonce=xyz789...
  &code_challenge=Hk7d...
  &code_challenge_method=S256
```

### Step 2: User authenticates with PingOne

PingOne shows its login form. User enters username + password. PingOne validates credentials against its user directory.

If valid, PingOne redirects back with a short-lived **authorization code**:
```
Browser → 302 → http://localhost:3000/demo/callback
  ?code=a1b2c3...
  &state=abc123...
```

### Step 3: Server exchanges the code for tokens

```
Our Server → POST https://auth.pingone.com/{envId}/as/token
  Authorization: Basic base64(clientId:clientSecret)
  Body: grant_type=authorization_code
        &code=a1b2c3...
        &redirect_uri=http://localhost:3000/demo/callback
        &code_verifier=original_secret_value
```

PingOne verifies:
- The code is valid and not expired
- The `code_verifier` hashes to the `code_challenge` sent in step 1 (**PKCE**)
- The `redirect_uri` matches
- The `client_secret` is correct

Returns an ID token and access token.

### Step 4: Server verifies the PingOne ID token

Fetches PingOne's public keys (JWKS) and cryptographically verifies:
- The **signature** is valid (token wasn't tampered with)
- The **issuer** matches PingOne
- The **audience** matches our client ID
- The **nonce** matches what we stored (prevents replay)
- The token **hasn't expired**

From the verified token we extract: `sub` (user ID), `email`, `name`.

### Step 5: Auto-enroll email if user is new to Authsignal

```
Our Server → GET https://api.authsignal.com/v1/users/{userId}
```

Checks if the user has any authenticators enrolled. If not:

```
Our Server → POST https://api.authsignal.com/v1/users/{userId}/authenticators
  Body: {
    "verificationMethod": "EMAIL_OTP",
    "email": "user@example.com",
    "isDefault": true
  }
```

This enrolls their PingOne-verified email as an EMAIL_OTP authenticator so they can be challenged immediately without manual enrollment.

### Step 6: Track the sign-in action with Authsignal

```
Our Server → POST https://api.authsignal.com/v1/users/{userId}/actions/signIn
  Body: {
    "redirectUrl": "http://localhost:3000/demo/mfa-callback",
    "email": "user@example.com"
  }
```

Authsignal's **rules engine** evaluates the action and returns:

```json
{
  "state": "CHALLENGE_REQUIRED",
  "url": "https://mfa.authsignal.com/challenge?token=eyJ...",
  "idempotencyKey": "47cd0b03-...",
  "isEnrolled": true
}
```

### Step 7: Store pending MFA context and redirect

Our server stores the user context in a pending MFA map (keyed by `idempotencyKey`). **No session is created yet** — the session only exists after MFA succeeds. This prevents MFA bypass.

Then redirects the browser to Authsignal's pre-built MFA UI:
```
Browser → 302 → https://mfa.authsignal.com/challenge?token=eyJ...
```

### Step 8: User completes MFA challenge

Authsignal's pre-built UI:
1. Shows the challenge screen (email OTP input)
2. Sends an OTP code to the user's email
3. User enters the code
4. Authsignal verifies it

On success, Authsignal redirects back:
```
Browser → 302 → http://localhost:3000/demo/mfa-callback?token=eyJ...
```

### Step 9: Server validates the MFA result

```
Our Server → POST https://api.authsignal.com/v1/validate
  Body: { "token": "eyJ..." }
```

Authsignal returns:
```json
{
  "isValid": true,
  "state": "CHALLENGE_SUCCEEDED",
  "userId": "fddb7b06-...",
  "idempotencyKey": "47cd0b03-...",
  "verificationMethod": "EMAIL_OTP"
}
```

Our server then:
1. Looks up the pending MFA context by `idempotencyKey`
2. **Verifies the userId matches** (prevents cross-user MFA swap attacks)
3. Deletes the pending entry
4. **Creates the session** with `mfaVerified: true`
5. Sets an httpOnly session cookie
6. Redirects to the dashboard

### Step 10: Dashboard

The dashboard JS calls `GET /demo/session`, gets the session info, and renders it showing the authenticated user with MFA status.

---

## Sign Out Flow

```
Browser → POST /demo/logout → Our Server
  1. Deletes the server-side session
  2. Clears the session cookie
  3. Returns PingOne's signoff URL

Browser → 302 → https://auth.pingone.com/{envId}/as/signoff
  1. PingOne kills its SSO session
  2. Redirects back to our app
```

Next login will require both PingOne credentials AND Authsignal MFA again.

## MFA Settings Flow

```
Browser → POST /demo/mfa-settings → Our Server
  → Authsignal trackAction("manageSettings", { redirectToSettings: true })
  → Returns settings URL

Browser → redirect to Authsignal settings UI
  → User adds/removes passkeys, TOTP, phone numbers
  → Click "Quit" → redirects back to dashboard
```

---

## Security

| Threat | Protection |
|--------|-----------|
| Code interception | PKCE — `code_verifier` never leaves server |
| CSRF | State parameter validated on callback |
| Token replay | Nonce verified in ID token |
| Token tampering | JWKS signature verification |
| MFA bypass | Session only created after MFA succeeds |
| Cross-user MFA swap | userId matched between pending context and MFA result |
| API key brute force | HMAC timing-safe comparison (no length leak) |
| Memory exhaustion | Bounded in-memory stores with TTL cleanup |
| Credential exposure | Secrets server-side only, httpOnly cookies |
| Open redirect | Redirect URL allowlist on DaVinci endpoints |

### Why OIDC + PKCE (not SAML)

Both protocols are equally secure when implemented correctly. We chose OIDC because:

- Authsignal exposes OIDC endpoints natively (no SAML support)
- PingOne's modern APIs are OIDC-first
- JSON/REST is simpler to debug, build, and maintain than XML/SOAP
- PKCE provides stronger protection against code interception than SAML
- Mobile and SPA support comes free with OIDC

---

## Quick Start

### 1. Install

```bash
npm install
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your Authsignal and PingOne credentials
```

### 3. Run

```bash
npm run dev    # Development with hot-reload
npm run build  # Production build
npm start      # Start production server
```

## Setup Guide

### Authsignal Setup

1. Create an account at [authsignal.com](https://www.authsignal.com)
2. Go to **Settings → API Keys** and copy:
   - **Tenant ID** → `AUTHSIGNAL_TENANT_ID`
   - **Secret Key** → `AUTHSIGNAL_SECRET`
3. Note your region (US/EU/AU/CA) and set the matching API/OIDC URLs
4. Configure the `signIn` action with a rule set to **"Always challenge"**
5. Create a `manageSettings` action for authenticator self-service

### PingOne Setup

1. Log in to [PingOne Admin Console](https://console.pingone.com)
2. Create an environment with **PingOne SSO** and **PingOne MFA** services
3. Copy the **Environment ID** → `PINGONE_ENVIRONMENT_ID`
4. Go to **Applications → Add Application → OIDC Web App**
5. Configure:
   - **Redirect URI**: `http://localhost:3000/demo/callback`
   - **Signoff URL**: `http://localhost:3000`
   - **Grant Type**: Authorization Code
   - **Scopes**: openid, profile, email
6. Copy **Client ID** and **Client Secret**
7. **Enable** the application (toggle on)
8. Create a test user under **Directory → Users**

## API Reference

### Demo Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /demo/login` | Redirects to PingOne for login |
| `GET /demo/callback` | PingOne callback → auto-enroll → Authsignal MFA |
| `GET /demo/mfa-callback` | Authsignal MFA callback → create session |
| `POST /demo/passkey-callback` | Validates passkey sign-in token |
| `GET /demo/session` | Current session info (JSON) |
| `POST /demo/mfa-settings` | Opens Authsignal authenticator management |
| `POST /demo/logout` | Ends local session + PingOne SSO session |

### OIDC Bridge Endpoints

#### `GET /oidc/initiate`

Initiates the Authsignal MFA challenge via OIDC federation.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes* | PingOne user ID |
| `email` | string | No | User's email |
| `phone` | string | No | User's phone |
| `action` | string | No | Authsignal action (default: `mfa`) |
| `flow_id` | string | No | PingOne flow ID to resume after MFA |
| `id_token_hint` | string | No | PingOne ID token (extracts user_id/email) |

*Either `user_id` or `id_token_hint` with a `sub` claim is required.
If `flow_id` is supplied, `id_token_hint` is also required.

### DaVinci API Endpoints

All endpoints require `X-API-Key` header.

#### `POST /davinci/mfa/init`

```json
{
  "userId": "string (required)",
  "action": "string (default: mfa)",
  "email": "string",
  "phoneNumber": "string",
  "ipAddress": "string",
  "userAgent": "string",
  "redirectUrl": "string (required)",
  "custom": {}
}
```

Response:
```json
{
  "challengeRequired": true,
  "state": "CHALLENGE_REQUIRED",
  "challengeUrl": "https://...",
  "token": "eyJ...",
  "idempotencyKey": "...",
  "isEnrolled": true,
  "enrolledMethods": ["PASSKEY", "SMS"]
}
```

#### `POST /davinci/mfa/verify`

```json
{
  "token": "string (required)",
  "userId": "string (required)",
  "action": "string (required)"
}
```

Response:
```json
{
  "isValid": true,
  "state": "CHALLENGE_SUCCEEDED",
  "userId": "...",
  "action": "mfa",
  "verificationMethod": "PASSKEY"
}
```

#### `GET /davinci/user/:userId/enrollment`

Returns enrollment status and authenticators for a user.

#### `POST /davinci/passwordless/init`

Initiates passwordless (passkey) authentication.

### Production Checklist

- [ ] Replace in-memory session store with Redis/database
- [ ] Replace in-memory OIDC bridge session store with Redis
- [ ] Set `APP_BASE_URL` to your production HTTPS URL
- [ ] Set `TRUST_PROXY` to match your reverse-proxy topology
- [ ] Use strong random values for `SESSION_SECRET` and `DAVINCI_BRIDGE_API_KEY`
- [ ] Configure PingOne redirect URIs and signoff URLs
- [ ] Enable HTTPS (terminate at load balancer or reverse proxy)
- [ ] Set up monitoring/alerting on auth failure rates

## License

MIT
