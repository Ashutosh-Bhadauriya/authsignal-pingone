# Authsignal + PingOne Integration

Add Authsignal MFA and passwordless authentication to PingOne (Ping Identity) login flows.

## What This Does

This integration adds **Authsignal's MFA and passwordless capabilities** to **PingOne** authentication flows via two patterns:

1. **OIDC Bridge** — PingOne sign-on policies redirect to Authsignal as an external OIDC MFA provider
2. **DaVinci HTTP API** — PingOne DaVinci flows call Authsignal's API via HTTP connector nodes

### Supported Authentication Methods

- Passkeys (FIDO2 WebAuthn)
- SMS OTP
- Email OTP / Magic Link
- TOTP (authenticator apps)
- Push notifications
- WhatsApp OTP

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser    │────>│     PingOne       │────>│   Authsignal    │
│             │     │  (Identity)       │     │  (MFA/Passkeys) │
│             │     │                   │     │                 │
│             │     │  Sign-on Policy   │     │  Rules Engine   │
│             │     │  or DaVinci Flow  │     │  Pre-built UI   │
└─────────────┘     └──────────────────┘     └─────────────────┘
                            │                        │
                            v                        v
                    ┌──────────────────┐     ┌─────────────────┐
                    │  This Server      │     │  Authsignal     │
                    │  (Bridge/Middleware│     │  OIDC Endpoint  │
                    │   for DaVinci)    │     │                 │
                    └──────────────────┘     └─────────────────┘
```

### Pattern 1: OIDC Federation (Recommended)

Best for: PingOne sign-on policies, minimal custom code.

```
User → PingOne Login → PingOne Sign-on Policy (External IdP step)
  → /oidc/initiate (this server)
  → Authsignal OIDC /auth (pre-built MFA UI)
  → /oidc/callback (this server)
  → Back to PingOne (flow resumed)
```

### Pattern 2: DaVinci HTTP Connector

Best for: DaVinci flow orchestration, full control over the UX.

```
User → DaVinci Flow → HTTP Connector: POST /davinci/mfa/init
  → Redirect to Authsignal pre-built UI
  → User returns → HTTP Connector: POST /davinci/mfa/verify
  → DaVinci flow continues
```

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
4. Configure your desired **Actions** (e.g., `signIn`, `mfa`, `manageSettings`)
5. Set up **Rules** for adaptive MFA (optional)

### PingOne Setup

1. Log in to [PingOne Admin Console](https://console.pingone.com)
2. Create or select an **Environment**
3. Copy the **Environment ID** → `PINGONE_ENVIRONMENT_ID`

#### For OIDC Bridge (Pattern 1):

4. Go to **Connections → Applications → Add Application**
5. Create an **OIDC Web App** with:
   - **Redirect URI**: `http://localhost:3000/demo/callback`
   - **Grant Type**: Authorization Code
   - **PKCE**: S256
6. Copy **Client ID** and **Client Secret**
7. Go to **Authentication → Sign-on Policies**
8. Add an **Identity Provider** action step
9. Register Authsignal as an External IdP:
   - **Type**: OpenID Connect
   - **Authorization Endpoint**: `http://localhost:3000/oidc/initiate`
   - Or directly use Authsignal's OIDC discovery: `https://us-connect.authsignal.com/oidc/.well-known/openid-configuration`

#### For DaVinci (Pattern 2):

4. Go to **DaVinci → Flows**
5. Create a new flow or import the reference from `davinci/authsignal-mfa-flow.json`
6. Add **HTTP Connector** nodes pointing to:
   - `POST {YOUR_SERVER}/davinci/mfa/init` — initiate MFA
   - `POST {YOUR_SERVER}/davinci/mfa/verify` — verify MFA
7. Set the `X-API-Key` header to your `DAVINCI_BRIDGE_API_KEY`

## API Reference

### OIDC Bridge Endpoints

#### `GET /oidc/initiate`

Initiates the Authsignal MFA challenge via OIDC.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes* | PingOne user ID |
| `email` | string | No | User's email |
| `phone` | string | No | User's phone |
| `action` | string | No | Authsignal action (default: `mfa`) |
| `flow_id` | string | No | PingOne flow ID to resume after MFA |
| `id_token_hint` | string | No | PingOne ID token (extracts user_id/email) |

*Either `user_id` or `id_token_hint` with a `sub` claim is required.

#### `GET /oidc/callback`

Receives the Authsignal OIDC callback. Not called directly.

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
  "token": "string (required)"
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

```json
{
  "userId": "string",
  "email": "string",
  "redirectUrl": "string (required)"
}
```

### Demo Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /demo/login` | Redirects to PingOne for login |
| `GET /demo/callback` | PingOne callback → Authsignal MFA |
| `GET /demo/mfa-callback` | Authsignal MFA callback |
| `GET /demo/session` | Current session info (JSON) |
| `POST /demo/mfa-settings` | Opens Authsignal authenticator management |
| `POST /demo/logout` | Ends session |

## Security

- **PKCE (S256)** on all OIDC flows
- **State parameter** validation to prevent CSRF
- **Timing-safe comparison** for API key validation
- **HTTP-only cookies** for session management
- **Helmet** security headers (CSP, HSTS, etc.)
- **Rate limiting** on auth and API endpoints
- **Token validation** via JWKS for PingOne ID tokens

### Production Checklist

- [ ] Replace in-memory session store with Redis/database
- [ ] Replace in-memory OIDC bridge session store with Redis
- [ ] Set `APP_BASE_URL` to your production HTTPS URL
- [ ] Use a strong random value for `SESSION_SECRET`
- [ ] Use a strong random value for `DAVINCI_BRIDGE_API_KEY`
- [ ] Configure Authsignal redirect URLs in the dashboard
- [ ] Configure PingOne redirect URIs in the app settings
- [ ] Enable HTTPS (terminate at load balancer or reverse proxy)
- [ ] Set up monitoring/alerting on auth failure rates

## Client-Side Passkey Integration

For passwordless passkey login directly in the browser (without redirect):

```html
<script src="https://cdn.authsignal.com/browser/v1/authsignal-browser.min.js"></script>
<script>
const authsignal = new Authsignal({
  tenantId: 'YOUR_TENANT_ID',
  baseUrl: 'https://api.authsignal.com/v1',
});

// Passkey sign-in
const { data } = await authsignal.passkey.signIn({
  action: 'signIn',
});

if (data?.token) {
  // Send token to your server for validation
  const res = await fetch('/demo/verify-passkey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: data.token }),
  });
}
</script>
```

## License

MIT
