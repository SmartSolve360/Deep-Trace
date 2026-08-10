# DEEP-TRACE — Wix Velo Integration Guide

This guide walks a Wix designer through wiring a Wix site to a
DEEP-TRACE backend (running on Render/Railway).

**Time to integrate: ~30 minutes** if you're comfortable with Wix
Velo's Public & Backend editor.

---

## 0. Prerequisites

- A deployed DEEP-TRACE backend (e.g. `https://deep-trace-api.onrender.com`)
- A Wix site with the **Dev Mode** enabled (Wix Studio or Editor X)
- The API key for the deployment (added to your backend's `API_KEYS` env var)

---

## 1. Add the backend module to your site

1. In Wix Studio, open your site in **Dev Mode**.
2. In the **Public & Backend** code editor, create a new file:
   - Path: `public/backend/deep_trace_client.jsw`
   - Content: copy from `examples/velo/public/deep_trace_client.jsw` in this repo
3. **Expose each function to the page**: in the editor, right-click each
   function name (`embedWatermark`, `extractWatermark`, `getPublicAsset`,
   `getWatermarkedImage`, `issueChallenge`, `verifyAgainstAsset`) and
   choose **"Expose to Page"**.

You should see a small "page" icon next to each function name in the
sidebar.

---

## 2. Configure the API base URL + secret

In `public/backend/deep_trace_client.jsw`, edit the top:

```js
const DEEPTRACE_API_BASE_URL = "https://deep-trace-api.onrender.com";
```

Then in Wix Studio's **Site Settings → Secrets Manager**, add a new
secret:

- **Name**: `DEEPTRACE_API_KEY`
- **Value**: your service API key (e.g. `prod_api_key_xxxxxxxxxx`)
- **Scope**: Backend (this is critical — never expose this to the page)

The client reads the secret via `wixSecrets.getSecret()` so the key
never leaves the server.

---

## 3. Allow your Wix domain in the backend CORS

The backend defaults to permissive CORS (`*`) for dev. For production,
edit your Render environment variables and set:

```
CORS_ALLOW_ORIGINS=https://yoursite.wixsite.com,https://www.yourcustomdomain.com
```

This is a comma-separated list. Restart the Render service after the
change.

---

## 4. Add the page code

1. Open the page where you want the embed/extract UI.
2. Add these elements (Wix Studio's Add panel):
   - **File Upload** — name it `imageUploader`
   - **Button** ×3 — name them `btnEmbed`, `btnExtract`, `btnVerify`
   - **Text** — name it `txtStatus` (status / error display)
   - **Image** — name it `imgResult` (watermarked preview)
   - **Text** — name it `txtAssetId` (the returned asset UUID)
   - **Text Input** — name it `inputVerifyAssetId` (used by verify/lookup)
   - **Text Input** — name it `inputAccountId` (optional filter)
3. Open the **Page Code** editor and paste the contents of
   `examples/velo/page/page-code.js` from this repo.
4. For each button, attach the matching `onClick` event:
   - `#btnEmbed`   → `btnEmbed_onClick`
   - `#btnExtract` → `btnExtract_onClick`
   - `#btnVerify`  → `btnVerify_onClick`

(If you also want the optional `btnLookup` button, add a button with
id `btnLookup` and wire it to `btnLookup_onClick`.)

---

## 5. Test the flow

1. Preview the page (or hit the live URL).
2. Pick an image, click **Embed**. You should see a status like:
   ```
   Success! Asset 5c51f8f6-0858-4ece-a890-a8307e11d46b
   ```
3. The watermarked preview should appear in `#imgResult`.
4. To verify: pick a watermarked image, paste its asset_id into
   `inputVerifyAssetId`, click **Verify**. You should see:
   ```
   VERIFIED — asset is genuine (1 bit distance)
   ```

---

## 6. What each API does (cheat sheet)

| Velo function | HTTP | Auth | Purpose |
|---|---|---|---|
| `embedWatermark(fileUrl, name, accountId?)` | `POST /api/v1/watermark/embed` | X-API-Key | Embed watermark, return asset_id + watermarked image |
| `extractWatermark(fileUrl, accountId?)` | `POST /api/v1/forensics/extract` | X-API-Key | Extract watermark, look up in ledger |
| `getPublicAsset(assetId)` | `GET /api/v1/asset/{id}` | none | Fetch sanitised public metadata |
| `getWatermarkedImage(assetId)` | `GET /api/v1/asset/{id}/image` | none | Download the watermarked PNG |
| `issueChallenge(accountId)` | `POST /api/v1/auth/challenge` | X-API-Key | Mint an HMAC challenge |
| `verifyAgainstAsset(fileUrl, assetId, token)` | `POST /api/v1/forensics/verify/{id}` | X-API-Key + X-Challenge | Verify a suspect image against a known asset |

---

## 7. Rate limits

The backend enforces these (per IP, or per API key for authenticated routes):

| Route | Default limit |
|---|---|
| `POST /watermark/embed` | 10 req/min |
| `GET /asset/{id}` and `/image`, `/thumb` | 60 req/min per IP |
| All other authed routes | 600 req/min per API key |

Configure via env vars `RATE_LIMIT_EMBED`, `RATE_LIMIT_PUBLIC`,
`RATE_LIMIT_AUTHED`.

When a limit is hit, the response is HTTP `429 Too Many Requests`
with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
headers. Wix's `wix-fetch` will surface the 429 to your `catch` block.

---

## 8. Error responses

All errors come back as JSON:

```json
{
  "error": {
    "error_code": "INVALID_IMAGE",
    "message": "Image too small: 100x100. Minimum is 128x128",
    "details": { "width": 100, "height": 100, "min_size": 128 }
  }
}
```

| HTTP code | Meaning |
|---|---|
| 200 | Success |
| 400 | Bad input (image unreadable, bad UUID, etc.) |
| 401 | Missing or invalid `X-API-Key` |
| 404 | Asset not found |
| 410 | Asset found but image not stored (legacy asset) |
| 413 | Image too small for the watermark payload |
| 422 | Validation error (missing required field, etc.) |
| 429 | Rate limit exceeded |
| 500 | Engine / server error |

---

## 9. Custom domain (optional)

If you have your own domain for the API (e.g. `api.yourbrand.com`):

1. In Render, add the custom domain to your service.
2. Set up DNS (CNAME → `deep-trace-api.onrender.com`).
3. Update `DEEPTRACE_API_BASE_URL` in `deep_trace_client.jsw` to your custom domain.
4. Update `CORS_ALLOW_ORIGINS` on Render to include both your Wix site
   and the custom API domain (for health-check tools).

---

## 10. Going live checklist

- [ ] `SECRET_KEY` is set to a fresh 32+ byte random value (not the dev default)
- [ ] `API_KEYS` contains a strong unique value for production
- [ ] `CORS_ALLOW_ORIGINS` is set to the specific Wix domain(s)
- [ ] `ENVIRONMENT=production` so the DB init errors are fatal (not warnings)
- [ ] `LOG_JSON=true` so logs are structured for your log aggregator
- [ ] Render Postgres backup schedule is configured
- [ ] `RATE_LIMIT_*` tuned to your expected traffic
- [ ] Wix `DEEPTRACE_API_KEY` secret is **Backend scope only** (not Page scope)
- [ ] Custom domain + DNS if applicable
- [ ] A test embed in production succeeded end-to-end

That's it. Hit me up if anything breaks.
