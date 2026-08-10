# DEEP-TRACE — example API calls
# Set these before running:
#   export DEEPTRACE_API_KEY=dev_api_key_change_me_in_production
#   export DEEPTRACE_BASE=http://localhost:8000

# 1. Health
curl -s $DEEPTRACE_BASE/health | jq

# 2. Ready
curl -s $DEEPTRACE_BASE/ready | jq

# 3. OpenAPI spec
curl -s $DEEPTRACE_BASE/openapi.json | jq '.info'

# 4. Issue a challenge
curl -s -X POST $DEEPTRACE_BASE/api/v1/auth/challenge \
    -H "X-API-Key: $DEEPTRACE_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"account_id":"acct-42"}' | jq

# 5. Embed a watermark
curl -s -X POST $DEEPTRACE_BASE/api/v1/watermark/embed \
    -H "X-API-Key: $DEEPTRACE_API_KEY" \
    -F "file=@photo.png" \
    -F "account_id=acct-42" \
    -F "account_public_key=04abcd$(openssl rand -hex 30)" \
    -F "device_signature=dev-laptop-001" \
    -o embed.json
cat embed.json | jq

# 6. Extract a watermark
curl -s -X POST $DEEPTRACE_BASE/api/v1/forensics/extract \
    -H "X-API-Key: $DEEPTRACE_API_KEY" \
    -F "file=@suspect.jpg" \
    -o extract.json
cat extract.json | jq

# 7. Look up by asset_id (replace UUID)
ASSET_ID="00000000-0000-0000-0000-000000000000"
curl -s $DEEPTRACE_BASE/api/v1/ledger/$ASSET_ID \
    -H "X-API-Key: $DEEPTRACE_API_KEY" | jq

# 8. List entries for an account
curl -s "$DEEPTRACE_BASE/api/v1/ledger?account_id=acct-42&limit=10" \
    -H "X-API-Key: $DEEPTRACE_API_KEY" | jq

# 9. Search by perceptual hash
curl -s "$DEEPTRACE_BASE/api/v1/ledger/search?phash=ffffffffffff" \
    -H "X-API-Key: $DEEPTRACE_API_KEY" | jq

# 10. Verify a suspect against an asset_id
curl -s -X POST "$DEEPTRACE_BASE/api/v1/forensics/verify/$ASSET_ID" \
    -H "X-API-Key: $DEEPTRACE_API_KEY" \
    -F "file=@suspect.jpg" | jq
