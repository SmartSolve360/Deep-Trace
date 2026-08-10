/**
 * DEEP-TRACE Velo Page Code
 * =========================
 *
 * Drop this into the Page Code editor of any Wix page. It expects:
 *   - #imageUploader    File Upload element
 *   - #btnEmbed         Button element
 *   - #btnExtract       Button element
 *   - #btnVerify        Button element (uses challenge flow)
 *   - #imgResult        Image element (for the watermarked output preview)
 *   - #txtStatus        Text element (status / errors)
 *   - #txtAssetId       Text element (the returned asset UUID)
 *   - #inputVerifyAssetId  Text Input element (asset_id to verify against)
 *   - #inputAccountId   Text Input element (optional account filter)
 *
 * Before this code will work, expose the backend functions from
 * `/public/backend/deep_trace_client.jsw` to the page (right-click each
 * function in the backend file > "Expose to Page").
 */

import {
    embedWatermark,
    extractWatermark,
    getPublicAsset,
    getWatermarkedImage,
    issueChallenge,
    verifyAgainstAsset
} from 'public/backend/deep_trace_client.jsw';


// ---- Status helper ----

function setStatus(message, kind) {
    if ($w("#txtStatus")) {
        $w("#txtStatus").text = message;
        // Optional: colour-code by kind. Wix Text elements support .style.
        const colour = { info: "#333", success: "#1a7f37", error: "#cf222e" }[kind] || "#333";
        try { $w("#txtStatus").style.color = colour; } catch (e) { /* ignore */ }
    }
    console.log(`[DEEP-TRACE][${kind || "info"}]`, message);
}


// ---- Embed flow ----

export async function btnEmbed_onClick(event) {
    setStatus("Initialising…", "info");

    // 1. Validate a file was selected
    if (!$w("#imageUploader").value || $w("#imageUploader").value.length === 0) {
        setStatus("Please select an image first.", "error");
        return;
    }

    try {
        // 2. Push the file to Wix temp storage
        setStatus("Uploading to secure staging…", "info");
        const uploaded = await $w("#imageUploader").uploadFiles();
        const fileInfo = uploaded[0];
        const fileUrl = fileInfo.fileUrl;
        const originalName = fileInfo.name || "asset.png";

        // 3. Call the backend
        setStatus("Embedding watermark & generating ledger receipt…", "info");
        const accountId = $w("#inputAccountId")?.value || undefined;
        const response = await embedWatermark(fileUrl, originalName, accountId);

        // 4. Show the watermarked preview (re-fetch from the public endpoint
        //    so the user gets the version-of-record stored in the ledger)
        setStatus(`Success! Asset ${response.asset_id}`, "success");
        if ($w("#txtAssetId")) $w("#txtAssetId").text = response.asset_id;
        if ($w("#imgResult")) {
            const blob = await getWatermarkedImage(response.asset_id);
            const objectUrl = URL.createObjectURL(blob);
            $w("#imgResult").src = objectUrl;
            $w("#imgResult").alt = `Watermarked asset ${response.asset_id}`;
        }
        console.log("DEEP-TRACE embed response:", response);

    } catch (err) {
        console.error("DEEP-TRACE embed failed:", err);
        setStatus(`Embed failed: ${err.message}`, "error");
    }
}


// ---- Extract flow ----

export async function btnExtract_onClick(event) {
    setStatus("Extracting…", "info");
    if (!$w("#imageUploader").value || $w("#imageUploader").value.length === 0) {
        setStatus("Please select a suspect image first.", "error");
        return;
    }
    try {
        const uploaded = await $w("#imageUploader").uploadFiles();
        const fileUrl = uploaded[0].fileUrl;
        const accountId = $w("#inputAccountId")?.value || undefined;
        const result = await extractWatermark(fileUrl, accountId);

        let msg = `Extraction: ${result.extraction_status}`;
        if (result.ledger_match) {
            const lm = result.ledger_match;
            msg += `\n\nMATCH FOUND\nAsset: ${lm.asset_id}\nAccount: ${lm.account_id}\nPayload match: ${lm.payload_match}`;
            if (lm.perceptual_distance) {
                msg += `\nHamming distance (pHash): ${lm.perceptual_distance.phash}`;
            }
            setStatus(msg, lm.payload_match ? "success" : "error");
        } else {
            setStatus(`${msg}\n(no ledger match found)`, "info");
        }
        console.log("DEEP-TRACE extract response:", result);

    } catch (err) {
        console.error("DEEP-TRACE extract failed:", err);
        setStatus(`Extract failed: ${err.message}`, "error");
    }
}


// ---- Verify flow ----

export async function btnVerify_onClick(event) {
    setStatus("Verifying…", "info");
    if (!$w("#imageUploader").value || $w("#imageUploader").value.length === 0) {
        setStatus("Please select a suspect image first.", "error");
        return;
    }
    const assetId = $w("#inputVerifyAssetId")?.value;
    if (!assetId) {
        setStatus("Please enter an asset_id to verify against.", "error");
        return;
    }
    try {
        // Verify requires a challenge. We need an account_id; default to
        // "verify" if the Wix user isn't signed in.
        const accountId = (wixUsers.currentUser.loggedIn && wixUsers.currentUser.id) || "verify";
        const ch = await issueChallenge(accountId);
        const uploaded = await $w("#imageUploader").uploadFiles();
        const fileUrl = uploaded[0].fileUrl;
        const result = await verifyAgainstAsset(fileUrl, assetId, ch.challenge_token);

        setStatus(
            result.verified
                ? `VERIFIED — asset is genuine (${result.perceptual_distance?.phash ?? "?"} bit distance)`
                : `Verification FAILED — payload ${result.payload_match ? "matches" : "does NOT match"}`,
            result.verified ? "success" : "error"
        );
        console.log("DEEP-TRACE verify response:", result);

    } catch (err) {
        console.error("DEEP-TRACE verify failed:", err);
        setStatus(`Verify failed: ${err.message}`, "error");
    }
}


// ---- Lookup flow (no upload required) ----

export async function btnLookup_onClick(event) {
    // Optional helper: fetch public asset metadata by id only (no upload).
    const assetId = $w("#inputVerifyAssetId")?.value;
    if (!assetId) {
        setStatus("Please enter an asset_id to look up.", "error");
        return;
    }
    try {
        const meta = await getPublicAsset(assetId);
        setStatus(
            `Asset ${meta.asset_id}\nAccount: ${meta.account_id}\nCreated: ${meta.created_at}\nImage URL: ${meta.image_url}`,
            "info"
        );
    } catch (err) {
        setStatus(`Lookup failed: ${err.message}`, "error");
    }
}
