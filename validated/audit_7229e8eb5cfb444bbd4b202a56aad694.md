### Title
Zip entry's declared `uncompressedSize` metadata is trusted to enforce a size cap, allowing the actual decompressed content to bypass it - ([File: wallet.js])

### Summary
`handlePrivatePaymentFile()` in `wallet.js` enforces a 100MB cap on a private-textcoin payload by checking `entry._data.uncompressedSize`, a metadata field taken from the zip archive's own (attacker-controlled) local/central directory record, rather than the actual number of bytes produced when the entry is inflated. This mirrors the Hono advisory's root cause: a size limit is enforced against a client-supplied "declared length" field instead of the verified real length of the data that will actually be processed, so a crafted input can understate the declared size while inflating to an arbitrarily larger payload.

### Finding Description [1](#0-0) 
`handlePrivatePaymentFile` opens a zip file supplied to the wallet (e.g. a "textcoin" claim file) and checks the size limit like this:
```
const entry = zip.file("private_textcoin");
if (!entry)
    return cb("missing private_textcoin entry in zip");
if (entry._data && entry._data.uncompressedSize > 100 * 1024 * 1024)
    return cb("private_textcoin entry is too large");
entry.async("string").then(function(data) {
    try {
        data = JSON.parse(data);
        ...
```
`entry._data.uncompressedSize` is populated by JSZip directly from the size field embedded in the zip entry's local file header / central directory record — a value fully controlled by whoever crafted the archive. It is not derived from re-measuring the actually-inflated bytes. JSZip (like most zip libraries) does not cross-validate that the header-declared uncompressed size matches the number of bytes the DEFLATE stream really expands to before this check runs; the mismatch, if any, only becomes apparent after `entry.async("string")` fully inflates the data. Consequently, a maliciously crafted zip can declare a small `uncompressedSize` (e.g. under the 100MB threshold) while its compressed stream actually inflates to a much larger string (a classic "zip bomb"/declared-vs-actual-size decoupling), exactly analogous to a client sending a small `Content-Length` while streaming a larger body.

The subsequent `entry.async("string")` call fully materializes the inflated payload into memory and then `JSON.parse`s it, so the entire mismatch-sized payload is processed before any other length check applies. No independent post-inflation size check exists between decompression and `JSON.parse`/further processing.

### Impact Explanation
This function is reachable by any counterparty who can hand the wallet user a "textcoin"/private-payment claim file (e.g. sent as an attachment or a claim link processed by `handlePrivatePaymentFile`), i.e. an unprivileged private-payment counterparty controls the archive contents. By crafting a zip whose header declares a tiny `uncompressedSize` but whose compressed stream inflates far beyond 100MB, the attacker bypasses the intended cap, forcing the victim wallet to allocate and process an arbitrarily large in-memory string/JSON document. This causes excessive CPU/memory consumption on the victim's node (denial-of-service/resource-exhaustion against the wallet process), consistent with the "increased per-request resource usage" impact class described in the analog advisory.

### Likelihood Explanation
Likelihood is moderate: the attacker needs the victim to open/import a crafted zip (textcoin file) supplied by the attacker, which is a normal part of the textcoin/private-payment claim flow and does not require any special privilege, key compromise, or malicious node/hub position — a simple crafted file is sufficient to defeat the declared 100MB guard.

### Recommendation
Do not rely on the zip container's self-reported `uncompressedSize`. Enforce the size limit against the number of bytes actually produced by decompression, e.g. by streaming the inflate operation and aborting once a byte counter exceeds the limit, or by re-checking `data.length` (post-`entry.async("string")`) against the cap before calling `JSON.parse`, and rejecting/discarding the buffer if it is exceeded rather than trusting the pre-inflation header field.

### Proof of Concept
1. Craft a zip archive containing an entry named `private_textcoin` whose local file header declares `uncompressed_size` just under `100 * 1024 * 1024` bytes (e.g. 90MB) but whose DEFLATE-compressed stream actually decompresses to several hundred MB or more (standard zip-bomb construction: e.g. many repeats of the same highly-compressible pattern with a size field manually altered, or a nested-deflate trick if the parser recomputes the field after inflate — the key point is that JSZip trusts the header value it reads without independently verifying it against the real inflate output before the check at `wallet.js:2895`).
2. Deliver this file to the victim as a textcoin claim file (via chat attachment / claim link that ultimately calls `handlePrivatePaymentFile`).
3. The check `entry._data.uncompressedSize > 100 * 1024 * 1024` passes because it inspects the (falsified) header value.
4. `entry.async("string")` fully inflates the true, much larger payload into memory, which is then `JSON.parse`d, consuming disproportionate CPU/memory on the victim's wallet process — bypassing the intended 100MB cap.

### Citations

**File:** wallet.js (L2883-2897)
```javascript
function handlePrivatePaymentFile(fullPath, content, cb) {
	var bCordova = (typeof window === 'object' && window.cordova);
	var JSZip = require("jszip");
	var zip = new JSZip();

	var unzip = function(err, data) {
		if (err)
			return cb(err);
		zip.loadAsync(data).then(function(zip) {
			const entry = zip.file("private_textcoin");
			if (!entry)
				return cb("missing private_textcoin entry in zip");
			if (entry._data && entry._data.uncompressedSize > 100 * 1024 * 1024)
				return cb("private_textcoin entry is too large");
			entry.async("string").then(function(data) {
```
