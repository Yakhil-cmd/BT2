### Title
Uncontrolled Zip Expansion in Private-Payment Textcoin Import Allows Memory-Exhaustion DoS - (File: wallet.js)

### Summary
`handlePrivatePaymentFile` in `wallet.js` decompresses a ZIP archive supplied by an untrusted counterparty (the sender of a private-payment "textcoin" recovery file) and only guards against oversized payloads by checking the ZIP entry's *declared* `uncompressedSize` metadata field before calling `entry.async("string")`. This metadata is attacker-controlled and is not verified against the amount of data actually produced during DEFLATE expansion, mirroring the root cause of CVE-2024-55909 (archive expansion without controlling resource consumption).

### Finding Description
`handlePrivatePaymentFile(fullPath, content, cb)` loads a JSZip archive from a file (or in-memory buffer) that a private-payment counterparty can hand to a victim as part of the textcoin/private-asset recovery flow (produced by `storePrivateAssetPayload`, which zips the `private_textcoin` JSON entry with DEFLATE level 9): [1](#0-0) 

The only size guard is:
```
if (entry._data && entry._data.uncompressedSize > 100 * 1024 * 1024)
    return cb("private_textcoin entry is too large");
```
This value is read from the ZIP local/central directory header of the attacker-supplied file — it is not derived from, or enforced against, the number of bytes actually emitted by the DEFLATE decoder. A malicious archive can declare an arbitrarily small `uncompressedSize` (passing the check) while its compressed stream expands to a much larger payload once `entry.async("string")` performs the actual inflate. Because there is no streaming byte-count cap during expansion itself, the wallet process will allocate memory for the full decompressed content regardless of the declared header value, exactly the "expansion of archive files without controlling resource consumption" pattern described in CVE-2024-55909.

### Impact Explanation
A crafted private-payment zip (e.g., attached to a textcoin transfer or sent as a "private payload file" between private-payment counterparties) can cause the receiving wallet to exhaust memory/CPU while decompressing the `private_textcoin` entry, crashing or freezing the wallet process. This is a denial-of-service against the recipient's wallet triggered purely by importing a file from an untrusted private-payment counterparty, without any privileged access.

### Likelihood Explanation
Exploitation requires only that a victim import a maliciously crafted private-payment/textcoin zip file — a normal, expected interaction for the private-payment recovery feature. The attacker fully controls the zip's compressed content and header metadata, so bypassing the 100MB *declared*-size check while still causing multi-gigabyte in-memory expansion is straightforward with standard zip-bomb construction techniques (nested/highly repetitive DEFLATE streams).

### Recommendation
Enforce the size limit during actual decompression (streaming inflate with a hard byte-count cutoff that aborts as soon as the limit is exceeded) rather than trusting the ZIP header's `uncompressedSize` field. Additionally validate compression ratio and reject archives whose actual expansion exceeds a sane multiple of the compressed size.

### Proof of Concept
1. Craft a ZIP archive containing a single entry named `private_textcoin` whose local file header declares `uncompressedSize` just under 100MB (e.g., 1KB) but whose DEFLATE stream is a compression bomb that inflates to several GB (standard zip-bomb construction, e.g. overlapping/repeated compressed blocks).
2. Deliver this file to a victim wallet as a private-payment/textcoin recovery file.
3. Victim calls `handlePrivatePaymentFile(fullPath, content, cb)` → the size guard at `wallet.js:2895` passes because the header claims a small size.
4. `entry.async("string")` at `wallet.js:2897` performs full inflate of the bomb, consuming excessive memory/CPU and causing the wallet process to crash or hang.

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
