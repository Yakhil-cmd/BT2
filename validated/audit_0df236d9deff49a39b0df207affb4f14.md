### Title
Zip-bomb DoS via unvalidated `uncompressedSize` check in private-payment/textcoin file handling - (File: wallet.js)

### Summary
`handlePrivatePaymentFile()` in `wallet.js` attempts to bound decompression memory by checking `entry._data.uncompressedSize` before calling `entry.async("string")` on a JSZip entry, but the guard relies on an internal, undocumented JSZip field that is not guaranteed to be populated for every zip encoding path, mirroring the root cause of CVE-2017-7609 (elfutils' `elf_compress.c` failing to validate/bound the declared decompression size before allocating memory for a crafted compressed stream).

### Finding Description
`storePrivateAssetPayload`/`handlePrivatePaymentFile` in `wallet.js` builds and consumes a DEFLATE-compressed zip file that carries a private-payment chain (`private_textcoin` entry containing `mnemonic` and `chains`) exchanged between private-payment counterparties/devices: [1](#0-0) 
The size guard is:
```
if (entry._data && entry._data.uncompressedSize > 100 * 1024 * 1024)
    return cb("private_textcoin entry is too large");
```
This only rejects an oversized entry when `entry._data` is truthy and populated. `entry._data` is JSZip's private/internal representation of the compressed object; it is not part of the public API contract and is not guaranteed to be filled in for all supported input encodings/paths (e.g., depending on how the zip was loaded/streamed or which JSZip version/compression method is used). If `entry._data` is `undefined` or lacks `uncompressedSize`, the `if` condition short-circuits to false and the check is silently skipped, after which `entry.async("string")` unconditionally decompresses the entry into memory with no fallback size limit.

This is structurally the same defect class as CVE-2017-7609: the code trusts an attacker-supplied/derivable "declared size" field from the compressed container format to gate decompression, rather than bounding the actual decompression output as data is produced (e.g., streaming with a hard byte cap). An attacker who crafts a zip file that avoids populating the internal `_data.uncompressedSize` field (or that reports a small value inconsistent with the true post-inflation size) causes the size check to be bypassed, and the subsequent full in-memory inflate of a highly-compressed payload can consume unbounded memory.

### Impact Explanation
This path is reachable from `handlePrivatePaymentFile`, which is invoked when a wallet/light node processes a private-payment/textcoin zip payload received from a private-payment counterparty (a party who can freely construct a crafted zip and hand it to a victim via the textcoin/private-payment claiming flow). A successful bypass of the 100 MB guard lets an attacker force decompression of an attacker-chosen (effectively unbounded) amount of data into memory in a single call, causing memory exhaustion / crash of the wallet process — a denial of service consistent with the "node unable to confirm new units" / availability-loss class explicitly in scope, without requiring any special network position, hub cooperation, or elevated privilege.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to control the zip's internal encoding such that JSZip's `_data.uncompressedSize` metadata is absent/zero for the crafted entry (achievable by choosing an encoding/loading path that doesn't populate that private field, since it's not validated against the format's own central-directory/local-header size fields, and JSZip does not officially guarantee it is always set). No signature checks or trust relationship is required beyond the normal act of one private-payment/textcoin counterparty sending a file/message to another, which is an unprivileged action explicitly in scope.

### Recommendation
Do not rely on JSZip's private `_data.uncompressedSize` to bound decompression. Instead, enforce an authoritative pre-check using the zip's official metadata (e.g., `entry.uncompressedSize` if consistently populated by the parsing library, or the central directory record) and, more robustly, stream-decompress with a hard cumulative byte cap (abort as soon as decompressed bytes exceed the 100 MB limit) regardless of what any header field claims, so a crafted zip cannot bypass the size check by omitting or lying about pre-decompression metadata.

### Proof of Concept
1. Construct a zip archive containing an entry named `private_textcoin` whose actual (post-inflation) content exceeds several hundred MB, but pack it so that JSZip's internal `_data.uncompressedSize` for that entry is `undefined` (e.g. by using a streaming/data-descriptor zip encoding path not fully populating that internal metadata) — this can be validated empirically against the target JSZip version in use.
2. Deliver this file as the private-payment/textcoin package to a victim wallet through the normal `handlePrivatePaymentFile` intake path (private-payment counterparty flow).
3. Observe that the `if (entry._data && entry._data.uncompressedSize > 100 * 1024 * 1024)` guard evaluates false and is skipped.
4. `entry.async("string")` proceeds to fully inflate the crafted entry into memory, consuming resources proportional to the attacker-chosen decompressed size and causing memory exhaustion / process crash on the victim's node. [1](#0-0)

### Citations

**File:** wallet.js (L2883-2896)
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
```
