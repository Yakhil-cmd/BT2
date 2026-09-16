### Title
Zip bomb DoS via unbounded decompression in private-payment/textcoin file handling - (File: wallet.js)

### Summary
`wallet.js`'s `handlePrivatePaymentFile()` accepts an attacker-supplied ZIP archive (a "private payment" / textcoin file that a private-payment counterparty can hand to a victim wallet) and decompresses its `private_textcoin` entry with JSZip before doing any real bound on the actual decompression work, mirroring the cpp-httplib CVE-2026-22776 pattern of trusting a size value instead of limiting the actual decompressed bytes produced.

### Finding Description
`handlePrivatePaymentFile()` loads the archive with `JSZip` and only guards against oversized payloads by checking metadata: [1](#0-0) 
The check `entry._data.uncompressedSize > 100 * 1024 * 1024` inspects the **declared** uncompressed size taken from the ZIP's local/central-directory metadata, which is attacker-controlled and independent of the actual compressed byte stream that will be inflated. A crafted archive can under-declare `uncompressedSize` (or otherwise structure the deflate stream) while `entry.async("string")` still performs full decompression into memory: [2](#0-1) 
This is exactly the bug class in the report: the library validates a stated/observed size (there, the compressed request size against `payload_max_length`; here, the metadata-declared uncompressed size) but does not bound the actual memory consumed while inflating the data. `zip.loadAsync()` and `entry.async()` happen unconditionally before the untrusted `uncompressedSize` field can be considered trustworthy proof of resulting memory footprint.

The file is reachable without any special privilege: `handlePrivatePaymentFile()` is invoked with `content` supplied directly (in addition to the local file-path variant) [3](#0-2) , and the wallet's private-payment/textcoin flow is a mechanism explicitly designed to let a counterparty hand a payment artifact to another wallet for automatic processing (`onDone()` calls `handlePrivatePaymentChains`) [4](#0-3) .

### Impact Explanation
A malicious private-payment counterparty can send a specially crafted ZIP ("textcoin"/private-payment file) whose declared metadata is small but whose actual inflated content is enormous (classic zip bomb), causing the victim wallet process to allocate excessive memory during `entry.async("string")`, leading to memory exhaustion and process crash/hang — a denial of service against the wallet that is processing incoming private payments. This matches the "AA fund loss or freezing / node unable to confirm new units" style impact only insofar as it can crash/disable the wallet handling private payment claims; it does not enable double-spend or supply inflation.

### Likelihood Explanation
Medium. Exploitation requires the victim to open/process a crafted `private_textcoin` file from an untrusted counterparty (e.g., via a textcoin sharing flow), which is a normal, expected interaction pattern in this feature, making it plausible but requiring some social engineering / file delivery vector.

### Recommendation
Do not rely on the ZIP metadata `uncompressedSize` field alone. Enforce an actual streaming size cap while decompressing (e.g., use a streaming inflate API and abort once a fixed byte threshold, such as 100 MB, is exceeded regardless of the declared header value), or otherwise bound total memory/time spent in `entry.async()` independent of attacker-supplied metadata, consistent with the upstream cpp-httplib fix that limits decompressed output size dynamically during decompression rather than trusting a pre-declared value.

### Proof of Concept
1. Craft a malicious ZIP file containing an entry named `private_textcoin` whose local/central-directory header declares a small `uncompressedSize` (e.g., under 100 MB) but whose deflate stream actually expands to a very large size (a classic "zip bomb", e.g., nested/highly repetitive compressed data expanding to gigabytes).
2. Deliver this file to a victim wallet through the private-payment/textcoin sharing flow so that `handlePrivatePaymentFile(fullPath, content, cb)` is invoked with the crafted bytes as `content`.
3. `zip.loadAsync(data)` and the subsequent `entry.async("string")` call in `wallet.js` (around lines 2891–2901) decompress the entry fully into memory before any content is parsed as JSON, since the guard only inspects the untrustworthy declared `uncompressedSize`, not the true decompressed length. Because the declared size is below the 100 MB threshold, the check passes, and the wallet process attempts to materialize the full (attacker-controlled, arbitrarily large) decompressed buffer, exhausting memory and crashing/hanging the wallet process. [5](#0-4)

### Citations

**File:** wallet.js (L2883-2901)
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
				try {
					data = JSON.parse(data);
					var first_chain_unit = data.chains[0][0].unit;
				} catch (err) {return cb(err);}
```

**File:** wallet.js (L2905-2915)
```javascript
					eventBus.once('all_private_payments_handled-' + first_chain_unit, function(){
						cb(null, data);
					});
					var onDone = function() {
						handlePrivatePaymentChains(ws, data, null, {
							ifError: function(err){
								cb(err);
							},
							ifOk: function(){} // we subscribe to event, not waiting for callback
						});
					}
```

**File:** wallet.js (L2950-2954)
```javascript
	
	if (content) {
		unzip(null, content);
		return;
	}
```
