### Title
Memory-amplification DoS via ZIP decompression bomb in private textcoin payment import - (File: wallet.js)

### Summary
`handlePrivatePaymentFile()` in `wallet.js` unzips an attacker-supplied "textcoin" package before parsing its private-payment chains. The size guard it uses only inspects the ZIP entry's declared metadata field (`entry._data.uncompressedSize`) rather than enforcing a limit during the actual inflate/decompression operation, mirroring the ion-java GZIP bomb pattern where a crafted compressed document expands to an arbitrarily large size upon decompression because the decompression path trusts declared/limited pre-decompression signals instead of bounding the real output stream.

### Finding Description
`handlePrivatePaymentFile(fullPath, content, cb)` loads a ZIP file (received as a "textcoin"/private payment package from any private-payment counterparty) with `JSZip`: [1](#0-0) 

The only safeguard against a decompression bomb is:
```js
if (entry._data && entry._data.uncompressedSize > 100 * 1024 * 1024)
    return cb("private_textcoin entry is too large");
entry.async("string").then(...)
```
`entry._data.uncompressedSize` is populated from the ZIP local/central-directory header field that the file's author controls when constructing the archive — it is metadata, not a verified measurement of what the DEFLATE stream will actually expand to when `entry.async("string")` runs. An attacker can craft a ZIP entry whose header declares a small (or falsified) `uncompressedSize` while the underlying compressed bytes represent (or, via crafted/overlapping deflate blocks, expand to) a stream that decompresses to a size far larger than what the header states. Since the size check is performed against this untrusted header value and not against the amount of data actually produced during `entry.async("string")`, the guard can be bypassed while the real decompression call still inflates unboundedly into memory, exactly analogous to the ion-java flaw where the auto-decompression handler didn't cap actual expansion during decompression.

Once decompressed, the resulting string is `JSON.parse`'d and fed into `handlePrivatePaymentChains`, so the entire decompression + parse happens before any further validation of the private chain content: [2](#0-1) 

This textcoin/private-payment file flow is reachable by any unprivileged private-payment counterparty: it is invoked whenever a wallet imports a received private payment file, e.g. from `storePrivateAssetPayload`/import handlers that call `handlePrivatePaymentFile`: [3](#0-2) 

### Impact Explanation
A malicious counterparty who sends a specially-crafted private-payment/textcoin ZIP file can cause the recipient wallet process to attempt to allocate an arbitrarily large in-memory string during `entry.async("string")`, exhausting heap memory and crashing or hanging the wallet process (denial of service). Because the size check relies on attacker-controlled ZIP metadata rather than a hard cap enforced during actual decompression, the 100MB guard provides no real protection against a bomb where the header lies about size. This is a client-side, unprivileged-input-triggered memory-amplification DoS matching the CVE-2026-75936 bug class (decompression handler trusting pre-expansion signals instead of bounding real output).

### Likelihood Explanation
Likelihood is high for any user who imports/receives textcoin files from untrusted senders: no authentication, signature check, or privileged capability is required to construct and deliver such a file; the only prerequisite is convincing (or automatically causing) the victim's wallet to call `handlePrivatePaymentFile` on the attacker's ZIP, which is the intended, unprivileged flow for redeeming/importing textcoins.

### Recommendation
Do not rely on the ZIP entry's declared `uncompressedSize` metadata as the sole size guard. Enforce a hard limit on the actual bytes produced during decompression — e.g., stream the entry via `entry.internalStream` / `entry.nodeStream()` and abort once the number of decompressed bytes exceeds the limit (100 MB or a smaller sane bound), rather than trusting the header value before calling `entry.async("string")`. Alternatively, use a JSZip/zlib configuration that enforces a maximum output size at the decompression layer itself.

### Proof of Concept
1. Construct a ZIP archive containing an entry named `private_textcoin` whose local file header declares `uncompressedSize` ≤ 100 MB (or a value that passes the check), but whose actual DEFLATE-compressed payload, when inflated, expands to several GB (a standard "zip bomb" construction, e.g. highly repetitive data compressed at a high ratio, with the header size field forged/mismatched from the true expansion).
2. Deliver this archive to a victim as a textcoin file / private-payment package (e.g., via the normal claim/import flow that calls `handlePrivatePaymentFile(fullPath, content, cb)`).
3. When the victim's wallet processes the file, `zip.loadAsync(data)` succeeds, the size check on `entry._data.uncompressedSize` passes (using the forged header value), and `entry.async("string")` decompresses the full multi-GB payload into memory, exhausting the process's memory and crashing/hanging the wallet.

### Citations

**File:** wallet.js (L2850-2881)
```javascript
function storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, chains, cb) {
	var storedObj = {
		mnemonic: mnemonic,
		chains: chains
	};
	var bCordova = (typeof window === 'object' && window.cordova);
	var JSZip = require("jszip");
	var zip = new JSZip();
	zip.file('private_textcoin', JSON.stringify(storedObj));
	var zipParams = {type: "nodebuffer", compression: 'DEFLATE', compressionOptions: {level: 9}};
	zip.generateAsync(zipParams).then(function(zipFile) {
		if (!bCordova) {
			var fs = require('fs');
			fs.writeFile(fullPath, zipFile, cb);
		} else {
			window.requestFileSystem(LocalFileSystem.TEMPORARY, 0, function(fs) {
				window.resolveLocalFileSystemURL(cordovaPathObj.root, function(dirEntry) {
					dirEntry.getDirectory(cordovaPathObj.path, {create: true, exclusive: false}, function(dirEntry1) {
						dirEntry1.getFile(cordovaPathObj.fileName, {create: true, exclusive: false}, function(file) {
							file.createWriter(function(writer) {
								writer.onwriteend = function() {
									cb(null); 
								};
								writer.write(zipFile.buffer);
							}, cb);
						}, cb);
					}, cb);
				}, cb);
			}, cb);
		}
	}, cb);
}
```

**File:** wallet.js (L2883-2916)
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
				device.getHubWs(function(err, ws){
					if (err)
						return cb("no hub connection, try again later:" + err);
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
					// for light wallets request history for mnemonic address, check if already spent
```
