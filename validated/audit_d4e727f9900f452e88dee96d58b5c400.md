### Title
Private textcoin payload files (mnemonic + private payment chain) are written to disk with default (non-restrictive) file permissions - (File: wallet.js)

### Summary
When a user sends a private asset as a "textcoin" via `sendMultiPayment`, the wallet serializes the claim mnemonic and the recipient's private payment chains into a ZIP file and writes it to disk using `fs.writeFile` without ever specifying a restrictive file mode, so the resulting file inherits the process/OS default permissions (governed only by umask).

### Finding Description
For private (non-public) assets, `wallet.js` routes textcoin creation through `storePrivateAssetPayload`, which builds an object containing the plaintext claim `mnemonic` (used to derive/spend the recipient address) and `arrChainsOfRecipientPrivateElements` (the full private payment chain, including amounts and blinding data needed to prove and later spend the private output), zips it, and persists it with: [1](#0-0) 

The call `fs.writeFile(fullPath, zipFile, cb)` at line 2863 passes no `{ mode: 0o600 }` option, so the new file is created with the platform's default mode (typically `0o666` minus umask, e.g. `0o644` on many systems), making it world/group-readable on multi-user hosts. This is invoked from the private-asset send path in `sendMultiPayment`: [2](#0-1) 

Anyone with read access to the same filesystem (another local user, a backup process, a misconfigured cloud-sync agent, etc.) can read this file before the intended recipient does, extract the `mnemonic`, and independently derive the private key material needed to claim/spend the private asset — this mirrors the "transcript containing secrets was created without forced user-only permissions" bug class from the report, but here the secret is spendable private-payment key material rather than a session log.

### Impact Explanation
The `mnemonic` in the textcoin payload is equivalent to a spendable private key for the address holding the private asset output; anyone who reads the file can claim the textcoin ahead of (or instead of) the intended recipient, resulting in outright theft/unauthorized spending of the transferred private-asset value. Because the exposure is purely a file-permission defect (no cryptographic protection on the mnemonic itself), the loss is deterministic once an unprivileged local reader exists — a realistic condition on shared, multi-user hosts or misconfigured backup/sync environments where the wallet's data directory is not exclusively user-owned.

### Likelihood Explanation
Exploitation requires only that another local (unprivileged) actor can read files created by the wallet process — no privileged access, no network position, and no cryptographic breakage is needed. Because `fs.writeFile` is called without an explicit `mode`, the resulting permissions purely depend on umask, which defaults to group/world-readable modes on many common Linux/desktop configurations. Any user who sends a private-asset textcoin and stores it on a shared or backed-up path is exposed.

### Recommendation
Pass an explicit restrictive mode when writing the private-asset payload file, e.g. `fs.writeFile(fullPath, zipFile, { mode: 0o600 }, cb)`, and additionally `fs.chmod`/verify permissions on any pre-existing file at that path before writing, consistent with the remediation pattern used in the referenced advisory (forcing `0o600` on secret-bearing files at creation time).

### Proof of Concept
1. Attacker and victim share a multi-user host (or the victim's textcoin save directory is synced/backed up without permission preservation).
2. Victim sends a private asset as a textcoin: `sendMultiPayment` → private-asset branch → `params.callbacks.preCommitCb` → `storePrivateAssetPayload(fullPath, ...)` at [2](#0-1) .
3. `storePrivateAssetPayload` zips `{mnemonic, chains}` and calls `fs.writeFile(fullPath, zipFile, cb)` with default permissions at [3](#0-2) .
4. Because no restrictive mode was set, the attacker (a co-resident unprivileged user) reads the file directly from disk, extracts `mnemonic`, and calls the equivalent of `receiveTextCoin`/`handlePrivatePaymentFile` to claim the private asset before the legitimate recipient does, resulting in theft of the transferred value.

### Citations

**File:** wallet.js (L2410-2420)
```javascript
									var mnemonic = assocMnemonics[Object.keys(assocMnemonics)[0]]; // TODO: assuming only one textcoin here
									if (typeof opts.getPrivateAssetPayloadSavePath === "function") {
										opts.getPrivateAssetPayloadSavePath(function(fullPath, cordovaPathObj){
											if (!fullPath && (!cordovaPathObj || !cordovaPathObj.fileName)) {
												return cb2("no file path provided for storing private payload");
											}
											storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, function(err) {
												if (err)
													throw Error(err);
												saveMnemonicsPreCommit(conn, objJoint, cb2);
											});
```

**File:** wallet.js (L2850-2863)
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
```
