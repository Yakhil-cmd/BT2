### Title
Private textcoin/asset payload files written with weak default file permissions - (File: wallet.js)

### Summary
`storePrivateAssetPayload()` in `wallet.js` persists the private payment chain and mnemonic for a private-asset/textcoin payment to disk using Node's default `fs.writeFile`, without specifying a restrictive file mode. This mirrors the sosreport bug class (CVE-2015-3171/GHSA-gw46-8559-cggp): a file that must contain sensitive secrets is created with the platform-default, overly permissive mode, exposing it to any other local user on the same machine.

### Finding Description
When a wallet sends a private payment or textcoin to a recipient that is not reachable as a paired device (e.g., payment to a mnemonic-based textcoin address), the `preCommitCb` path in `sendMultiPayment` calls `opts.getPrivateAssetPayloadSavePath` and then `storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, cb)`: [1](#0-0) 

`storePrivateAssetPayload` builds a zip archive containing the plaintext `mnemonic` and the full private-payment `chains` (the amounts, blinding data, and unit chain needed to claim the private funds), then writes it to `fullPath` on non-Cordova (desktop/headless) platforms via a bare `fs.writeFile(fullPath, zipFile, cb)` call with no `mode` option: [2](#0-1) 

Node.js `fs.writeFile` without an explicit `mode` defaults to `0o666` (masked by the process umask, typically resulting in world/group-readable `0644` on Unix systems). Unlike other sensitive on-disk state in this codebase — e.g. the RocksDB app-data directory, which is explicitly created with restrictive `0700` permissions — no such hardening is applied here: [3](#0-2) 

The mnemonic contained in this file is a bearer secret: anyone who obtains it can call `expandMnemonic`/`receiveTextCoin` to derive the private key and sign a claim for the associated private payment or textcoin, exactly as the legitimate recipient would: [4](#0-3) [5](#0-4) 

### Impact Explanation
Any local, unprivileged user with read access to the filesystem location where `fullPath` resides (shared/multi-user hosts, world-readable temp/downloads directories, backup snapshots, etc.) can read the plaintext mnemonic and private payment chain before the intended counterparty claims it, then race to call `receiveTextCoin`/claim the private asset themselves — resulting in concrete theft (unauthorized spending) of the private-payment counterparty's funds. This is a direct confidentiality-to-spending escalation, matching the "concrete unauthorized spending" bar.

### Likelihood Explanation
This code path is exercised by ordinary, unprivileged wallet usage: any user who is the private-payment counterparty (sender) sending a private asset payment or textcoin to a non-paired recipient triggers `storePrivateAssetPayload`. No malicious peer, hub, or elevated privilege is required — only that another local account/process can read the output file due to its default (non-restrictive) permission bits, the same weak-permission condition described in the original sosreport advisory.

### Recommendation
Explicitly set a restrictive mode (e.g., `0o600`) when writing the private payload file, e.g. `fs.writeFile(fullPath, zipFile, { mode: 0o600 }, cb)`, and/or ensure the containing directory is created with `0700` permissions (consistent with the pattern already used in `kvstore.js`). Consider also encrypting the payload contents at rest so that file-permission misconfiguration on the host OS does not directly translate into fund loss.

### Proof of Concept
1. Alice sends a private-asset payment/textcoin to Bob using `sendMultiPayment` with a recipient not represented by a paired device, causing `opts.getPrivateAssetPayloadSavePath`/`storePrivateAssetPayload` to write the mnemonic + private chains to `fullPath` on Alice's (or a shared) machine.
2. Because `fs.writeFile` is called without a `mode`, the resulting file is created with the default `0o666 & ~umask` (commonly `0644`), readable by any other local account.
3. Mallory, a second unprivileged local user/process on the same host (or with access to a shared temp/download directory, backup, or synced folder), reads the file and extracts `mnemonic`.
4. Mallory calls `receiveTextCoin(mnemonic, mallory_address, ...)`, deriving the private key via `expandMnemonic` and broadcasting a valid signed claim before Bob does, stealing the funds.

### Citations

**File:** wallet.js (L2410-2421)
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
										});
```

**File:** wallet.js (L2643-2655)
```javascript
function expandMnemonic(mnemonic) {
	var addrInfo = {};
	mnemonic = mnemonic.toLowerCase().split('-').join(' ');
	if ((mnemonic.split(' ').length % 3 !== 0) || !Mnemonic.isValid(mnemonic)) {
		throw new Error("invalid mnemonic: "+mnemonic);
	}
	mnemonic = new Mnemonic(mnemonic);
	addrInfo.xPrivKey = mnemonic.toHDPrivateKey().derive("m/44'/0'/0'/0/0");
	addrInfo.pubkey = addrInfo.xPrivKey.publicKey.toBuffer().toString("base64");
	addrInfo.definition = ["sig", {"pubkey": addrInfo.pubkey}];
	addrInfo.address = objectHash.getChash160(addrInfo.definition);
	return addrInfo;
}
```

**File:** wallet.js (L2657-2690)
```javascript
function receiveTextCoin(mnemonic, addressTo, signWithLocalPrivateKey, cb) {
	if (arguments.length === 3) {
		cb = signWithLocalPrivateKey;
		signWithLocalPrivateKey = null;
	}
	try {
		var addrInfo = expandMnemonic(mnemonic);
	} catch (e) {
		cb(e.message);
		return;
	}

	// used to pay for the fees from my own address
	const localSigner = signWithLocalPrivateKey ? getSigner({}, [device.getMyDeviceAddress()], signWithLocalPrivateKey) : null;
	
	var signer = {
		readSigningPaths: function(conn, address, handleLengthsBySigningPaths){ // returns assoc array signing_path => length
			if (address !== addrInfo.address)
				return localSigner.readSigningPaths(conn, address, handleLengthsBySigningPaths);
			var assocLengthsBySigningPaths = {};
			assocLengthsBySigningPaths["r"] = constants.SIG_LENGTH;
			handleLengthsBySigningPaths(assocLengthsBySigningPaths);
		},
		readDefinition: function(conn, address, handleDefinition){
			if (address !== addrInfo.address)
				return localSigner.readDefinition(conn, address, handleDefinition);
			handleDefinition(null, addrInfo.definition);
		},
		sign: function(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature){
			if (address !== addrInfo.address)
				return localSigner.sign(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature);
			handleSignature(null, ecdsaSig.sign(objectHash.getUnitHashToSign(objUnsignedUnit), addrInfo.xPrivKey.privateKey.bn.toBuffer({size:32})));
		}
	};
```

**File:** wallet.js (L2850-2864)
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
```

**File:** kvstore.js (L8-16)
```javascript
try{
	fs.statSync(app_data_dir);
}
catch(e){
	var mode = parseInt('700', 8);
	var parent_dir = require('path').dirname(app_data_dir);
	try { fs.mkdirSync(parent_dir, mode); } catch(e){}
	try { fs.mkdirSync(app_data_dir, mode); } catch(e){}
}
```
