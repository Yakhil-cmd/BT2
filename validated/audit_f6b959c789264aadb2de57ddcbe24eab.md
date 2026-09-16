### Title
Private Textcoin Payload File Written With Default Insecure Permissions Discloses Wallet-Draining Mnemonic - (File: `wallet.js`)

### Summary
`storePrivateAssetPayload()` in `wallet.js` persists the mnemonic (private key) and private-chain data for a private-asset textcoin to disk using `fs.writeFile()` without specifying a restrictive file mode, so the file inherits the process's default permissions (`0666` minus the current `umask`). Any other local user/process on the same machine can read this file while it exists and obtain the mnemonic, giving them full spending control over the sent private-asset funds — directly analogous to CVE-2023-38037, where `ActiveSupport::EncryptedFile` wrote sensitive content to a temp file with default, unrestricted umask-derived permissions.

### Finding Description
When a user sends a private asset as a "textcoin" to a generated address (instead of an existing recipient device), `sendMultiPayment()` sets `params.callbacks.preCommitCb` to call `opts.getPrivateAssetPayloadSavePath`, and once a path is obtained, invokes `storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, cb)`: [1](#0-0) 

```js
function storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, chains, cb) {
	var storedObj = {
		mnemonic: mnemonic,
		chains: chains
	};
	...
	zip.generateAsync(zipParams).then(function(zipFile) {
		if (!bCordova) {
			var fs = require('fs');
			fs.writeFile(fullPath, zipFile, cb);
``` [2](#0-1) 

The `mnemonic` here is the exact same value used elsewhere to derive the sending/spending private key for the funded textcoin address: [3](#0-2) 

`fs.writeFile(fullPath, zipFile, cb)` is called with no `{ mode: 0o600 }` option, so Node creates the file with the default mode `0666`, filtered only by the process umask (commonly `022`, yielding world- and group-readable `0644`). This is the same root cause as CVE-2023-38037: sensitive material is written to a filesystem path relying on the ambient umask for confidentiality instead of an explicit restrictive mode, and it is not deleted or overwritten immediately (`cb` merely continues the payment flow via `saveMnemonicsPreCommit`).

Contrast this with other file/database creation in the same codebase that explicitly hardens permissions, showing the project is aware of this class of issue but did not apply it here: [4](#0-3) [5](#0-4) 

### Impact Explanation
The private-textcoin payload file contains the mnemonic that is the sole authenticator for the private-asset address (`addrInfo.address` derived from it, with `["sig", {"pubkey": ...}]` definition). Anyone able to read the file — any other local account, another app on a shared/multi-user desktop, or a background process with generic read access — obtains the private key material and can immediately claim/spend the private-asset funds themselves via the same `receiveTextCoin`/`expandMnemonic` path, before or instead of the intended recipient: [6](#0-5) 

This is concrete unauthorized spending / theft of funds that were meant for the recipient — matching the required impact bar (unauthorized spending). It is reachable purely by the wallet's own private-payment counterparty flow (sending a private asset as a textcoin), with no reliance on a malicious peer, hub, or node.

### Likelihood Explanation
Exploitation requires local file-system access on the sender's machine at the time the payload file exists (same precondition/CVSS profile — AV:L — as the original advisory). On typical desktop/server umask settings (`022`), the resulting file is world-readable, so any co-located process/user can read it without needing elevated privileges. Because private-asset/textcoin transfers explicitly go through this file-based path (as opposed to direct device-to-device delivery), this is a normal, attacker-reachable feature path rather than an edge case.

### Recommendation
When writing `storePrivateAssetPayload`'s output (and any other file containing mnemonics/private key material), explicitly set restrictive permissions, e.g. `fs.writeFile(fullPath, zipFile, { mode: 0o600 }, cb)`, and ensure the containing directory is not world-readable/writable. Consider also encrypting the payload at rest and deleting/overwriting it promptly once the transfer completes.

### Proof of Concept
1. On a multi-user machine (or with another local process able to read files with default permissions), start an Obyte wallet and send a private asset as a "textcoin" to a new address, supplying `opts.getPrivateAssetPayloadSavePath` to save the payload to a path such as `/tmp/textcoin.zip`.
2. Observe that `storePrivateAssetPayload()` calls `fs.writeFile(fullPath, zipFile, cb)` in `wallet.js:2863` with no mode argument, so the file is created with mode `0666 & ~umask` (e.g., `0644` under the common `022` umask).
3. From a second local OS account (or any process with generic file read permission), read `/tmp/textcoin.zip`, unzip it, and parse the `private_textcoin` JSON entry to recover `mnemonic` and `chains`.
4. Call `expandMnemonic(mnemonic)` to derive `addrInfo.address`/`xPrivKey`, then invoke `receiveTextCoin(mnemonic, attacker_address, cb)` to claim the funds before the intended recipient does — demonstrating unauthorized spending enabled purely by the insecure default file permissions.

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

**File:** wallet.js (L2643-2654)
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
```

**File:** wallet.js (L2657-2689)
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

**File:** sqlite_pool.js (L456-474)
```javascript
	else{ // copy initial db to app folder
		var fs = require('fs');
		fs.stat(path + db_name, function(err, stats){
			console.log("stat "+err);
			if (!err) // already exists
				return onDbReady();
			console.log("will copy initial db");
			var mode = parseInt('700', 8);
			var parent_dir = require('path').dirname(path);
			fs.mkdir(parent_dir, mode, function(err){
				console.log('mkdir '+parent_dir+': '+err);
				fs.mkdir(path, mode, function(err){
					console.log('mkdir '+path+': '+err);
				//	fs.createReadStream(__dirname + '/initial-db/' + initial_db_filename).pipe(fs.createWriteStream(path + db_name)).on('finish', onDbReady);
					fs.writeFileSync(path + db_name, fs.readFileSync(__dirname + '/initial-db/' + initial_db_filename));
					onDbReady();
				});
			});
		});
```
