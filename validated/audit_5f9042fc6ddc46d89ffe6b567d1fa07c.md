### Title
Textcoin private payload file (`storePrivateAssetPayload`) is written world-readable, letting local users steal the bearer funds - (File: `wallet.js`)

### Summary
When a user sends a private-asset "textcoin," `wallet.js` calls `storePrivateAssetPayload()` to persist the bearer secret (the claiming mnemonic plus the private-element chains) to a file that the sender is expected to hand to the recipient out of band. On non-Cordova platforms the file is written with plain `fs.writeFile(fullPath, zipFile, cb)`, with no explicit file mode set, so the resulting file inherits the process's default umask (commonly `0644`, world-readable) rather than a restrictive mode. This is the same root-cause class as CVE-2017-9868 (Mosquitto's `mosquitto.db` persistence file being world-readable and exposing sensitive topic data to any local user) — a sensitive local artifact is persisted without owner-only permissions.

### Finding Description
`storePrivateAssetPayload` builds a ZIP containing `{ mnemonic, chains }` — the mnemonic that derives the claiming address and the full chain of private elements needed to redeem the asset — and writes it with `fs.writeFile`: [1](#0-0) 

Unlike the sqlite database or rocksdb store, which live inside the app data directory created with an explicit `0700` mode, this file's location (`fullPath`) is supplied by the host application via `opts.getPrivateAssetPayloadSavePath`, and it is very often placed in a location the user can browse to (e.g. Downloads, temp export folder), not inside the `0700` app-data folder: [2](#0-1) 

By contrast, the app data directory itself is deliberately locked down: [3](#0-2) [4](#0-3) 

showing the project's own convention is to restrict access to files holding secrets (mode `0700`/inherits parent). `storePrivateAssetPayload` breaks this convention for the one artifact that is a literal bearer token for funds.

The file's content is sufficient, on its own, to redeem the asset: `handlePrivatePaymentFile` re-derives the claiming address purely from `data.mnemonic` and forwards `data.chains` to the network to complete the claim, with no additional secret required: [5](#0-4) 

### Impact Explanation
The mnemonic + private chains in this file function exactly like a bearer note (comparable to a printed banknote or a giftcard PIN). Any local user (or any process — malware, another account) able to read the file before the legitimate recipient imports it can construct and submit the same claim transaction, redirecting the entire textcoin amount to an address they control. Because it is a private/indivisible asset payment, this is concrete unauthorized spending/theft of value — not merely metadata disclosure — mapping to the "concrete unauthorized spending" impact bucket.

### Likelihood Explanation
This path is reachable by an ordinary wallet user performing a completely normal, supported operation: sending a private-asset textcoin (`sendMultiPayment` → `composeAndSaveIndivisibleAssetPaymentJoint`/divisible path → `storePrivateAssetPayload`), which any unprivileged user of the wallet can trigger. No attacker-controlled input or privileged access is required to create the exposure — only the ambient environment's default umask, which on typical Linux/desktop configurations (`022`) yields a world- or group-readable file. Multi-user shared machines, shared cloud-sync folders, or shared export directories are the realistic exposure vectors, matching the same "any local/other user can read a persisted secret" scenario as the referenced Mosquitto CVE.

### Recommendation
When creating the private-payload file, explicitly restrict its permissions rather than relying on the umask — e.g. pass `{ mode: 0o600 }` to `fs.writeFile`/`fs.open`, or `fs.chmod(fullPath, 0o600, cb)` immediately after writing, mirroring the `0700` convention already used for `desktop_app.getAppDataDir()`-based storage in `kvstore.js` and `sqlite_pool.js`. Additionally, document to consuming apps that `getPrivateAssetPayloadSavePath` should point at a private, non-shared location, and consider encrypting the payload with a passphrase communicated out of band so the file alone is not sufficient to redeem funds.

### Proof of Concept
1. On a multi-user Linux machine with default umask `022`, a wallet user sends a private-asset textcoin using the wallet's textcoin feature (`sendMultiPayment` with a private asset), choosing a save location under a directory other local users can traverse (e.g. `/tmp` or a shared `Downloads`).
2. `storePrivateAssetPayload` writes the zip via `fs.writeFile(fullPath, zipFile, cb)` with no mode argument: [6](#0-5) , resulting in a `0644` file readable by any local user.
3. A second local user reads the file, extracts `mnemonic` and `chains`, and calls the same `handlePrivatePaymentFile` flow (or replicates the underlying `expandMnemonic` + `handlePrivatePaymentChains` calls) to claim the asset to their own address before the intended recipient does, resulting in permanent theft of the transferred funds.

### Citations

**File:** wallet.js (L2409-2424)
```javascript
								else if (Object.keys(assocAddresses).length > 0) {
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
									} else {
										throw Error("no getPrivateAssetPayloadSavePath provided");
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

**File:** wallet.js (L2896-2914)
```javascript
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

**File:** sqlite_pool.js (L456-472)
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
```
