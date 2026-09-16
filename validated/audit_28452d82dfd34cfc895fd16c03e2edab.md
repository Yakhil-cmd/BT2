### Title
Unencrypted persistence of textcoin mnemonic (private key) and private payment chain to the filesystem - (File: wallet.js)

### Summary
When a user sends a private or fixed-denomination asset to a "textcoin" address (an address derived from a freshly generated mnemonic, used for off-chain/offline transfer of funds), `storePrivateAssetPayload` in `wallet.js` serializes the mnemonic — which is the seed for the private key controlling the recipient address — together with the private payment chain into a ZIP archive and writes it to disk with no encryption, only DEFLATE compression. [1](#0-0) 

### Finding Description
`storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, chains, cb)` builds an object containing the raw `mnemonic` and the `chains` (the private payment chain elements, including blinding factors and amounts) and zips it with `JSZip`/DEFLATE only — there is no call to any cipher or key-derivation function before `zip.generateAsync` and `fs.writeFile(fullPath, zipFile, cb)` (or the Cordova file-write branch). [2](#0-1) 

This function is reached directly from the normal, unprivileged private-payment/textcoin flow in `sendMultiPayment`: when a caller sends a private asset to a `textcoin:`-prefixed pseudo-address (any wallet user composing a payment can do this) and provides `opts.getPrivateAssetPayloadSavePath`, the resulting recipient private chain and the textcoin mnemonic are written to the returned path via `storePrivateAssetPayload` inside the `preCommitCb` of the payment composer. [3](#0-2) 

The mnemonic is exactly the secret used later to reconstruct the spending key: `expandMnemonic` derives an HD private key (`m/44'/0'/0'/0/0`) from the mnemonic and uses `xPrivKey.privateKey` to sign transactions claiming the textcoin funds. [4](#0-3) [5](#0-4) 

Thus the plaintext file written by `storePrivateAssetPayload` is functionally equivalent to an unencrypted `wallet.dat`: possession of the file alone (independent of the recipient device, hub, or any password) is sufficient to derive the private key and spend the funds, matching the reported bug class of "wallet secrets persisted unencrypted on the filesystem."

### Impact Explanation
Anyone who obtains this file before it reaches (or in addition to) the intended recipient — e.g., through shared storage, backup sync, cloud upload, a lost/stolen device, or interception of the file transfer channel the sender chooses to use — can extract the mnemonic and directly spend/steal the associated private-asset/indivisible-asset funds sent as a textcoin. This is a real unauthorized-spending / fund-theft path reachable from a normal wallet-message/private-payment feature, not a privileged/operator/node compromise scenario.

### Likelihood Explanation
The write path is triggered by ordinary application logic (`sendMultiPayment` composing a private-asset or fixed-denomination-asset payment to a `textcoin:` output) rather than by any attacker-controlled malicious input; the vulnerability is a design/implementation flaw (missing encryption before persistence) that is deterministically triggered whenever this legitimate feature is used, so likelihood of exposure depends only on normal usage and file handling, not on exploiting a hard-to-reach edge case.

### Recommendation
Encrypt the serialized payload (mnemonic + private chains) with a symmetric cipher (e.g., AES-GCM) using a key derived from a user-supplied passphrase or device-bound secret before writing it to disk in `storePrivateAssetPayload`, and correspondingly decrypt it in `handlePrivatePaymentFile` before parsing. At minimum, never persist the raw mnemonic to a file; require immediate transfer/consumption or protect it with authenticated encryption at rest.

### Proof of Concept
1. Call `wallet.sendMultiPayment` with an `asset_outputs`/`base_outputs` entry whose address is `"textcoin:" + <email or unused identifier>` for a private or fixed-denomination asset, and supply `opts.getPrivateAssetPayloadSavePath` returning a filesystem path.
2. Observe that `sendMultiPayment`'s `preCommitCb` invokes `storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, cb)`. [6](#0-5) 
3. Inspect the produced ZIP file at `fullPath`: it contains a JSON object `{mnemonic, chains}` compressed but not encrypted. [7](#0-6) 
4. Any party who reads this file can call `expandMnemonic(mnemonic)` to derive the private key and definition of the recipient address and sign a transaction moving the funds elsewhere, without ever needing the intended recipient's hub/device credentials. [8](#0-7)

### Citations

**File:** wallet.js (L2405-2422)
```javascript
							var sendToRecipients = function(cb2){
								if (recipient_device_address) {
									walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2);
								} 
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
```

**File:** wallet.js (L2643-2690)
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

**File:** wallet.js (L2850-2880)
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
```
