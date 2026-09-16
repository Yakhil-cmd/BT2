## #Vulnerability found

### Title
Plaintext device-message logging exposes textcoin mnemonics and private-payment secrets via application logs - (File: device.js)

### Summary
`device.js` logs the full plaintext content of every outgoing and incoming device message via `console.log`, both before encryption (sender side) and after decryption (receiver side). Device messages routinely carry bearer-style secrets — most notably textcoin mnemonics, which function as private keys that let anyone in possession of them claim funds — as well as private-payment chain data (blinding factors, addresses). Persisting this plaintext to logs (stdout, journald, log aggregators, crash reporters, etc., which is standard practice for long-running wallet/hub processes) is a direct analog of CWE-532 Information Exposure Through Log Files described in the cordova-android advisory: sensitive data that should stay confined to the application is written to a persistent, often broader-access log store.

### Finding Description
On the sending path, `reliablySendPreparedMessageToHub` logs the entire plaintext JSON payload before it is encrypted for the recipient: [1](#0-0) 

That `json` payload is exactly what `sendMessageToHub`/`sendMessageToDevice` construct from arbitrary `subject`/`body` content: [2](#0-1) 

On the receiving path, `decryptPackage` logs the fully decrypted message content in plaintext, after successfully decrypting a device message sent by a correspondent (or replayed via a compromised hub): [3](#0-2) 

The device-message channel is exactly the transport used to move textcoin mnemonics and private-payment chains between wallets. Textcoin mnemonics are bearer private keys — anyone holding one can spend the coin directly, without any other authorization, via `expandMnemonic`/`receiveTextCoin`: [4](#0-3) [5](#0-4) 

Mnemonics generated for textcoin outputs are also logged in plaintext elsewhere, e.g. when claiming back stale unclaimed textcoins: [6](#0-5) 

And private-payment chain payloads (which include per-output blinding factors) are logged in plaintext when saved: [7](#0-6) [8](#0-7) 

None of this logging is gated behind a debug flag; it runs unconditionally in normal wallet/hub operation whenever a device message is sent or received, or a private payment chain / textcoin mnemonic is processed.

### Impact Explanation
Any process or party with read access to the application's logs (log aggregation services, crash-reporting integrations, shared hosting, container log drivers, or any log-retention pipeline commonly attached to Node.js services) can recover textcoin mnemonics and private-payment blinding factors straight from the log stream — without ever compromising the wallet's database, private keys, or requiring any special privilege beyond log access. Because a textcoin mnemonic is itself a spendable secret (equivalent to holding the private key for that address), an attacker who reads it from logs can call `receiveTextCoin`/`expandMnemonic` and claim the funds before the intended recipient, resulting in concrete unauthorized spending / theft of funds. Exposure of private-payment blinding factors additionally undermines the confidentiality guarantees of private-asset transfers.

### Likelihood Explanation
The logging occurs unconditionally on the hot path of every device message send/receive and every private-chain save — it requires no attacker action beyond normal use of the wallet's chat/textcoin/private-payment features (sending a textcoin over chat, receiving a private payment notification, etc.), and log capture is the default behavior of essentially all production Node.js deployment environments (PM2, Docker, systemd/journald, PaaS platforms). This makes the exposure highly likely to occur in any real-world deployment that retains stdout/stderr logs, and it is reachable purely from actions an ordinary user or paired device performs.

### Recommendation
Remove or gate all `console.log` statements in `device.js`, `wallet.js`, and `indivisible_asset.js` that print decrypted device-message bodies, mnemonics, or private-payment payloads. At minimum, redact/mask secret fields (mnemonics, blinding factors, private message bodies) before logging, and make any diagnostic logging of message contents opt-in via an explicit debug configuration flag that is off by default in production.

### Proof of Concept
1. Attacker gains read access to the stdout/log output of an ocore-based wallet or hub process (e.g., via a shared logging service, container log driver, or crash-reporting pipeline — no wallet compromise required).
2. Victim sends a textcoin to another user, or a chat message containing textcoin claim information, or receives a private-asset payment.
3. `device.js`'s `reliablySendPreparedMessageToHub` (line 572) logs the outgoing plaintext JSON, and/or `decryptPackage` (line 466) logs the incoming decrypted plaintext, both of which may contain a mnemonic or private-payment blinding data.
4. Attacker greps the captured logs for the mnemonic string and immediately calls `receiveTextCoin(mnemonic, attacker_address, ...)`, claiming the funds before the legitimate recipient — an unauthorized spend of the victim's funds.

### Citations

**File:** device.js (L464-466)
```javascript
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
```

**File:** device.js (L570-573)
```javascript
function reliablySendPreparedMessageToHub(ws, recipient_device_pubkey, json, callbacks, conn){
	var recipient_device_address = objectHash.getDeviceAddress(recipient_device_pubkey);
	console.log('will encrypt and send to '+recipient_device_address+': '+JSON.stringify(json));
	// encrypt to recipient's permanent pubkey before storing the message into outbox
```

**File:** device.js (L714-721)
```javascript
function sendMessageToHub(ws, recipient_device_pubkey, subject, body, callbacks, conn){
	// this content is hidden from the hub by encryption
	var json = {
		from: my_device_address, // presence of this field guarantees that you cannot strip off the signature and add your own signature instead
		device_hub: my_device_hub, 
		subject: subject, 
		body: body
	};
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

**File:** wallet.js (L2828-2833)
```javascript
					receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
						if (err)
							console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
						else
							console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
						cb();
```

**File:** indivisible_asset.js (L243-243)
```javascript
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
```

**File:** indivisible_asset.js (L272-272)
```javascript
					console.log("inserting output "+JSON.stringify(output));
```
