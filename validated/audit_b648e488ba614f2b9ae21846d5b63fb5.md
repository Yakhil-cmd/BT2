### Title
Sensitive device-to-device payload (mnemonics, private-payment data) unconditionally written to console/log output - ([File: device.js])

### Summary
`decryptPackage()` in `device.js` decrypts every incoming encrypted device-to-device message (chat messages, pairing packages, private-payment chains, textcoin mnemonics forwarded between wallets, shared-address data, etc.) and unconditionally prints the full plaintext payload via `console.log("decrypted: "+decrypted_message)` before any content-type check or `no_log`-style redaction is applied. [1](#0-0) . This mirrors the CVE-2018-10855 bug class: content that must remain confidential is written to logs/terminal regardless of success or sensitivity of the operation.

### Finding Description
`decryptPackage()` is the single entry point that decrypts messages received from paired devices/hubs (chat, pairing, private-payment notifications, and mnemonic-bearing textcoin transfer messages). After AES-GCM decryption, the function does:
```
var decrypted_message = decrypted_message_buf.toString("utf8");
console.log("decrypted: "+decrypted_message);
``` [2](#0-1) 
before the JSON is even parsed or inspected for its `subject`. There is no gate that suppresses this log line for sensitive subjects (private payment chains, textcoin mnemonics, wallet/shared-address definitions). Anything sent between two paired devices — including data an unprivileged counterparty in a private-payment or textcoin exchange controls the content of — ends up verbatim in the recipient's process stdout/log files.

Separately, and reachable purely by a wallet's own automated maintenance job (not attacker input, but demonstrating the same logging-hygiene defect exists pervasively in the payment/textcoin code paths), the textcoin mnemonic — which is the literal private key material controlling funds sent as a "textcoin" — is also logged in plaintext:
```
console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
``` [3](#0-2) 
`row.mnemonic` here is the BIP39 mnemonic from which the textcoin's spending key (`xPrivKey`) is derived via `expandMnemonic()` [4](#0-3) , i.e. it is equivalent to a raw private key for a funded address.

### Impact Explanation
Both `console.log` calls persist highly sensitive secrets to any place stdout/log output is captured (systemd journal, PM2/forever logs, crash-report tooling, log aggregation, or terminal scrollback shared for support/debugging). For the textcoin case, exposure of the mnemonic is direct unauthorized-spending exposure: anyone who can read the log can reconstruct the private key and steal the funds on the textcoin address before the legitimate recipient claims them. For `decryptPackage`, any secret embedded in a private-payment chain, mnemonic-bearing chat message, or wallet-pairing data exchanged between correspondents is likewise written to logs in cleartext, extending the exposure surface to anything a counterparty chooses to send.

### Likelihood Explanation
No privileged access or special conditions are required — this fires on every successfully decrypted device message and on every run of the periodic textcoin-reclaim job, so exposure is deterministic whenever logging is enabled (the default in most Node deployments and debug consoles), not a corner case triggered only by rare error paths as in the original Ansible advisory.

### Recommendation
Remove or heavily redact the `console.log("decrypted: "+decrypted_message)` line in `decryptPackage()` (or replace with a hashed/length-only diagnostic), and stop logging `row.mnemonic` (and any other private key material) in `claimBackOldTextcoins`/`receiveTextCoin`. Where diagnostics are needed, log only non-sensitive identifiers (message subject, unit hash, address) and never full decrypted payloads or mnemonics.

### Proof of Concept
1. Pair device A and device B; have B send A any message (chat text, private-payment chain, or textcoin claim notification).
2. On A's process, observe stdout/log: `decrypted: {...full JSON payload...}` is printed containing whatever secret B included (e.g., mnemonic phrase text pasted by a user, or private payment data) — [2](#0-1) .
3. Independently, have a wallet send a textcoin (`sendMultiPayment` with a `textcoin:` address) and let it go unclaimed past the reclaim window; the periodic job `claimBackOldTextcoins` logs `"claimed back mnemonic "+row.mnemonic` to the node's log file in plaintext — [3](#0-2) . Anyone with read access to that log can extract the mnemonic and derive the private key (`expandMnemonic`) to spend any remaining balance on that address before/along with the legitimate owner.

### Citations

**File:** device.js (L463-467)
```javascript
	breadcrumbs.add("decrypted lengths: "+decrypted1.length+" + "+decrypted2.length);
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
	try {
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

**File:** wallet.js (L2828-2833)
```javascript
					receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
						if (err)
							console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
						else
							console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
						cb();
```
