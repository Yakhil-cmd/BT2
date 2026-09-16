### Title
Sensitive Device-Messaging Payloads (Private Payment Chains, Wallet Definitions, Keys) Are Written to Debug Logs in Plaintext - ([File: device.js])

### Summary
`device.js` unconditionally writes the full plaintext JSON of outgoing and incoming device-to-device messages to `console.log`, including data that is meant to be confidential between paired devices (private payment chains, wallet/xpub definitions, pairing secrets, textcoin mnemonics). This mirrors the Ansible flaw (CVE-2019-14846), where debug-level logging leaked credential-bearing plugin data — here, `ocore`'s always-on debug logging leaks the plaintext of end-to-end "encrypted" device messages before encryption and after decryption.

### Finding Description
`device.js` implements end-to-end encrypted device messaging used for wallet pairing, private payment chain delivery, textcoin mnemonics, and wallet/address definitions. Two locations log the full plaintext content unconditionally:

- On send, before the payload is encrypted for delivery to the hub/recipient: `console.log('will encrypt and send to '+recipient_device_address+': '+JSON.stringify(json));` [1](#0-0) 
- On receive, immediately after successful decryption of an incoming package: `console.log("decrypted: "+decrypted_message);` [2](#0-1) 

The `json`/`decrypted_message` objects carry sensitive application payloads sent between paired devices — e.g. private payment chains forwarded via `forwardPrivateChainsToOtherMembersOfOutputAddresses` (which itself also logs the chains directly), wallet key/address definitions, and other wallet-management messages routed through `wallet_defined_by_keys.js`, `wallet_defined_by_addresses.js`, `arbiter_contract.js`, and `prosaic_contract.js`. [3](#0-2) 

Similarly, `wallet.js` logs unclaimed textcoin secrets (mnemonics that function as bearer private keys for the textcoin address) in plaintext whenever a claim attempt fails or succeeds: `console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);` and `console.log("claimed back mnemonic "+row.mnemonic+...)`. [4](#0-3) 

Unlike the Ansible case where DEBUG-level logging was the specific culprit, here the logging is unconditional `console.log` output with no log-level gating at all — meaning any deployment that captures process stdout (systemd journal, pm2 logs, docker log driver, `nohup`/redirect-to-file setups commonly used to run ocore-based hubs/wallets) persists this plaintext sensitive data to disk indefinitely. This is a textbook CWE-532 (insertion of sensitive information into log file), and because the logged content is attacker/counterparty-controlled JSON, it also enables CWE-117 log injection/forging by a peer or paired device.

### Impact Explanation
Any paired device, private-payment counterparty, or textcoin recipient interacting with the hub/wallet process can cause secrets to be written to the operator's persistent logs:
- Private payment chain proofs and address definitions that are supposed to remain confidential to the two counterparties get persisted outside the intended trust boundary (in log storage, log aggregation systems, or backups), letting anyone with log access reconstruct private asset ownership/spend history or impersonate wallet members.
- Textcoin mnemonics logged in plaintext are equivalent to leaking a spendable private key — anyone reading the log can claim the corresponding output before the legitimate recipient, resulting in direct theft of funds.
- Because the logs capture data before/after decryption, the end-to-end encryption design of the messaging layer is effectively bypassed for anyone with log access, undermining the confidentiality guarantee the protocol is meant to provide.

This satisfies "concrete unauthorized spending" (textcoin mnemonic leak) and "AA fund loss" style disclosure impact via log capture of private wallet/payment data.

### Likelihood Explanation
No special privilege is needed to trigger the logging — any correspondent device pairing with the target, sending a private payment, or the wallet itself processing a stalled/queued textcoin claim, causes these log lines to execute as part of normal, expected message flow. Because `console.log` output is commonly redirected to persistent log files/log aggregators in production Node.js deployments, the likelihood of the sensitive data actually being captured in storage is high for any non-trivially operated node.

### Recommendation
- Remove or gate behind an explicit, disabled-by-default verbose/debug flag all `console.log` calls in `device.js` that print full message JSON (`reliablySendPreparedMessageToHub`, `decryptPackage`) and in `wallet.js` (`forwardPrivateChainsToOtherMembersOfOutputAddresses`, `claimBackOldTextcoins`).
- When logging is needed for diagnostics, redact/whitelist only non-sensitive metadata (e.g., message type, recipient device address, message hash) instead of the full payload or the mnemonic itself.
- Ensure any future debug logging of message content is opt-in only and documented as unsafe for production log retention, consistent with how the Ansible advisory was ultimately fixed by not logging plugin output at DEBUG level.

### Proof of Concept
1. Pair two devices/wallets (Device A, Device B) using standard `ocore` pairing.
2. Device A sends a private payment (private chain) or shares a wallet/address definition with Device B via the normal wallet flow, which calls `reliablySendPreparedMessageToHub`. [1](#0-0) 
3. On Device A's host, observe stdout/log output: the full plaintext JSON payload (private chain data, wallet keys, etc.) is printed via `console.log('will encrypt and send to ...')` before encryption.
4. On Device B's host, upon receiving and decrypting the package, `decryptPackage` prints the full plaintext decrypted message via `console.log("decrypted: "+decrypted_message)`. [2](#0-1) 
5. Separately, send a textcoin and let it go unclaimed past the configured `days` threshold; when `claimBackOldTextcoins` runs, the plaintext mnemonic (a spendable secret) is printed to the log on both success and failure paths. [5](#0-4) 
6. Any process capturing stdout in production (journald, pm2, docker logs) now permanently stores this sensitive data outside of the intended device-to-device encrypted channel.

### Citations

**File:** device.js (L464-466)
```javascript
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
```

**File:** device.js (L570-572)
```javascript
function reliablySendPreparedMessageToHub(ws, recipient_device_pubkey, json, callbacks, conn){
	var recipient_device_address = objectHash.getDeviceAddress(recipient_device_pubkey);
	console.log('will encrypt and send to '+recipient_device_address+': '+JSON.stringify(json));
```

**File:** wallet.js (L1082-1096)
```javascript
function forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfOutputAddresses", arrChains);
	var assocOutputAddresses = {};
	arrChains.forEach(function(arrPrivateElements){
		var objHeadPrivateElement = arrPrivateElements[0];
		var payload = objHeadPrivateElement.payload;
		payload.outputs.forEach(function(output){
			if (output.address)
				assocOutputAddresses[output.address] = true;
		});
		if (objHeadPrivateElement.output && objHeadPrivateElement.output.address)
			assocOutputAddresses[objHeadPrivateElement.output.address] = true;
	});
	var arrOutputAddresses = Object.keys(assocOutputAddresses);
	console.log("output addresses", arrOutputAddresses);
```

**File:** wallet.js (L2818-2834)
```javascript
function claimBackOldTextcoins(to_address, days){
	if (typeof days !== 'number')
		throw Error("bad days: " + days);
	db.query(
		"SELECT mnemonic FROM sent_mnemonics LEFT JOIN unit_authors USING(address) \n\
		WHERE mnemonic!='' AND unit_authors.address IS NULL AND creation_date<"+db.addTime("-"+days+" DAY"),
		function(rows){
			async.eachSeries(
				rows,
				function(row, cb){
					receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
						if (err)
							console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
						else
							console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
						cb();
					});
```
