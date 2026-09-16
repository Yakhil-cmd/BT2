### Title
Sensitive Wallet and Device-Message Secrets Logged in Cleartext at Default Log Level - (File: device.js, wallet.js)

### Summary
Similar to CVE-2023-29471 (Alpakka Kafka logging credentials at debug level), `ocore` unconditionally writes sensitive secret material to `console.log`/stdout on the normal, always-on code path (not gated by a debug flag), where any paired device, hub, or counterparty can trigger the logging simply by sending a device message or textcoin payment. If stdout is captured to a log file (a very common deployment pattern for hubs/wallets built on `ocore`, and standard practice when users share logs for support), these secrets become persisted and exposed.

### Finding Description
`device.js`'s `decryptPackage()` decrypts every incoming device-to-device message and then logs the **full plaintext** of the decrypted content unconditionally: [1](#0-0) 

This function is reached from `handleJustsaying`/message-receiving paths for any message sent by a paired device or hub — no elevated privilege is required, only being paired with the victim device (pairing itself is initiated by exchanging a `pairing_secret` that is also logged, see below). The decrypted `json` payload commonly carries private wallet material: shared-address definitions, `wallet_signing_paths`, `extended_pubkeys` (xpubkeys), and private-asset payment-chain elements (which include `blinding` factors and per-output addresses used to prove ownership of hidden outputs), as seen elsewhere in the same message-handling flow, e.g. private-chain saving logs the entire chain including blinding data: [2](#0-1) [3](#0-2) 

Separately, `wallet.js` logs the **mnemonic** of a textcoin — the bearer secret that is functionally equivalent to a spending credential, since anyone who possesses the mnemonic can claim the funds locked to the address it derives — directly to console during automatic reclaim processing: [4](#0-3) 

None of this logging is gated behind a debug/verbose flag; it runs on the default `console.log` path exactly like the Alpakka Kafka issue, where configuration (including credentials) was logged at "debug" level by default rather than being suppressed or redacted.

### Impact Explanation
- Leaked `blinding` factors and addresses for private (indivisible) asset outputs let an observer of the logs de-anonymize and prove/disprove ownership of private outputs, and combined with other exposed chain data can facilitate crafting conflicting/double-spend chains for those private outputs.
- Leaked textcoin `mnemonic` values are a direct bearer-credential leak: whoever reads the log can claim the referenced funds, i.e. concrete unauthorized spending/theft of value that was intended for a specific recipient.
- Leaked `extended_pubkeys`/`wallet_signing_paths` for multi-signature/shared addresses reduce the secrecy assumptions of the wallet's cosigning setup and can aid fund-loss/freezing scenarios in shared-address wallets if combined with other leaked material.

### Likelihood Explanation
Triggering the logging requires no privileged access — merely being a paired counterparty device (or the local wallet processing its own outgoing/incoming textcoins) is enough, matching the "paired device"/"private-payment counterparty" actors permitted by scope. Because ocore-based products (hubs, GUI/headless wallets) commonly redirect stdout to persistent log files or ask users to share logs for troubleshooting/bug reports, the credential/secret exposure is realistic and not merely theoretical, exactly mirroring how Alpakka Kafka's debug-level config dump became an exploitable disclosure path once operators enabled debug logging or shipped it in bug reports.

### Recommendation
- Remove or redact the plaintext payload logging in `decryptPackage()` (`device.js:466`) — log only message type/hash/size, never the decrypted content.
- Remove mnemonic values from log statements in `wallet.js` (`claimBackOldTextcoins`, and any other `console.log` referencing `mnemonic`); log only the unit/asset/address instead.
- Audit other `console.log` call sites that print full `JSON.stringify` of private-chain/private-payment objects (e.g. `indivisible_asset.js:243,272`) and strip `blinding`/secret fields before logging.
- Introduce a centralized logger with explicit secret-redaction rules so future contributors cannot reintroduce plaintext secret logging.

### Proof of Concept
1. Pair with a victim device (standard pairing flow) or become a private-payment/textcoin counterparty.
2. Send the victim a device message containing a private-asset payment chain, or have the victim create/reclaim a textcoin.
3. On the victim's node, `decryptPackage()` (`device.js:466`) prints the full decrypted JSON — including blinding factors/addresses — to stdout; `claimBackOldTextcoins` (`wallet.js:2828-2832`) prints the textcoin mnemonic to stdout.
4. If the victim's deployment pipes stdout to a log file (common), or the victim shares logs for troubleshooting, the attacker (or anyone with log access) obtains the mnemonic/blinding data and can claim the associated funds or de-anonymize private outputs.

### Citations

**File:** device.js (L464-466)
```javascript
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
```

**File:** indivisible_asset.js (L242-243)
```javascript
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
```

**File:** indivisible_asset.js (L270-272)
```javascript
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
```

**File:** wallet.js (L2828-2832)
```javascript
					receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
						if (err)
							console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
						else
							console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
```
