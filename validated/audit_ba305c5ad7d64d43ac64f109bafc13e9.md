## Title
Unsanitized control characters in prosaic/arbiter contract `title`/`text` fields can spoof what a peer displays and approves before co-signing a payment - (File: prosaic_contract.js)

### Summary
The Flatpak CVE-2023-28101 pattern is: attacker-controlled metadata containing non-printable control characters (e.g. `ESC`) is rendered to a user by a CLI tool, letting the attacker hide/alter what the user actually sees before approving an action. In ocore, an analogous unauthenticated input path exists in the prosaic-contract offer flow: `wallet.js`'s handler for the `prosaic_contract_offer` device message only checks that `title`/`text` are present, non-empty, and match the SHA-256 hash of the concatenated fields — it never restricts or strips control characters from either field. [1](#0-0) [2](#0-1) 

### Finding Description
`title` and `text` are attacker-supplied strings coming directly from a paired device/private-payment counterparty (`prosaic_contract_offer`/`prosaic_contract_shared` device messages). The only validations performed are: presence, `ttl > 0`, valid addresses, hash match, and a date-format regex — there is no check for `\x1b` (ESC), other C0 control codes, or any other character-class restriction. [3](#0-2) [4](#0-3) 

The accepted contract is persisted verbatim via `prosaic_contract.store()`/`createAndSend()` and later used to derive and drive a shared address, sign transactions, and pay a `CHARGE_AMOUNT` deposit from the local wallet. [5](#0-4) [6](#0-5) 

The contract's `title`/`text` are the human-readable content a user relies on when deciding to accept a contract offer (which subsequently triggers deposit/claim payments through the shared address, confirmed via `confirm_contract_deposit`/`confirm_contract_sign`/`confirm_contract_claim` events during signing). [7](#0-6) 

Separately, chat "text" messages received from a device are emitted essentially unfiltered to the UI (only a few specific `(prosaic-contract:...)`-style markers are stripped by regex; everything else, including raw ANSI escape sequences, passes through), reinforcing that ocore's device-message layer has no general control-character sanitation for user-displayed strings. [8](#0-7) 

This mirrors the Flatpak bug class: the general unit/joint-level sanitization in `validation.js` (`isObjectWellFormed`) only rejects lone surrogates and NUL bytes, not ANSI/C0 control codes, and only applies to on-chain unit content — it is not reused for off-chain device messages like contract offers. [9](#0-8) [10](#0-9) 

### Impact Explanation
A malicious paired device (private-payment counterparty in a prosaic/arbiter contract) can embed ANSI escape sequences or other control characters in `title`/`text` to visually hide or rewrite the terms displayed to the victim's wallet UI/terminal (e.g., overwrite lines, hide a clause committing more funds, or spoof a different peer address/amount context around the contract). If the victim approves what appears to be an innocuous contract, they end up co-signing a shared-address transaction and paying the `CHARGE_AMOUNT` deposit for a contract whose actual displayed/agreed terms differ from what they believe — a concrete unauthorized-spending scenario driven entirely by a hostile display rendering of attacker-controlled content that ocore forwarded unsanitized.

### Likelihood Explanation
Likely but requires: (1) an existing pairing between the victim and an adversarial peer device (any paired device can send `prosaic_contract_offer`/`_shared`), and (2) a UI layer that renders `title`/`text` directly to a terminal/console-based surface without its own sanitization. Since ocore performs no filtering itself and delegates the entire responsibility to downstream UIs, any UI that does raw console/log rendering (headless wallets, admin/ops tooling) is exposed. The presence of `readline`-like helper `console.log` usage patterns for similar debug/display paths in the codebase indicates this is a plausible integration pattern.

### Recommendation
- In `wallet.js`'s handlers for `prosaic_contract_offer` / `prosaic_contract_shared` (and any other device message with free-form user-facing text, including chat `text`), reject or strip ASCII control characters (0x00–0x1F excluding `\n`/`\t` as needed, and 0x7F) from `title`/`text` before storing/displaying, similar to the existing `\n` check performed for data-feed names/values in `validation.js`.
- Enforce a maximum length and character allowlist on `title`, consistent with poll `question`/`choices` handling (`validation.js` `MAX_CHOICE_LENGTH`/trim checks) which already exists for similar public on-chain content.
- Extend `isObjectWellFormed` (or a new `isDisplaySafeString` helper) to also flag control characters, and apply it uniformly to all message bodies handled in `wallet.js`'s `handleMessageFromHub`, not just to unit/joint validation.

### Proof of Concept
1. Pair Device B with victim Device A.
2. Device B sends a `prosaic_contract_offer` message where `title` = `"Loan repayment\x1b[2K\x1b[1AShared address contract for 1000 bytes"` and `text` similarly contains ANSI cursor-movement/clear-line sequences designed to overwrite the true clause (e.g. actual amount/terms) once rendered on a terminal-based wallet display.
3. `wallet.js` validates only `hash`, addresses, `ttl`, and date format — it accepts and stores the contract as-is. [11](#0-10) 
4. A terminal-rendering wallet UI displays the corrupted `title`/`text` to the victim, showing misleading contract terms.
5. Victim approves the contract, triggering shared-address creation and deposit/claim payments they did not intend to approve as displayed.

**Uncertainty**: This repo (`ocore`) is a core library; the actual rendering surface (GUI vs. terminal) lives in downstream wallet applications not present in this repository, so the exact visual exploitation depends on how a given UI renders `title`/`text`. The finding is scoped to the fact that ocore performs no sanitization of these attacker-controlled, peer-supplied display strings before persisting/forwarding them, which is the root-cause parallel to CVE-2023-28101.

### Citations

**File:** wallet.js (L101-113)
```javascript
			case "text":
				message_counter++;
				if (!ValidationUtils.isNonemptyString(body))
					return callbacks.ifError("text body must be string");
				body = body
					.replace(/\(prosaic-contract:.+?\)/g, '')
					.replace(/\(arbiter-contract-offer:.+?\)/g, '')
					.replace(/\(arbiter-contract-event:.+?\)/g, '')
					.replace(/\(arbiter-dispute:.+?\)/g, '');
				// the wallet should have an event handler that displays the text to the user
				eventBus.emit("text", from_address, body, message_counter);
				callbacks.ifOk();
				break;
```

**File:** wallet.js (L455-481)
```javascript
			case 'prosaic_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date)
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!(body.ttl > 0))
					return callbacks.ifError("ttl must be a positive number");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address))
					return callbacks.ifError("either peer_address or address is not valid in contract");
				if (body.hash !== prosaic_contract.getHash(body)) {
					if (body.hash === prosaic_contract.getHashV1(body))
						return callbacks.ifError("received prosaic contract offer with V1 hash");	
					return callbacks.ifError("wrong contract hash");
				}
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.my_address], function(rows) {
					if (!rows.length)
						return callbacks.ifError("contract does not contain my address");
					delete body.shared_address;
					prosaic_contract.store(body);
					var chat_message = "(prosaic-contract:" + Buffer.from(JSON.stringify(body), 'utf8').toString('base64') + ")";
					eventBus.emit("text", from_address, chat_message, ++message_counter);
					callbacks.ifOk();
				});
				break;
```

**File:** wallet.js (L483-501)
```javascript
			case 'prosaic_contract_shared':
				if (!body.title || !body.text || !body.creation_date)
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address))
					return callbacks.ifError("either peer_address or address is not valid in contract");
				if (body.hash !== prosaic_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses \n\
						JOIN wallet_signing_paths USING(wallet)\n\
						WHERE my_addresses.address=? AND wallet_signing_paths.device_address=?",[body.my_address, from_address],
					function(rows) {
						if (!rows.length)
							return callbacks.ifError("contract does not contain my address shared with your device");
						prosaic_contract.store(body);
						callbacks.ifOk();
					}
				);
```

**File:** wallet.js (L2043-2096)
```javascript
					// filter out prosaic and arbiter contract txs to change/suppress popup messages
					async.series([function(cb) { // step 1: prosaic/arbiter contract shared address deposit
						var payment_msg = _.find(objUnsignedUnit.messages, function(m){return m.app=="payment" && m.payload && !m.payload.asset});
						if (!payment_msg)
							return cb();
						var possible_contract_output = _.find(payment_msg.payload.outputs, function(o){return o.amount==prosaic_contract.CHARGE_AMOUNT || o.amount==arbiter_contract.CHARGE_AMOUNT});
						if (!possible_contract_output)
							return cb();
						var table = possible_contract_output.amount==prosaic_contract.CHARGE_AMOUNT ? 'prosaic' : 'wallet_arbiter';
						db.query("SELECT peer_device_address FROM "+table+"_contracts WHERE shared_address=?", [possible_contract_output.address], function(rows) {
							if (!rows.length)
								return cb();
							if (!bRequestedConfirmation) {
								if (rows[0].peer_device_address !== device_address)
									eventBus.emit("confirm_contract_deposit");
								bRequestedConfirmation = true;
							}
							return cb(true);
						});
					}, function(cb) { // step 2: posting unit with contract hash (or not a prosaic and arbiter contract / not a tx at all)
						db.query("SELECT peer_device_address, NULL AS amount, NULL AS asset, NULL AS my_address FROM prosaic_contracts WHERE shared_address=? OR peer_address=?\n\
							UNION SELECT peer_device_address, amount, asset, my_address FROM wallet_arbiter_contracts WHERE shared_address=? OR peer_address=?", [address, address, address, address], function(rows) {
							if (!rows.length) 
								return cb();
							// do not show alert for peer address in prosaic contracts
							if (rows[0].peer_device_address === device_address)
								return cb(true);
							// co-signers on our side
							if (!bRequestedConfirmation) {
								var isClaim = false;
								objUnsignedUnit.messages.forEach(function(message) {
									var payload = message.payload || assocPrivatePayloads[message.payload_hash];
									if (!payload)
										return;
									var possible_contract_output = _.find(payload.outputs, function(o){return payload.asset==rows[0].asset && o.address === rows[0].my_address});
									if (possible_contract_output)
										isClaim = true;
								});
								if (isClaim)
									eventBus.emit("confirm_contract_claim");
								else
									eventBus.emit("confirm_contract_sign");
								bRequestedConfirmation = true;
							}
							return cb(true);
						});
					}], function(wasConfirmationRequested) {
						if (wasConfirmationRequested)
							return;
						if (!bRequestedConfirmation) {
							eventBus.emit("confirm_on_other_devices");
							bRequestedConfirmation = true;
						}
					});
```

**File:** prosaic_contract.js (L13-20)
```javascript
function createAndSend(hash, peer_address, peer_device_address, my_address, creation_date, ttl, title, text, cosigners, cb) {
	db.query("INSERT INTO prosaic_contracts (hash, peer_address, peer_device_address, my_address, is_incoming, creation_date, ttl, status, title, text, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [hash, peer_address, peer_device_address, my_address, false, creation_date, ttl, status_PENDING, title, text, JSON.stringify(cosigners)], function() {
		var objContract = {title: title, text: text, creation_date: creation_date, hash: hash, peer_address: my_address, ttl: ttl, my_address: peer_address};
		device.sendMessageToDevice(peer_device_address, "prosaic_contract_offer", objContract);
		if (cb)
			cb(objContract);
	});
}
```

**File:** prosaic_contract.js (L55-70)
```javascript
function store(objContract, cb) {
	var fields = '(hash, peer_address, peer_device_address, my_address, is_incoming, creation_date, ttl, status, title, text';
	var placeholders = '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?';
	var values = [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, true, objContract.creation_date, objContract.ttl, objContract.status || status_PENDING, objContract.title, objContract.text];
	if (objContract.shared_address) {
		fields += ', shared_address';
		placeholders += ', ?';
		values.push(objContract.shared_address);
	}
	fields += ')';
	placeholders += ')';
	db.query("INSERT "+db.getIgnore()+" INTO prosaic_contracts "+fields+" VALUES "+placeholders, values, function(res) {
		if (cb)
			cb(res);
	});
}
```

**File:** prosaic_contract.js (L98-104)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}

function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
```

**File:** string_utils.js (L362-382)
```javascript
function isObjectWellFormed(obj) {
	if (typeof obj !== 'object' || obj === null)
		return typeof obj === 'string' ? obj.isWellFormed() && obj.indexOf('\0') === -1 : true;

	if (Array.isArray(obj)) {
		// for-loop is faster than .every
		for (let i = 0; i < obj.length; i++) {
			if (!isObjectWellFormed(obj[i])) return false;
		}
		return true;
	}

	for (const key in obj) {
		if (Object.hasOwn(obj, key)) {
			if (!key.isWellFormed() || key.indexOf('\0') >= 0) return false;
			if (!isObjectWellFormed(obj[key])) return false;
		}
	}

	return true;
}
```

**File:** validation.js (L157-158)
```javascript
	if (!isObjectWellFormed(objJoint))
		return bAA ? callbacks.ifUnitError("unit contains invalid string (lone surrogate or null byte)") : callbacks.ifJointError("unit contains invalid string (lone surrogate or null byte)");
```
