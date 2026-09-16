### Title
Prosaic/Arbiter contract hash and acceptance signature omit critical contract terms, allowing contract falsification - (File: prosaic_contract.js, arbiter_contract.js, wallet.js)

### Summary
`prosaic_contract.getHash()` and the acceptance-signature check in `wallet.js` bind the contract's "identity"/agreement only to `title`, `text`, and `creation_date`, but never to the addresses, TTL, or (for arbiter contracts) amount/asset/arbiter fields that actually determine the financial obligations of the contract. This mirrors the diamond-cut bug where the proposal hash omitted `_init`/`_calldata`: the hash that is supposed to uniquely and completely identify the deal can be satisfied while critical terms are free to be substituted.

### Finding Description
`prosaic_contract.getHash()` computes: [1](#0-0) 
which hashes only `title + text + creation_date`. It does not include `my_address`, `peer_address`, `ttl`, `cosigners`, or `shared_address`.

This hash is used in `wallet.js` as the sole integrity check for `prosaic_contract_offer` and `prosaic_contract_shared` messages: [2](#0-1) [3](#0-2) 

Because the hash never covers `my_address`/`peer_address`/`ttl`, an attacker (the counterparty who crafts the contract offer/share message) can present a `body.hash` that legitimately matches `prosaic_contract.getHash(body)` while the address/ttl fields carried in the same message are attacker-controlled and never verified against anything else. Subsequent protocol steps trust `objContract.hash` as a stable identifier of "the same deal" (`prosaic_contract.setField`, `deriveSharedAddress`, `handleReceivedSigningUnit`), even though the deal's actual counterparties/duration are not bound to that identifier.

The acceptance path compounds this: when the peer accepts, it signs only the title, not a hash covering the full negotiated terms: [4](#0-3) 
The verification confirms only `objSignedMessage.signed_message != objContract.title`, i.e., the cryptographic acceptance the offerer relies on to prove "the peer agreed to this contract" is a signature over the title string alone — not over `text`, `creation_date`, `my_address`, `peer_address`, or `ttl`. Any prosaic contract sharing the same title as another can reuse a previously obtained acceptance signature, and any of the un-hashed/un-signed fields (particularly the party addresses used later to derive the 2-of-2 `shared_address` in `deriveSharedAddress`) can diverge between what was actually agreed and what is recorded/acted upon. [5](#0-4) 

The equivalent arbiter-contract flow is less exposed because `arbiter_contract.getHash` (post `NEW_HASH_DATE`) does include `payer_address`, `arbiter_address`, `payee_address`, `amount`, and `asset`: [6](#0-5) 
but the legacy pre-`NEW_HASH_DATE` hash path only hashes names, not addresses, exhibiting the same class of gap, and is still accepted via the V1-hash fallback check in `wallet.js`. [7](#0-6) 

### Impact Explanation
Because the shared multisig address for a prosaic contract is derived directly from `contract.my_address`/`contract.peer_address` (fields never covered by the hash or by the acceptance signature), and because dispute/signing-unit verification in `prosaic_contract.js` trusts `contract.hash` as the sole binding of the deal terms, a counterparty can manipulate un-hashed/un-signed fields to redirect where a shared deposit address is derived, or replay/cross-apply an acceptance signature meant for one deal onto another sharing the same title. This can lead to funds being locked into a shared address controlled by unintended parties/addresses, or a party being held to (or defrauded of) terms it never actually cryptographically committed to — a concrete AA/wallet-fund loss or freezing analog to the diamond-cut falsification bug.

### Likelihood Explanation
This requires only a malicious contract counterparty (not a hub, node, or peer with special privileges) sending crafted `prosaic_contract_offer`/`prosaic_contract_shared`/`prosaic_contract_response` messages through the normal device-messaging channel, which is a standard, always-reachable code path for any wallet user negotiating a prosaic (or legacy arbiter) contract. No compromise of hub/node/keys is needed, so likelihood is Medium: it depends on a user engaging in a contract negotiation with a malicious counterparty, but no other privilege is required.

### Recommendation
Include all contract-defining fields — `my_address`, `peer_address`, `ttl`, and any asset/amount fields where applicable — in `prosaic_contract.getHash()` (and retire the legacy `getHashV1`/pre-`NEW_HASH_DATE` `arbiter_contract` hash path). Change the acceptance signature to cover the full contract hash (or an object hash of all binding fields) rather than just `title`, and enforce this in the `prosaic_contract_response` validation in `wallet.js`.

### Proof of Concept
1. Device A sends `prosaic_contract_offer` to Device B with `title="Deal"`, `text="Terms X"`, `creation_date=T`, `my_address=Addr1`, `peer_address=AddrVictim`. `hash = sha256(title+text+creation_date)` passes the check in `wallet.js` (`body.hash !== prosaic_contract.getHash(body)`), since address fields aren't hashed.
2. Device B accepts by signing only `title` ("Deal") as `signed_message`, per `respond()`/`validateSignedMessage` check `objSignedMessage.signed_message != objContract.title`.
3. Device A now stores/uses a contract record where `peer_address`/`my_address` (used later in `deriveSharedAddress`) can be swapped or altered relative to what Device B believes it agreed to, because neither the identifying hash nor the accepted signature commits to those fields — the derived `shared_address` (and later fund flow into it) is not verifiably tied to the terms Device B actually reviewed and signed for. [1](#0-0) [4](#0-3) [5](#0-4)

### Citations

**File:** prosaic_contract.js (L98-100)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```

**File:** prosaic_contract.js (L114-138)
```javascript
function deriveSharedAddress(contract, bOfferor) {
	const offeror_address = bOfferor ? contract.my_address : contract.peer_address;
	const acceptor_address = bOfferor ? contract.peer_address : contract.my_address;
	const offeror_device_address = bOfferor ? device.getMyDeviceAddress() : contract.peer_device_address;
	const acceptor_device_address = bOfferor ? contract.peer_device_address : device.getMyDeviceAddress();
	var arrDefinition =
		["and", [
			["address", offeror_address],
			["address", acceptor_address]
		]];

	var assocSignersByPath = {
		"r.0": {
			address: offeror_address,
			member_signing_path: "r",
			device_address: offeror_device_address
		},
		"r.1": {
			address: acceptor_address,
			member_signing_path: "r",
			device_address: acceptor_device_address
		},
	};
	return { arrDefinition, assocSignersByPath };
}
```

**File:** wallet.js (L455-469)
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
```

**File:** wallet.js (L483-491)
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
```

**File:** wallet.js (L565-571)
```javascript
						}
					//	if (objSignedMessage.version !== constants.version)
					//		return callbacks.ifError("wrong version in signed message: " + objSignedMessage.version);
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
```

**File:** arbiter_contract.js (L194-207)
```javascript
function getHashSrc(contract) {
	const payer_name = contract.me_is_payer ? contract.my_party_name : contract.peer_party_name;
	const payee_name = contract.me_is_payer ? contract.peer_party_name : contract.my_party_name;
	const payer_address = contract.me_is_payer ? contract.my_address : contract.peer_address;
	const payee_address = contract.me_is_payer ? contract.peer_address : contract.my_address;
	const src = contract.creation_date > exports.NEW_HASH_DATE
		 ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
		 : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
	return src;
}

function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
}
```
