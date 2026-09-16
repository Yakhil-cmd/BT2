Based on the investigation, I found a clear analog in `wallet.js` for the "sign" message handler, where a sender-identity check is explicitly commented out.

### Title
Missing Sender/Cosigner Validation in "sign" Device-Message Handler Allows Any Correspondent to Trigger Signing Requests for a Shared/Multisig Address - (File: wallet.js)

### Summary
The `sign` case in `handleMessageFromHub()` (`wallet.js`) processes a signing request for a local address without verifying that the paired device sending the request (`from_address`) is actually an authorized cosigner/member of the target `body.address`. The check that would enforce this was written and then explicitly disabled.

### Finding Description
When a paired device sends a `"sign"` message, the handler validates the unsigned unit's structure, payment outputs, and private-payload hashes, then calls `findAddress(body.address, body.signing_path, {...})`. In the `ifLocal` branch, it immediately proceeds to raise a `signing_request` event for the wallet UI, but the sender-authorization check is commented out: [1](#0-0) 
The comment explicitly states the check "would make multilateral signing impossible" — meaning it was disabled by design to support use case #2 (multilateral signing / dumb contracts) rather than being an oversight caught in testing, similar to the "acknowledged, validation is done elsewhere" framing in the external report. [2](#0-1) 
As a result, **any correspondent device** (paired, but not necessarily a cosigner of `body.address`) can send a `sign` request for an address it does not control, as long as `body.address` is one of the `objUnit.authors`. The only real gating happens deeper in `findAddress`, which determines whether the address is "local" (owned or shared by this wallet) — but does not check that `from_address` specifically is one of the cosigning devices for that address before emitting the `signing_request` UI event, unlike the `ifRemote` branch which does check `other_device_addresses.includes(from_address)`: [3](#0-2) 

### Impact Explanation
For shared/multisig addresses, this allows an unrelated paired correspondent (not necessarily a cosigner) to prompt a user's wallet with a `signing_request` confirmation dialog for arbitrary attacker-crafted units, potentially leading a confused user to co-sign a transaction that spends shared funds against their real cosigners' intent, or to sign a message purporting to bind them to attacker-chosen contract terms. Since the final signing action still requires manual user confirmation via the `signing_request` UI event, the practical severity depends on the wallet UI not clearly identifying the true origin/legitimacy of the request — the same "validated elsewhere, thus lower severity" caveat noted in the original report.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to already be a paired correspondent of the victim (a normal precondition for any Obyte multi-device wallet interaction) and knowledge of a shared address the victim participates in (which is often shared for legitimate multilateral signing). No special network position or vulnerability chaining is required beyond social engineering the user to approve the resulting dialog.

### Recommendation
Restore and enforce a sender check in the `ifLocal` branch equivalent to the commented-out code, verifying `from_address` is a legitimate cosigner/device for `body.address` (or, if this must remain permissive for multilateral-signing/contract use cases, make the wallet UI clearly and unambiguously label the requester's identity so the user can distinguish a legitimate cosigner co-signing request from a foreign device requesting signature of an outside contract).

### Proof of Concept
1. Device A (attacker) pairs with Device B (victim) as ordinary correspondents.
2. Device B is a cosigner (via `shared_address_signing_paths`) of shared address `S`, together with Device C.
3. Device A crafts an arbitrary `unsigned_unit` whose `authors` includes `S`, and sends a `"sign"` message to Device B with `body.address = S`.
4. `findAddress` resolves `S` as local to Device B (since it is a shared address B is party to).
5. Because the cosigner check is commented out, Device B's wallet immediately fires `signing_request` for this attacker-supplied unit without any indication that Device A is unrelated to `S`'s actual cosigner set, prompting the user to potentially approve signing an unauthorized transaction.

### Citations

**File:** wallet.js (L247-256)
```javascript
			// request to sign a unit created on another device
			// two use cases:
			// 1. multisig: same address hosted on several devices
			// 2. multilateral signing: different addresses signing the same message, such as a (dumb) contract
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
```

**File:** wallet.js (L332-339)
```javascript
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
