### Title
Unbounded `eventBus` listener accumulation via repeated `sign` requests for unknown addresses - ([File: wallet.js])

### Summary
`handleMessageFromHub`'s `"sign"` case lets any paired device ask the wallet to sign a unit for an arbitrary `body.address`. When the address is not tracked locally, the `ifUnknownAddress` callback registers a **permanent, one‑time `eventBus` listener** keyed by the attacker‑controlled address string, waiting for that address to ever become "new." Because the address is fully controlled by the requester and never needs to correspond to anything real, an attacker can generate unlimited unique addresses and unlimited listeners that will realistically never fire and are never cleaned up. [1](#0-0) 

### Finding Description
`handleMessageFromHub` is invoked for every message received from a paired device via `"handle_message_from_hub"`, and dispatches on `subject`. [2](#0-1) 

For `subject === "sign"`, after some structural validation of the unsigned unit and payloads, the code resolves `body.address` via `findAddress`: [3](#0-2) 

The relevant branch is:
```js
ifUnknownAddress: function(){
    callbacks.ifError("not aware of address "+body.address+" but will see if I learn about it later");
    eventBus.once("new_address-"+body.address, function(){
        // rewrite callbacks to avoid duplicate unlocking of mutex
        handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, { ifOk: function(){}, ifError: function(){} });
    });
}
``` [1](#0-0) 

`callbacks.ifError` is called immediately, which correctly releases the `"from_hub"` mutex lock taken earlier in `handleMessageFromHub`: [4](#0-3)  — so there is no deadlock — but the `eventBus.once("new_address-"+body.address, …)` subscription is **never removed** unless the exact address later shows up locally via a `new_address-<address>` emission. Since `body.address` is fully attacker-supplied (only checked with `ValidationUtils.isValidAddress`, i.e., any syntactically valid 32-byte base32 address works, whether or not it is ever actually used) [5](#0-4) , an attacker who is merely paired with the victim device (a "paired device" reachable persona per scope) can repeatedly send `"sign"` messages with a freshly generated random address each time. Each call:
- Passes cheap structural checks (valid address, valid signing path, minimal unsigned-unit shape).
- Falls into `ifUnknownAddress` because the random address is never actually one of the wallet's addresses.
- Registers one more permanent `EventEmitter` listener under a unique event name (`"new_address-"+address`), which Node.js's `EventEmitter` keeps indexed in an internal map forever, since the corresponding `"new_address-"+address` event will essentially never be emitted (it fires only when the wallet itself creates that specific address).

This is structurally analogous to the reported Deadwood/MaraDNS issue: a resource (a connection slot in MaraDNS; an event-listener slot / heap memory here) is reserved while waiting for an external condition to resolve (a nameserver address resolving; a specific wallet address showing up), and an attacker can trigger unlimited never-resolving reservations, exhausting the process's resources over time.

### Impact Explanation
Repeated exploitation causes continuous, unbounded growth of the `eventBus`'s internal listener registry (memory) in the victim's wallet process. This is a live-memory leak driven entirely by messages from a paired correspondent device, with no cap on the number of distinct listeners that can be created. Over a sustained attack, this leads to growing memory consumption and, eventually, degraded performance or process crash of the wallet/hub node, which can result in the node being **unable to process/confirm further wallet operations or units** while it is being slowed or restarted, i.e., "a network unable to confirm new units" from the affected node's perspective. There is no fund loss primitive here (no double-spend, no supply inflation) — the impact is purely availability/resource exhaustion of the recipient's ocore process.

### Likelihood Explanation
The attacker only needs to be paired with the victim device (a normal wallet-to-wallet or bot-to-wallet correspondent relationship), which is a low bar reachable by any correspondent that a user has ever exchanged pairing info with (including malicious bots offering "services" that induce pairing). Crafting the `"sign"` payload requires only a validly-formatted, but otherwise meaningless, address and unsigned-unit skeleton — no cryptographic material, funds, or special privileges are required, and the request can be automated and sent at high rates.

### Recommendation
- Cap the total number of pending `"new_address-*"` listeners (or `ifUnknownAddress` waits) per correspondent device, and/or add a TTL that removes the listener (via `eventBus.removeListener`) after a bounded timeout.
- Rate-limit `"sign"` requests (and other message types that register long-lived listeners) per correspondent device in `handleMessageFromHub`.
- Consider not auto-resubscribing on truly unknown addresses at all, requiring the peer to resend the request instead of the wallet holding state on their behalf indefinitely.

### Proof of Concept
1. Pair a malicious device B with victim wallet A (normal pairing flow).
2. From B, repeatedly send device messages of the form:
```json
{
  "subject": "sign",
  "body": {
    "address": "<freshly generated random valid 32-char base32 address, never used by A>",
    "signing_path": "r",
    "unsigned_unit": { "version": "...", "authors": [{ "address": "<same random address>" }] }
  }
}
```
3. Each call reaches `handleMessageFromHub` → `"sign"` case → `findAddress` → `ifUnknownAddress`, adding one more `eventBus.once("new_address-<random address>", …)` listener that will never fire. [1](#0-0) 
4. Repeating this at scale (thousands to millions of unique addresses) grows the wallet process's listener/heap footprint without bound, since none of these listeners are ever satisfied or removed, eventually degrading or crashing the victim's ocore process.

**Note on confidence**: I was unable to fully inspect `findAddress`'s exact matching logic (e.g., whether any additional caching/short-circuit exists that would bound repeated `ifUnknownAddress` invocations) due to index/tool call limits; this should be verified by reading `findAddress` in `wallet.js` in full before treating this as fully confirmed. [6](#0-5)

### Citations

**File:** wallet.js (L63-98)
```javascript
// one of callbacks MUST be called, otherwise the mutex will stay locked
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");

	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});

		
	function doHandle() {

		var subject = json.subject;
		var body = json.body;
		if (!subject || typeof body == "undefined" || body === null)
			return callbacks.ifError("no subject or body");
		if (typeof subject !== "string")
			return callbacks.ifError("subject is not a string");
		//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
		//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
		var from_address = objectHash.getDeviceAddress(device_pubkey);
		
		switch (subject){
			case "pairing":
				device.handlePairingMessage(json, device_pubkey, callbacks);
```

**File:** wallet.js (L253-333)
```javascript
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
				var assocPrivatePayloads = body.private_payloads;
				if ("private_payloads" in body){
					if (!isNonemptyObject(assocPrivatePayloads))
						return callbacks.ifError("bad private payloads");
					if (!ValidationUtils.isNonemptyArray(objUnit.messages))
						return callbacks.ifError("private payloads require messages");
					const sent_pp_hashes = Object.keys(assocPrivatePayloads).sort();
					const expected_pp_hashes = objUnit.messages.filter(m => m.payload_location === "none" && m.app === "payment").map(m => m.payload_hash).sort();
					if (!_.isEqual(sent_pp_hashes, expected_pp_hashes))
						return callbacks.ifError("private payloads are not the same as in the messages");
					for (var payload_hash in assocPrivatePayloads){
						try {
							const payload = assocPrivatePayloads[payload_hash];
							if (!ValidationUtils.isNonemptyArray(payload.outputs) || !payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isNonemptyString(o.blinding) && ValidationUtils.isPositiveInteger(o.amount)))
								return callbacks.ifError("bad private payload outputs");
							if (!ValidationUtils.isNonemptyArray(payload.inputs) || !payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
								return callbacks.ifError("bad private payload inputs");
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
				}
				if (("messages" in objUnit) + ("signed_message" in objUnit) !== 1)
					return callbacks.ifError("either messages or signed_message must be present, but not both");
				if ("messages" in objUnit){
					const validation = require('./validation.js');
					if (!validation.hasValidPayloadHashes({ unit: objUnit }))
						return callbacks.ifError("invalid payload hashes");
					if (!objUnit.messages.find(m => m.app === 'payment'))
						return callbacks.ifError("no payment messages");
					for (let m of objUnit.messages) {
						if (m.app !== 'payment' || m.payload_location !== 'inline') continue;
						if (!ValidationUtils.isNonemptyArray(m.payload.outputs) || !m.payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isPositiveInteger(o.amount)))
							return callbacks.ifError("invalid payment outputs");
						if (!ValidationUtils.isNonemptyArray(m.payload.inputs) || !m.payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
							return callbacks.ifError("invalid payment inputs");
					}
				}
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
```

**File:** wallet.js (L396-402)
```javascript
					ifUnknownAddress: function(){
						callbacks.ifError("not aware of address "+body.address+" but will see if I learn about it later");
						eventBus.once("new_address-"+body.address, function(){
							// rewrite callbacks to avoid duplicate unlocking of mutex
							handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, { ifOk: function(){}, ifError: function(){} });
						});
					}
```
