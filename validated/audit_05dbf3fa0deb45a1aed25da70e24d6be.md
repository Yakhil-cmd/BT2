## Title
Memory leak via unbounded `eventBus.once('saved_unit-'+unit, ...)` listener registration in `payment_notification` handling - (File: wallet.js)

### Summary
`handleMessageFromHub()` in `wallet.js` processes the `payment_notification` device-chat message from any paired/correspondent device. For every such message it registers a permanent, never-cleaned-up `eventBus.once('saved_unit-'+unit, emitPn)` listener keyed by the attacker-supplied unit hash, with no mechanism to remove the listener if that unit never gets saved. Because a correspondent can freely choose any 44-character base64 string as the "unit", they can trivially produce values that will never correspond to a real unit and will never fire, causing the listener (and its closure) to remain in the process's `EventEmitter` internals forever. This is the same bug class as CVE-2026-24828 ("Missing Release of Memory after Effective Lifetime"), reachable here via ordinary wallet/device chat message handling rather than a game engine, and results in unbounded heap growth / eventual process crash (denial of service).

### Finding Description [1](#0-0) 

```
case 'payment_notification':
    var current_message_counter = ++message_counter;
    var unit = body;
    if (!ValidationUtils.isStringOfLength(unit, constants.HASH_LENGTH))
        return callbacks.ifError("invalid unit in payment notification");
    var bEmitted = false;
    var emitPn = function(objJoint){
        if (bEmitted) return;
        bEmitted = true;
        emitNewPublicPaymentReceived(from_address, objJoint.unit, current_message_counter);
    };
    eventBus.once('saved_unit-'+unit, emitPn);
    storage.readJoint(db, unit, {
        ifNotFound: function(){
            console.log("received payment notification for unit "+unit+" which is not known yet, will wait for it");
            callbacks.ifOk();
        },
        ifFound: function(objJoint){
            emitPn(objJoint);
            eventBus.removeListener('saved_unit-'+unit, emitPn);
            callbacks.ifOk();
        }
    });
    break;
```

The only validation performed on `unit` (the attacker-controlled `body`) is a length check (`isStringOfLength(unit, constants.HASH_LENGTH)`), not that it is a real, well-formed, or existing unit hash. If `storage.readJoint` reports `ifNotFound`, the code simply logs and calls `callbacks.ifOk()` — the `eventBus.once('saved_unit-'+unit, emitPn)` listener that was already registered is **never removed** in this branch. It is only ever removed inside `ifFound`, which requires the exact same string to eventually become a real, saved unit — something the attacker fully controls and will never do, since they picked a random string.

`eventBus` is a plain Node `EventEmitter` singleton shared process-wide: [2](#0-1)  — each unique event name (`'saved_unit-'+unit`) creates a new entry in the emitter's internal event map that is retained indefinitely, along with the closure over `from_address`, `current_message_counter`, and `bEmitted`.

This handler is reached through the generic hub-message dispatcher `handleMessageFromHub`, which is registered on `"handle_message_from_hub"` and processes messages from any correspondent/paired device: [3](#0-2) . The comment in the code itself acknowledges that `payment_notification` is attacker-reachable ("since the payments are public, an evil user might notify us about a payment sent by someone else") [4](#0-3) , but the security concern addressed there is spoofing, not resource exhaustion from repeated calls.

Similar, though comparatively narrower, patterns exist for `eventBus.once("signature-"+..., ...)` and `eventBus.once("new_address-"+..., ...)` in the same file [5](#0-4) , which likewise register listeners that are only removed if the counterpart event actually fires; a malicious/looping counterparty controlling `device_address`/`body.address` combinations can similarly accumulate listeners, though these paths require more specific preconditions than `payment_notification`.

### Impact Explanation
An attacker who can exchange chat/wallet-protocol messages with a victim node (any correspondent device, including one from a single one-time chat interaction) can call `payment_notification` repeatedly with random 44-character strings. Each call permanently leaks one `EventEmitter` listener/closure that is never garbage collected. Sustained sending (cheap — no signature, no valid unit, no fee) drives unbounded heap growth in the victim node process, eventually leading to out-of-memory crash — an availability impact on the node (matches the "Availability High" component of the analogous CVE, CVSS A:H). This does not lead to fund loss or consensus divergence, but it can take down a full node or wallet backend that keeps this hub-connection channel open, which is a legitimate node-availability concern.

### Likelihood Explanation
High. No signature or valid unit is required, only a peer/device relationship sufficient to route a `payment_notification` message to the victim (which is a normal part of wallet-to-wallet/device chat functionality). The attack is trivial to script and can be sent at very high rate through the hub relay, since `handleMessageFromHub` returns `callbacks.ifOk()` immediately for unknown units without any per-request or per-peer accounting/back-pressure specific to this leak.

### Recommendation
- Track pending `payment_notification` listeners (e.g., in a map keyed by unit) with an expiry timestamp, and periodically sweep/`removeListener` entries that have exceeded a TTL (mirroring the pattern already used for `handledChainsCache` in the same file: [6](#0-5) ).
- Alternatively, avoid using per-unit dynamic event names entirely; instead maintain a bounded map from `unit -> array of pending callbacks` and clean it up on a single generic `'saved_unit'` event handler plus a periodic expiry sweep.
- Rate-limit `payment_notification` messages per correspondent device to bound the number of concurrently pending listeners.
- Apply the same fix pattern to the `signature-` and `new_address-` `eventBus.once` registrations that have no timeout/cleanup path.

### Proof of Concept
1. Establish a normal device-pairing/chat relationship with the victim node (any correspondent able to send hub messages, as already required for legitimate `payment_notification` use).
2. From the attacking device, repeatedly send `payment_notification` messages to the victim with `body` set to a freshly-generated random 44-character base64 string (satisfying `ValidationUtils.isStringOfLength(unit, constants.HASH_LENGTH)`) that does not correspond to any real, existing unit.
3. Each message causes the victim's `handleMessageFromHub` to execute `eventBus.once('saved_unit-'+unit, emitPn)` and then hit `ifNotFound`, leaving the listener registered permanently since the fabricated unit will never be saved.
4. Repeat at high frequency (no cost, no valid signatures required); observe the victim process's heap/listener count for the `saved_unit-*` event family growing without bound over time, eventually leading to increased memory pressure/OOM.

### Citations

**File:** wallet.js (L55-56)
```javascript
eventBus.on("handle_message_from_hub", handleMessageFromHub);
eventBus.on("message_for_light", handleLightJustsaying);
```

**File:** wallet.js (L386-401)
```javascript
						eventBus.once("signature-"+device_address+"-"+body.address+"-"+body.signing_path+"-"+text_to_sign, function(sig){
							sendSignature(from_address, text_to_sign, sig, body.signing_path, body.address);
						});
						// forward the offer to the actual signer
						device.sendMessageToDevice(device_address, subject, body);
						callbacks.ifOk();
					},
					ifMerkle: function(bLocal){
						callbacks.ifError("there is merkle proof at signing path "+body.signing_path);
					},
					ifUnknownAddress: function(){
						callbacks.ifError("not aware of address "+body.address+" but will see if I learn about it later");
						eventBus.once("new_address-"+body.address, function(){
							// rewrite callbacks to avoid duplicate unlocking of mutex
							handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, { ifOk: function(){}, ifError: function(){} });
						});
```

**File:** wallet.js (L426-452)
```javascript
			case 'payment_notification':
				// note that since the payments are public, an evil user might notify us about a payment sent by someone else 
				// (we'll be fooled to believe it was sent by the evil user).  It is only possible if he learns our address, e.g. if we make it public.
				// Normally, we generate a one-time address and share it in chat session with the future payer only.
				var current_message_counter = ++message_counter;
				var unit = body;
				if (!ValidationUtils.isStringOfLength(unit, constants.HASH_LENGTH))
					return callbacks.ifError("invalid unit in payment notification");
				var bEmitted = false;
				var emitPn = function(objJoint){
					if (bEmitted)
						return;
					bEmitted = true;
					emitNewPublicPaymentReceived(from_address, objJoint.unit, current_message_counter);
				};
				eventBus.once('saved_unit-'+unit, emitPn);
				storage.readJoint(db, unit, {
					ifNotFound: function(){
						console.log("received payment notification for unit "+unit+" which is not known yet, will wait for it");
						callbacks.ifOk();
					},
					ifFound: function(objJoint){
						emitPn(objJoint);
						eventBus.removeListener('saved_unit-'+unit, emitPn);
						callbacks.ifOk();
					}
				});
```

**File:** wallet.js (L948-953)
```javascript
var handledChainsCache = {};
setInterval(() => {
	for (let cache_key in handledChainsCache)
		if (handledChainsCache[cache_key] < Date.now() - 3600 * 1000)
			delete handledChainsCache[cache_key];
}, 3600 * 1000); // clear cache every hour
```

**File:** event_bus.js (L1-10)
```javascript
/*jslint node: true */
"use strict";
require('./enforce_singleton.js');

var EventEmitter = require('events').EventEmitter;

var eventEmitter = new EventEmitter();
eventEmitter.setMaxListeners(40);

module.exports = eventEmitter;
```
