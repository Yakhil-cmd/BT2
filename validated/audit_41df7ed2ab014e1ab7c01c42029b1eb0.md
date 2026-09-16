### Title
Unbounded growth of `unhandled_private_payments` via repeated bogus private-payment chains from a paired device - ([File: network.js])

### Summary
A paired device (correspondent) can call the `private_payments` device message handler repeatedly with well-formed but unresolvable private-payment chains (referencing units that will never be delivered/known). Each attempt is unconditionally persisted to the `unhandled_private_payments` table before any real validation of the referenced unit takes place, and the record is only removed when the chain is eventually validated (successfully or with error). If the attacker keeps sending new, never-resolving unit references, rows accumulate indefinitely, consuming disk/DB memory — the same bug class as CVE-2016-6188 (repeated "upload" attempts leave behind unbounded temporary state that is never cleaned up).

### Finding Description
Any paired device can send a `'private_payments'` message, which is routed to `handlePrivatePaymentChains(ws, body, from_address, callbacks)`: [1](#0-0) 

This function only performs shallow structural checks (non-empty arrays/objects, presence of `unit`/`payload`/`asset`/`inputs`/`outputs`) before handing each chain to `network.handleOnlinePrivatePayment`: [2](#0-1) 

Inside `handleOnlinePrivatePayment`, the only checks performed are that `unit` is a syntactically valid base64 hash and `message_index`/`output_index` are non-negative integers — there is no check on the size of `arrPrivateElements`, no rate limit, and no cap on how many distinct never-resolving chains can be queued: [3](#0-2) 

For any unit that is not yet known (`ifNew`) or known-but-unverified (`ifKnownUnverified`), the handler unconditionally calls `savePrivatePayment`, which inserts the full `JSON.stringify(arrPrivateElements)` blob into the `unhandled_private_payments` table and only requests the missing joint in the background: [4](#0-3) 

The `unhandled_private_payments` table is a persistent SQL table (not an in-memory bounded structure), keyed by `(unit, message_index, output_index)` with `INSERT OR IGNORE`, so an attacker simply varies these fields (e.g., using distinct random but well-formed unit hashes) to bypass de-duplication and add new rows on every attempt: [5](#0-4) 

Rows are only removed via `deleteHandledPrivateChain`, which is invoked exclusively from the `ifOk`/`ifError` callbacks of `validateAndSavePrivatePaymentChain` — i.e., only after the referenced unit is actually retrieved and validated: [6](#0-5) 

Because `unit` in the payload is attacker-controlled and can point to a unit hash that no peer will ever serve (a hash that simply doesn't correspond to any real DAG unit, or one deliberately never published), `requestNewMissingJoints`/`network.requestUnfinishedPastUnitsOfPrivateChains` will simply keep failing to resolve it, and the corresponding row in `unhandled_private_payments` is retained forever. There is no periodic purge/expiry job for stale `unhandled_private_payments` rows (unlike, e.g., the `handledChainsCache` cleanup interval used for successfully-processed chains in wallet.js): [7](#0-6) 

Repeating this from a paired device — each time with a new random-looking (but structurally valid) unit hash, a new `message_index`, and an arbitrarily large `payload`/`inputs`/`outputs` array (no size ceiling is enforced before the row is written) — lets the attacker grow `unhandled_private_payments` without bound.

### Impact Explanation
This is a resource-exhaustion vector reachable from a paired wallet device (the "private-payment counterparty"/paired device category explicitly in scope): an attacker-controlled paired device can force unbounded, permanent growth of the victim's SQL database via the `unhandled_private_payments` table, degrading node performance and eventually exhausting disk space, which can render the node unable to process further private payments or, at the extreme, unable to continue normal operation (denial of service). This mirrors the CVE-2016-6188 bug class: an unauthenticated/low-privilege actor repeatedly performs an "upload" (here, sending a private-payment chain) that leaves behind orphaned state that is never garbage-collected.

### Likelihood Explanation
Likelihood is moderate-to-high: no signature, proof-of-work, or fee is required for a paired device to submit a `private_payments` message; the only requirement is passing the shallow structural validation in `handlePrivatePaymentChains`. Constructing many syntactically-valid-but-unresolvable unit hashes is trivial (any 44-char base64 string of the correct length passes `ValidationUtils.isValidBase64`). The lack of any per-device rate limiting or storage quota on `unhandled_private_payments` means the attack can be automated and sustained indefinitely.

### Recommendation
- Enforce a maximum number of pending (unresolved) `unhandled_private_payments` rows per originating device/peer, and reject or drop new insertions beyond that cap.
- Add a size limit on the JSON payload stored per row (similar to the `MAX_STATE_VAR_VALUE_LENGTH`/`isTooBigObj` pattern used elsewhere in the codebase for AA triggers) before it is persisted.
- Add a periodic sweep (analogous to the `handledChainsCache` interval-based cleanup in wallet.js) that purges `unhandled_private_payments` rows older than a configurable TTL if their referenced unit was never resolved.
- Consider requiring proof that the referenced unit exists (e.g., checking that a joint is retrievable/known within a bounded time window) before persisting the chain rather than persisting first and resolving in the background indefinitely.

### Proof of Concept
1. Pair an attacker-controlled device with the victim wallet (as any legitimate correspondent).
2. Repeatedly send `'private_payments'` device messages of the form:
```json
{
  "subject": "private_payments",
  "body": {
    "chains": [[
      {
        "unit": "<random-valid-base64-44-char-string>",
        "message_index": 0,
        "payload": {
          "asset": "<any private asset unit hash the victim knows about>",
          "inputs": [{"unit":"...","message_index":0,"output_index":0}],
          "outputs": [{"address":"...","amount":1}]
        }
      }
    ]]
  }
}
```
3. Each call passes the structural checks in `handlePrivatePaymentChains` (wallet.js:955) and `handleOnlinePrivatePayment` (network.js:2376), and — since the referenced `unit` doesn't correspond to any real unit that peers can supply — the chain is written to `unhandled_private_payments` via `savePrivatePayment` and never cleaned up.
4. Repeating with fresh random `unit` values indefinitely grows the `unhandled_private_payments` table without bound, consuming disk space on the victim node.

### Citations

**File:** wallet.js (L420-424)
```javascript
			case 'private_payments':
				if (conf.bIgnorePrivatePayments)
					return callbacks.ifError("private payments are ignored");
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
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

**File:** wallet.js (L955-983)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
	if (!arrChains.every(c =>
		isNonemptyArray(c) &&
		c.every(e =>
			isNonemptyObject(e) &&
			isNonemptyString(e.unit) &&
			isNonemptyObject(e.payload) &&
			isNonemptyString(e.payload.asset) &&
			isNonemptyArray(e.payload.inputs) &&
			isNonemptyArray(e.payload.outputs) &&
			e.payload.inputs.every(isNonemptyObject) &&
			e.payload.outputs.every(isNonemptyObject)
		)
	))
		return callbacks.ifError("malformed private chain");
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
	}
```

**File:** network.js (L2376-2440)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit");
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index");
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index");

	var savePrivatePayment = function(cb){
		// we may receive the same unit and message index but different output indexes if recipient and cosigner are on the same device.
		// in this case, we also receive the same (unit, message_index, output_index) twice - as cosigner and as recipient.  That's why IGNORE.
		db.query(
			"INSERT "+db.getIgnore()+" INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)", 
			[unit, message_index, output_index, JSON.stringify(arrPrivateElements), bViaHub ? '' : ws.peer], // forget peer if received via hub
			function(){
				callbacks.ifQueued();
				if (cb)
					cb();
			}
		);
	};
	
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
	}

	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
		ifNew: function(){
			savePrivatePayment();
			// if received via hub, I'm requesting from the same hub, thus telling the hub that this unit contains a private payment for me.
			// It would be better to request missing joints from somebody else
			requestNewMissingJoints(ws, [unit]);
		},
		ifKnownUnverified: savePrivatePayment,
		ifKnownBad: function(){
			callbacks.ifValidationError(unit, "known bad");
		}
	});
```

**File:** network.js (L2479-2503)
```javascript
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
```

**File:** initial-db/byteball-sqlite.sql (L811-811)
```sql

```
