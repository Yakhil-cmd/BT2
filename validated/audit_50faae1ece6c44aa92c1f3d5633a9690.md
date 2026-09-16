### Title
Memory Leak via Unbounded eventBus Listener Accumulation in Private Payment Chain Handling - (File: wallet.js)

### Summary
`handlePrivatePaymentChains()` in `wallet.js` registers a one-time `eventBus` listener (`eventBus.once(key, ...)`) for every private-payment chain it forwards to `network.handleOnlinePrivatePayment()`. The listener is only removed when the corresponding chain is later fully validated (`ifOk`/`ifError` in `network.handleSavedPrivatePayments()`), which emits the `key` event. If the chain can never be completed — e.g., its referenced unit never becomes available, or the stale row is silently purged from `unhandled_private_payments` by the periodic cleanup jobs — the `key` event is never emitted, `eventBus.removeListener` is never called, and the listener (together with the closures it captures: `ws`, `from_address`, `arrChains`, `callbacks`, `assocValidatedByKey`) stays attached to the shared, singleton `eventBus` object forever.

### Finding Description
`wallet.js` handles the `private_payments` subject sent by any paired device/counterparty: [1](#0-0) 

For every chain in the request it registers: [2](#0-1) 

The listener is a closure over `arrPrivateElements`, `assocValidatedByKey`, `ws`, `body`, `from_address`, and `callbacks`. It is removed only in two cases: (1) the corresponding validation completes and `network.js` emits the `key` event, or (2) `cancelAllKeys()` is triggered by a `false` result. Both paths depend on `network.js` eventually calling `eventBus.emit(key, ...)`: [3](#0-2) 

However, the record backing this emission (`unhandled_private_payments`) can be silently removed *without* ever emitting the key:

* `cleanBadSavedPrivatePayments()` (full node) deletes rows whose referenced unit never showed up after 1 day, with no `eventBus.emit`: [4](#0-3) 

* `requestUnfinishedPastUnitsOfPrivateChains()` (light client) likewise deletes stale rows after 1 day with no emission: [5](#0-4) 

* `updateLinkProofsOfPrivateChain()` deletes the chain via `deleteHandledPrivateChain` without ever emitting the `key` in the "not linked" branch: [6](#0-5) 

In every one of these paths the DB row disappears but the `eventBus.once(key, ...)` listener that `wallet.js` attached remains registered on the process-wide `eventBus` singleton (created once via `enforce_singleton.js`): [7](#0-6) 

Because `key` is built from `unit + payload_hash + output_index`, an attacker can trivially generate a large number of distinct keys, so `eventBus.setMaxListeners(40)` — which only limits listeners for the *same* event name — provides no protection: each malicious chain uses a fresh, unique event name, so listeners keep accumulating without limit.

This mirrors the root cause of the referenced report: a function is repeatedly invoked by an external/untrusted actor, allocates resources on each call, and fails to release them in certain (here: non-completion) code paths, leading to unbounded memory growth.

### Impact Explanation
Any private-payment counterparty (or any peer able to reach a device's `private_payments` handler) can repeatedly send crafted or incomplete private payment chains that are queued but never resolve (e.g., referencing a unit/chain segment that is withheld or never linked). Each such submission permanently leaks one `eventBus.once` listener plus its captured closure state (which includes the full `arrChains` payload). Sustained, low-cost repetition drives continuous memory growth in the victim's wallet/hub process, eventually exhausting available memory and crashing the process — an uncontrolled resource consumption / denial-of-service condition against a node that otherwise continues to run indefinitely.

### Likelihood Explanation
The trigger requires only sending well-formed-looking but never-completing private payment chains via the standard `private_payments` device message — no privileged access, no protocol violation, and no race condition is needed. The `handledChainsCache` dedupe (`wallet.js`, keyed by a hash of the whole chains array) can be trivially bypassed by varying any field (e.g., blinding factors, amounts, or unresolved unit references) between requests, so the attack can be repeated indefinitely by a single non-privileged counterparty.

### Recommendation
- In every code path that removes a row from `unhandled_private_payments` without validating it (`cleanBadSavedPrivatePayments`, the "not linked" branch of `updateLinkProofsOfPrivateChain`, and the stale-unit deletion in `requestUnfinishedPastUnitsOfPrivateChains`), emit the corresponding `private_payment_validated-...` key (with `false`) so that any pending `eventBus.once` listeners are triggered and cleaned up.
- Alternatively, track pending listeners explicitly (e.g., in a map alongside `assocValidatedByKey`) with a timeout that calls `eventBus.removeListener` directly, instead of relying solely on an eventual `emit` from `network.js`.
- Add a global cap / TTL on the number of outstanding `private_payment_validated-*` listeners per peer/device to bound worst-case memory usage.

### Proof of Concept
1. As a paired device/counterparty, send a `private_payments` message to a victim wallet with a chain whose head element references a `unit` that will never be delivered (or that fails the `checkThatEachChainElementIncludesThePrevious` link check on a light client).
2. `wallet.js`'s `handlePrivatePaymentChains()` stores the chain (`network.handleOnlinePrivatePayment` → `savePrivatePayment`) and registers `eventBus.once(key, ...)`.
3. Wait (or force) the row to be purged by `cleanBadSavedPrivatePayments` / `requestUnfinishedPastUnitsOfPrivateChains` / `updateLinkProofsOfPrivateChain`'s not-linked branch — none of these emit `key`.
4. The `eventBus.once` listener registered in step 2 remains attached forever.
5. Repeat steps 1–4 with a new asset/blinding/unit combination each time (to avoid `handledChainsCache` dedupe) to accumulate an unbounded number of leaked listeners/closures, observable via growing `eventBus.listenerCount()` totals and increasing process RSS over time.

### Citations

**File:** wallet.js (L420-424)
```javascript
			case 'private_payments':
				if (conf.bIgnorePrivatePayments)
					return callbacks.ifError("private payments are ignored");
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
```

**File:** wallet.js (L1033-1062)
```javascript
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
				ifError: function(error){
					console.log("handleOnlinePrivatePayment error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifValidationError: function(unit, error){
					console.log("handleOnlinePrivatePayment validation error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifAccepted: function(unit){
					console.log("handleOnlinePrivatePayment accepted");
					assocValidatedByKey[key] = true;
					cb(); // do not leak unit info to the hub
				},
				// this is the most likely outcome for light clients
				ifQueued: function(){
					console.log("handleOnlinePrivatePayment queued, will wait for "+key);
					eventBus.once(key, function(bValid){
						if (!bValid)
							return cancelAllKeys();
						assocValidatedByKey[key] = true;
						if (bParsingComplete)
							checkIfAllValidated();
						else
							console.log('parsing incomplete yet');
					});
					cb();
				}
```

**File:** network.js (L2478-2503)
```javascript
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
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

**File:** network.js (L2529-2544)
```javascript
// full only
function cleanBadSavedPrivatePayments(){
	if (conf.bLight || bCatchingUp)
		return;
	db.query(
		"SELECT DISTINCT unhandled_private_payments.unit FROM unhandled_private_payments LEFT JOIN units USING(unit) \n\
		WHERE units.unit IS NULL AND unhandled_private_payments.creation_date<"+db.addTime('-1 DAY'),
		function(rows){
			rows.forEach(function(row){
				breadcrumbs.add('deleting bad saved private payment '+row.unit);
				db.query("DELETE FROM unhandled_private_payments WHERE unit=?", [row.unit]);
			});
		}
	);
	
}
```

**File:** network.js (L2582-2588)
```javascript
				// get units that are still new or unstable after refreshing the history
				storage.filterNewOrUnstableUnits(arrUnits, async arrMissingUnits => {
					if (arrMissingUnits.length === 0) return finish();
					console.log(`will delete unhandled private payments whose units are not known after 1 day`, arrMissingUnits);
					await db.query(`DELETE FROM unhandled_private_payments WHERE unit IN(${arrMissingUnits.map(db.escape).join(', ')}) AND creation_date < ${db.addTime('-1 DAY')}`);
					finish();
				});
```

**File:** network.js (L2701-2705)
```javascript
	checkThatEachChainElementIncludesThePrevious(arrPrivateElements, function(bLinked){
		if (bLinked === null)
			return onFailure();
		if (!bLinked)
			return deleteHandledPrivateChain(unit, message_index, output_index, onFailure);
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
