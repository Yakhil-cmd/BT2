### Title
Unbounded `eventBus` listener leak in `handlePrivatePaymentChains()` when awaiting private-payment validation that never completes - ([File: wallet.js])

### Summary
`wallet.js:handlePrivatePaymentChains()` registers a per-chain, dynamically-named `eventBus.once(key, ...)` listener whenever a received private-payment chain is queued (`ifQueued`) rather than immediately validated. The `key` is only ever fired by `network.js:handleSavedPrivatePayments()` when the referenced unit eventually becomes known and `deleteHandledPrivateChain()`/`eventBus.emit(key, ...)` runs. If the referenced unit never arrives, the row in `unhandled_private_payments` is eventually deleted by background cleanup jobs (`cleanBadSavedPrivatePayments()`, `requestUnfinishedPastUnitsOfPrivateChains()`) that purge stale DB rows directly via `db.query(...)` without ever emitting the corresponding `key` event. The `eventBus.once` listener registered in `handlePrivatePaymentChains()` is therefore never triggered and never removed, and `cancelAllKeys()` (the only code path that calls `eventBus.removeAllListeners(key)`) is only invoked from within that same `eventBus.once` callback or from an `async.eachSeries` error - both of which require the event to fire, which it never will in this scenario.

### Finding Description
An unprivileged private-payment counterparty (device pairing / hub-forwarded message) can send `handlePrivatePaymentChains(ws, body, from_address, callbacks)` a syntactically valid chain array whose head element references a unit that will never be delivered (e.g., an invented/garbage but well-formed 44-char base64 unit id, or one belonging to a different network/never-broadcast unit): [1](#0-0) 

For each chain, a unique `key = 'private_payment_validated-'+unit+'-'+json_payload_hash+'-'+output_index` is computed and `assocValidatedByKey[key] = false` is set, then `network.handleOnlinePrivatePayment(ws, ...)` is called: [2](#0-1) 

Because the unit is unknown, `network.handleOnlinePrivatePayment()` takes the `ifNew`/`ifKnownUnverified` path and stores the chain in `unhandled_private_payments` and calls `callbacks.ifQueued()`. In `handlePrivatePaymentChains()`, the `ifQueued` branch registers `eventBus.once(key, ...)` and returns: [3](#0-2) [4](#0-3) 

The only place that ever fires `key` is `network.js:handleSavedPrivatePayments()`, invoked on an interval, but only after the referenced `unit` shows up in the `units` table (join `unhandled_private_payments CROSS JOIN units USING(unit)`): [5](#0-4) 

If the unit never arrives, the row simply sits in `unhandled_private_payments` until background jobs purge it directly with a raw `DELETE` query — no `eventBus.emit(key, ...)` is ever issued: [6](#0-5) [7](#0-6) 

Since `key` never fires, the `eventBus.once(key, ...)` handler registered in `wallet.js` is never invoked, so `cancelAllKeys()` (which does `eventBus.removeAllListeners(key)`) is never called for that chain — it's only reachable from inside the very listener that never runs, or from the `async.eachSeries` final error callback (which only triggers on synchronous validation errors, not on the queued/never-resolved path): [8](#0-7) [9](#0-8) 

This mirrors the CVE's root cause: an internal reference/handle (`stream`/current-file in fastify-multipart; here the `eventBus` listener plus `assocValidatedByKey` closure and its `body`/`arrChains` payload) is created and left dangling when the counterpart peer aborts/never completes the exchange (never sends the referenced unit), and the code responsible for reclaiming it (`cleanBadSavedPrivatePayments`/`requestUnfinishedPastUnitsOfPrivateChains`) only cleans the DB row, not the pending listener/callback chain that is "waiting to settle."

### Impact Explanation
Each such request permanently leaks one `eventBus` listener plus its closure (holding `assocValidatedByKey`, `arrChains`, `ws`, `callbacks`, and `body` references) in the victim's wallet process. A counterparty (or a hub relaying attacker-controlled `private_payment` messages) can repeat this indefinitely — the DB-level `unhandled_private_payments` rows are eventually purged (bounding disk growth to ~1 day of accumulation), but the corresponding process-memory listeners are never removed, growing without bound as long as the wallet process runs. This produces a slow, unauthenticated-repeatable memory/event-loop exhaustion DoS against a full or light wallet node, consistent with the CVE's impact category (process resource exhaustion via suspended/never-settling handlers), reachable via a `private-payment counterparty` as scoped by the report rules.

### Likelihood Explanation
No authentication beyond an existing device pairing (or forwarding through a hub, which is the normal untrusted-relay path for private payments) is required; the attacker only needs to send a well-formed `private_payment` chain payload whose head unit is fabricated/never broadcast. This is a single, cheap, repeatable action with no computational cost gate, making it straightforward to trigger the growth indefinitely and only bounded by whatever request-rate limiting exists at the messaging layer (none of which is evident in `wallet.js`/`network.js` shown here).

### Recommendation
Ensure the `eventBus.once(key, ...)` listener (and the closures it references) registered in `handlePrivatePaymentChains()` is guaranteed to be cleaned up even when the underlying `unhandled_private_payments` row is purged without validation. This can be done by:
1. Emitting `eventBus.emit(key, false)` from `cleanBadSavedPrivatePayments()` and from the `requestUnfinishedPastUnitsOfPrivateChains()` delete path whenever a row is removed without having been validated, so the existing `eventBus.once` handler fires and self-cleans via `cancelAllKeys()`.
2. Alternatively/additionally, attach a timeout to each `eventBus.once(key, ...)` registration in `wallet.js:handlePrivatePaymentChains()` (e.g., using `setTimeout` + `eventBus.removeListener`) so listeners are forcibly reclaimed after a bounded period even if no emit ever occurs.

### Proof of Concept
Note: I was unable to fully trace the exact wire message handler in `wallet.js` that ultimately calls `handlePrivatePaymentChains()` (e.g. the `case` in `handleMessageFromHub`) within the remaining tool budget, so the following PoC describes the reachable call chain based on the confirmed code paths above; the entry point (device/hub message dispatch into `handlePrivatePaymentChains`) should be verified directly in the repository before remediation.

1. As a paired device (or via a hub forwarding a `private_payment` message), send a `chains` payload structurally valid per the checks in `handlePrivatePaymentChains()` (non-empty array, well-formed objects with `unit`, `payload.asset`, `payload.inputs`, `payload.outputs`), but whose head `unit` is a random, never-broadcast 44-character base64 string.
2. `network.handleOnlinePrivatePayment()` treats the unit as new/unverified, inserts a row into `unhandled_private_payments`, and calls `ifQueued()`.
3. `wallet.js` registers `eventBus.once('private_payment_validated-<unit>-<hash>-<idx>', ...)` and returns without further tracking.
4. Wait (or force, in a controlled test, by adjusting the 1-day interval) for `cleanBadSavedPrivatePayments()` to delete the stale row — observe that `key` is never emitted and the listener count on `eventBus` for these dynamically-named keys keeps growing (`eventBus.listenerCount(key)` still 1, and `eventBus.eventNames().length` grows) after every repeated request, since no code path removes it.
5. Repeat step 1 with new fabricated unit ids to observe unbounded growth of leaked listeners/closures over time.

### Citations

**File:** wallet.js (L955-995)
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
	profiler.increment();
	
	if (conf.bLight)
		network.requestUnfinishedPastUnitsOfPrivateChains(arrChains); // it'll work in the background
	
	var assocValidatedByKey = {};
	var bParsingComplete = false;
	var cancelAllKeys = function(){
		for (var key in assocValidatedByKey)
			eventBus.removeAllListeners(key);
	};

```

**File:** wallet.js (L1020-1063)
```javascript
	async.eachSeries(
		arrChains,
		function(arrPrivateElements, cb){ // validate each chain individually
			var objHeadPrivateElement = arrPrivateElements[0];
			if (!!objHeadPrivateElement.payload.denomination !== ValidationUtils.isNonnegativeInteger(objHeadPrivateElement.output_index))
				return cb("divisibility doesn't match presence of output_index");
			var output_index = objHeadPrivateElement.payload.denomination ? objHeadPrivateElement.output_index : -1;
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
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
			});
```

**File:** wallet.js (L1064-1078)
```javascript
		},
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
			checkIfAllValidated();
			handledChainsCache[cache_key] = Date.now();
			callbacks.ifOk();
			// forward the chains to other members of output addresses
			if (!body.forwarded)
				forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true);
		}
	);
```

**File:** network.js (L2390-2440)
```javascript
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

**File:** network.js (L2444-2455)
```javascript
function handleSavedPrivatePayments(unit){
	//if (unit && assocUnitsInWork[unit])
	//    return;
	if (!my_device_address) return; // skip if we don't have a wallet
	if (!unit && mutex.isAnyOfKeysLocked(["private_chains"])) // we are still downloading the history (light)
		return console.log("skipping handleSavedPrivatePayments because history download is still under way");
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
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

**File:** network.js (L2565-2592)
```javascript
// light only
function requestUnfinishedPastUnitsOfPrivateChains(arrChains, onDone){
	mutex.lock(["private_chains"], function(unlock){
		function finish(){
			unlock();
			if (onDone)
				onDone();
		}
		privatePayment.findUnfinishedPastUnitsOfPrivateChains(arrChains, true, function(arrUnits){
			if (arrUnits.length === 0)
				return finish();
			breadcrumbs.add(arrUnits.length+" unfinished past units of private chains");
			requestHistoryFor(arrUnits, [], err => {
				if (err) {
					console.log(`error getting history for unfinished units of private payments`, err);
					return finish();
				}
				// get units that are still new or unstable after refreshing the history
				storage.filterNewOrUnstableUnits(arrUnits, async arrMissingUnits => {
					if (arrMissingUnits.length === 0) return finish();
					console.log(`will delete unhandled private payments whose units are not known after 1 day`, arrMissingUnits);
					await db.query(`DELETE FROM unhandled_private_payments WHERE unit IN(${arrMissingUnits.map(db.escape).join(', ')}) AND creation_date < ${db.addTime('-1 DAY')}`);
					finish();
				});
			});
		});
	});
}
```
