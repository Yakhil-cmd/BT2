### Title
Unbounded private-payment chain length allows a counterparty to DoS/freeze private-payment processing on the recipient's node - ([File: indivisible_asset.js], [File: private_payment.js], [File: network.js], [File: wallet.js])

### Summary
Just like PartyB in the referenced report can open unlimited pending positions because no cap exists on the array it controls, an `ocore` private-payment counterparty (or asset issuer) can construct an arbitrarily long chain of private-payment "hops" (`arrPrivateElements`) with no upper bound on its length, and send it to a victim wallet/hub. The recipient must walk and validate the *entire* chain serially, one DB round-trip per hop, while holding a single global mutex key that serializes **all** private-payment processing for that node, before any length limit is ever checked.

### Finding Description
Private payments are represented as `arrPrivateElements`, a chain that is validated element-by-element in strict series:
- `parsePrivatePaymentChain` walks the whole array with `async.forEachOfSeries`, calling `validatePrivatePayment` on each element, which itself issues DB queries (`validateSpendProof`, `validateSourceOutput` → `graph.determineIfIncluded`) for every hop. [1](#0-0) 
- The chain is (re)built server-side the same way, recursively climbing to the issuance with `readPayloadAndGoUp`, with no depth cap. [2](#0-1) 

None of the entry points that accept an externally supplied chain enforce a maximum chain length:
- `validateAndSavePrivatePaymentChain` in `private_payment.js` only checks that the array is non-empty and that the head element has the expected shape — no cap on `arrPrivateElements.length`. [3](#0-2) 
- `handleOnlinePrivatePayment` in `network.js` only validates that the array is non-empty before persisting/queuing it and, for light clients, walks/queries the whole chain (`updateLinkProofsOfPrivateChain`, `findUnfinishedPastUnitsOfPrivateChains`). [4](#0-3) 
- `handlePrivatePaymentChains` in `wallet.js` (device-message handler, reachable by any correspondent) validates only per-element field shape (`isNonemptyObject`, `isNonemptyArray`, …), never the number of chain links, then hashes/serializes the whole array (`objectHash.getBase64Hash(arrChains)`, `JSON.stringify(arrPrivateElements)`). [5](#0-4) 

Crucially, this whole pipeline is serialized behind global mutex keys shared by *all* private payments handled by the node:
- `requestUnfinishedPastUnitsOfPrivateChains` takes `mutex.lock(["private_chains"], ...)` for the duration of resolving unfinished past units of a chain. [6](#0-5) 
- `handleSavedPrivatePayments` takes `mutex.lock(["saved_private"], ...)` (or `lockOrSkip`) while iterating and validating every saved chain, and explicitly early-returns while `"private_chains"` is locked, i.e. this queue drains only after the (possibly huge) chain finishes. [7](#0-6) 

An attacker who is a legitimate private-asset issuer/transfer counterparty (unprivileged, reachable via ordinary private-payment or device-message flows) can therefore construct a chain with an enormous number of hops (each hop only needs to reference the previous one consistently) and forward it to a victim. Because there is no cap on chain length anywhere in `private_payment.js`, `indivisible_asset.js`, `network.js`, or `wallet.js`, the victim node must perform a linear number of DB round-trips and CPU work while holding the shared `"private_chains"`/`"saved_private"` mutex, blocking validation/forwarding of every other legitimate private payment (including its own pending incoming/outgoing private payments) for as long as the malicious chain is being processed — mirroring exactly the "no limit on PartyB's positions → DoS of all functions relying on that unbounded structure" bug class from the report.

### Impact Explanation
This directly matches an acceptable impact category: freezing of funds/functionality. While the malicious chain is validated, all other private payments destined to or forwarded by the victim device are held up behind the shared mutex, so legitimate private payments (which carry real value, unlike public transfers) cannot be confirmed/forwarded for the victim, and the victim's wallet DB connection pool/CPU is tied up doing unbounded serial DB work. A determined counterparty can repeat this cheaply (each hop of the chain corresponds to a real chain of on-DAG transfers they must have made themselves once, but subsequently the *same* pre-built long chain can be resent/forwarded to any number of victims), producing a low-cost, high-duration DoS against private-payment processing.

### Likelihood Explanation
Likelihood is high: constructing a long private-transfer chain requires only ordinary indivisible-private-asset transfers (no special privilege, no consensus-level access), and every one of the externally reachable entry points (`handlePrivatePaymentChains` device message, `handleOnlinePrivatePayment` network message) accepts the chain without any length check before doing serial, per-hop DB validation under a global lock.

### Recommendation
Enforce an explicit maximum chain length (e.g. a `MAX_PRIVATE_CHAIN_LENGTH` constant) at the earliest possible validation points — `validateAndSavePrivatePaymentChain` in `private_payment.js`, `handleOnlinePrivatePayment` in `network.js`, and `handlePrivatePaymentChains` in `wallet.js` — rejecting/ignoring chains that exceed it before any DB work or mutex acquisition occurs. Additionally, avoid serializing unrelated private payments behind a single global `"private_chains"`/`"saved_private"` mutex key; key the lock per-chain (e.g. by head unit/asset) so that one oversized or slow chain cannot block the processing of unrelated private payments.

### Proof of Concept
1. Attacker (Bob) creates asset A as a fixed-denomination private asset and issues a coin to himself.
2. Bob repeatedly transfers the coin to himself N times (N = tens of thousands), each transfer being a valid on-DAG unit, producing a private-element chain of length N via `buildPrivateElementsChain`.
3. Bob sends the full `arrPrivateElements` chain (length N) as a private payment to Alice, either directly over the wire (`handleOnlinePrivatePayment`) or as a device message (`handlePrivatePaymentChains`).
4. Neither entry point rejects the chain based on length; Alice's node begins `parsePrivatePaymentChain`/`validateAndSavePrivatePaymentChain`, issuing O(N) serial DB queries while holding the shared `"private_chains"`/`"saved_private"` mutex.
5. While this runs, Alice's other legitimate private payments (sending and receiving) cannot be processed, and if N is large enough the operation can run for an extended period, effectively freezing Alice's private-payment functionality.

### Citations

**File:** indivisible_asset.js (L186-235)
```javascript
// arrPrivateElements is ordered in reverse chronological order
function parsePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	var bAllStable = true;
	var issuePrivateElement = arrPrivateElements[arrPrivateElements.length-1];
	if (!issuePrivateElement.payload || !issuePrivateElement.payload.inputs || !issuePrivateElement.payload.inputs[0])
		return callbacks.ifError("invalid issue private element");
	var asset = issuePrivateElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in issue private element");
	var denomination = issuePrivateElement.payload.denomination;
	if (!denomination)
		return callbacks.ifError("no denomination in issue private element");
	async.forEachOfSeries(
		arrPrivateElements,
		function(objPrivateElement, i, cb){
			if (!objPrivateElement.payload || !objPrivateElement.payload.inputs || !objPrivateElement.payload.inputs[0])
				return cb("invalid payload");
			if (!objPrivateElement.output)
				return cb("no output in private element");
			if (objPrivateElement.payload.asset !== asset)
				return cb("private element has a different asset");
			if (objPrivateElement.payload.denomination !== denomination)
				return cb("private element has a different denomination");
			var prevElement = null; 
			if (i+1 < arrPrivateElements.length){ // excluding issue transaction
				var prevElement = arrPrivateElements[i+1];
				if (prevElement.unit !== objPrivateElement.payload.inputs[0].unit)
					return cb("not referencing previous element unit");
				if (prevElement.message_index !== objPrivateElement.payload.inputs[0].message_index)
					return cb("not referencing previous element message index");
				if (prevElement.output_index !== objPrivateElement.payload.inputs[0].output_index)
					return cb("not referencing previous element output index");
			}
			validatePrivatePayment(conn, objPrivateElement, prevElement, {
				ifError: cb,
				ifOk: function(bStable, input_address){
					objPrivateElement.bStable = bStable;
					objPrivateElement.input_address = input_address;
					if (!bStable)
						bAllStable = false;
					cb();
				}
			});
		},
		function(err){
			if (err)
				return callbacks.ifError(err);
			callbacks.ifOk(bAllStable);
		}
	);
```

**File:** indivisible_asset.js (L619-721)
```javascript
function buildPrivateElementsChain(conn, unit, message_index, output_index, payload, handlePrivateElements){
	var asset = payload.asset;
	var denomination = payload.denomination;
	var output = payload.outputs[output_index];
	var hidden_payload = _.cloneDeep(payload);
	hidden_payload.outputs.forEach(function(o){
		delete o.address;
		delete o.blinding;
		// output_hash was already added
	});
	var arrPrivateElements = [{
		unit: unit,
		message_index: message_index,
		payload: hidden_payload,
		output_index: output_index,
		output: {
			address: output.address,
			blinding: output.blinding
		}
	}];
	
	function readPayloadAndGoUp(_unit, _message_index, _output_index){
		conn.query(
			"SELECT src_unit, src_message_index, src_output_index, serial_number, denomination, amount, address, asset, \n\
				(SELECT COUNT(*) FROM unit_authors WHERE unit=?) AS count_authors \n\
			FROM inputs WHERE unit=? AND message_index=?", 
			[_unit, _unit, _message_index],
			function(in_rows){
				if (in_rows.length === 0)
					throw Error("building chain: blackbyte input not found");
				if (in_rows.length > 1)
					throw Error("building chain: more than 1 input found");
				var in_row = in_rows[0];
				if (!in_row.address)
					throw Error("readPayloadAndGoUp: input address is NULL");
				if (in_row.asset !== asset)
					throw Error("building chain: asset mismatch");
				if (in_row.denomination !== denomination)
					throw Error("building chain: denomination mismatch");
				var input = {};
				if (in_row.src_unit){ // transfer
					input.unit = in_row.src_unit;
					input.message_index = in_row.src_message_index;
					input.output_index = in_row.src_output_index;
				}
				else{
					input.type = 'issue';
					input.serial_number = in_row.serial_number;
					input.amount = in_row.amount;
					if (in_row.count_authors > 1)
						input.address = in_row.address;
				}
				conn.query(
					"SELECT address, blinding, output_hash, amount, output_index, asset, denomination FROM outputs \n\
					WHERE unit=? AND message_index=? ORDER BY output_index", 
					[_unit, _message_index], 
					function(out_rows){
						if (out_rows.length === 0)
							throw Error("blackbyte output not found");
						var output = {};
						var outputs = out_rows.map(function(o){
							if (o.asset !== asset)
								throw Error("outputs asset mismatch");
							if (o.denomination !== denomination)
								throw Error("outputs denomination mismatch");
							if (o.output_index === _output_index){
								output.address = o.address;
								output.blinding = o.blinding;
							}
							return {
								amount: o.amount,
								output_hash: o.output_hash
							};
						});
						if (!output.address)
							throw Error("output not filled");
						var objPrivateElement = {
							unit: _unit,
							message_index: _message_index,
							payload: {
								asset: asset,
								denomination: denomination,
								inputs: [input],
								outputs: outputs
							},
							output_index: _output_index,
							output: output
						};
						arrPrivateElements.push(objPrivateElement);
						(input.type === 'issue') 
							? handlePrivateElements(arrPrivateElements)
							: readPayloadAndGoUp(input.unit, input.message_index, input.output_index);
					}
				);
			}
		);
	}
	
	var input = payload.inputs[0];
	(input.type === 'issue') 
		? handlePrivateElements(arrPrivateElements)
		: readPayloadAndGoUp(input.unit, input.message_index, input.output_index);
}
```

**File:** private_payment.js (L23-34)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
```

**File:** network.js (L2376-2410)
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
```

**File:** network.js (L2443-2454)
```javascript
// if unit is undefined, find units that are ready
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
```

**File:** network.js (L2566-2592)
```javascript
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

**File:** wallet.js (L955-984)
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
```
