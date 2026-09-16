## Analysis

This maps to a valid DoS analog in ocore's private payment chain handling, reachable by an unprivileged **private-payment counterparty**.

### Title
Unbounded private payment chain length causes DoS via unbounded sequential validation - ([File: private_payment.js])

### Summary
`validateAndSavePrivatePaymentChain` and the network/wallet entry points that feed it (`handleOnlinePrivatePayment` in `network.js`, `handlePrivatePaymentChains` in `wallet.js`) accept an `arrPrivateElements`/`arrChains` array from a private-payment counterparty (or a paired device relaying such a payment) with no upper bound on the number of chain elements, unlike ordinary units which are capped by `constants.MAX_MESSAGES_PER_UNIT`, `MAX_INPUTS_PER_PAYMENT_MESSAGE`, etc. Each element in the chain triggers sequential per-element DB validation.

### Finding Description
A private (indivisible/divisible) asset payment is delivered as a chain of private elements representing the full history of that coin back to issuance. The chain is walked with `async.forEachOfSeries`/`async.eachSeries`, performing DB queries and signature/spend-proof checks for every element: [1](#0-0) [2](#0-1) 

The entry points that accept this attacker-controlled chain from the network or from a paired device do not enforce a maximum chain length: [3](#0-2) [4](#0-3) 

Unlike unit-level messages/inputs/outputs, which are explicitly bounded (`MAX_MESSAGES_PER_UNIT=128`, `MAX_INPUTS_PER_PAYMENT_MESSAGE=128`, `MAX_OUTPUTS_PER_PAYMENT_MESSAGE=128` in `constants.js`), there is no analogous `MAX_PRIVATE_CHAIN_LENGTH` constant applied before the chain is iterated element-by-element in `parsePrivatePaymentChain` / `validateAndSavePrivatePaymentChain`. Each element also causes a DB query and, on double-spend, acquires the `["private_write"]` global mutex: [5](#0-4) 

A malicious counterparty (or colluding paired device) can construct/forward an artificially long private chain (thousands of hops, each cheap to fabricate since only the head element needs a real spend proof matching a real unit — attacker fully controls off-chain construction of a private chain of hidden outputs before ever posting a real on-chain unit) and send it via `private_payment` justsaying or `private_payments_chains` device message, forcing the receiving node/wallet to process the whole chain synchronously and sequentially.

### Impact Explanation
Processing an arbitrarily long chain ties up the wallet/node in sequential DB round-trips and can hold the `private_write` mutex during double-spend handling, delaying or blocking processing of legitimate payments and other write operations on that node. This is a resource-exhaustion DoS against the specific recipient node/wallet analogous to the Gitcoin `getApplicationIndexesByProjectID` issue: an unbounded, attacker-grown structure is fully processed in one synchronous pass, making the corresponding function/feature (receiving private payments) unusable for the victim.

### Likelihood Explanation
Any private-payment counterparty (or paired device forwarding a chain) can trigger this without needing any special privilege — building a fabricated long chain of private elements only requires local computation of hashes/blinding, not network confirmation. The likelihood is moderate: it requires the target to accept/process the malicious counterparty's payment, but this is the ordinary operation of receiving a private payment.

### Recommendation
Enforce an explicit maximum length (e.g., `constants.MAX_PRIVATE_CHAIN_LENGTH`) on `arrPrivateElements`/each chain in `arrChains` before iterating, in `handleOnlinePrivatePayment` (`network.js`), `handlePrivatePaymentChains` (`wallet.js`), and `validateAndSavePrivatePaymentChain` (`private_payment.js`), rejecting chains that exceed a sane bound (mirroring the existing unit-level anti-spam limits in `constants.js`).

### Proof of Concept
1. Attacker crafts a private indivisible-asset coin chain locally: an issue element followed by N (e.g., 50,000) chained transfer elements, each referencing the previous one's hidden output, without ever posting these units on the DAG except the final head unit.
2. Attacker sends this via `private_payment` (`network.js: sendPrivatePaymentToWs`) or bundles it in a `private_payments_chains` device message (`wallet.js: handlePrivatePaymentChains`) to the victim.
3. Victim's node calls `validateAndSavePrivatePaymentChain` → `parsePrivatePaymentChain`/`indivisible_asset.validateAndSavePrivatePaymentChain`, which sequentially validates all N elements with DB queries each, consuming excessive time/CPU/DB connections and potentially holding the `private_write` mutex, degrading or denying the victim's ability to process further payments.

### Citations

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

**File:** network.js (L2376-2411)
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

**File:** wallet.js (L955-972)
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
```

**File:** validation.js (L2283-2295)
```javascript
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
```
