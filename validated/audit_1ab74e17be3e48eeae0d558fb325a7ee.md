### Title
Unbounded, strictly sequential private-payment chain validation allows griefing/freezing of privately-transferred funds - (File: `indivisible_asset.js`, `private_payment.js`)

### Summary
Private (hidden) asset payments in ocore are validated and accepted as a *chain* of transfers going all the way back to the issuance unit. Every hop of the chain must be validated strictly one after another, and there is no limit on how many hops a chain may contain. A malicious issuer/holder of a private asset can create an arbitrarily long chain of cheap, minimal self-transfers before finally sending the asset to a victim, forcing the victim's wallet (and any hub/full node forwarding the private elements) to perform an unbounded amount of sequential, per-hop database work before the payment can be accepted or spent. This mirrors the reported bug class: a queue/chain that must be processed strictly in order, with no way for a victim to "skip ahead" to just their own element, letting an attacker cheaply impose disproportionate processing cost on victims and freeze their newly received funds until the entire attacker-controlled history is walked.

### Finding Description
When a node receives a private payment, it does not just validate the single received element — it must validate `arrPrivateElements`, the full reverse-chronological chain from the current output back to the `issue` element, via `parsePrivatePaymentChain`: [1](#0-0) 

This uses `async.forEachOfSeries`, i.e., each element is validated only after the previous one succeeds, and each element's validation (`validatePrivatePayment`) performs multiple sequential DB round-trips (`validateSpendProof`, `validateSourceOutput` via `graph.determineIfIncluded`, and `validation.validatePayment`): [2](#0-1) [3](#0-2) 

There is no maximum length enforced anywhere on `arrPrivateElements`/the chain (no `MAX_CHAIN`/length check was found in the codebase). A sender can therefore construct a chain with an arbitrary number of hops (e.g., transferring the same private coin back-and-forth to their own addresses thousands of times, each hop costing only a minimal fee) before finally sending it to the victim.

On the light-client wallet side, before the payment can even be validated, `findUnfinishedPastUnitsOfPrivateChains` requires collecting/requesting every past unit referenced in the chain: [4](#0-3) [5](#0-4) 

and `handleOnlinePrivatePayment` in `network.js` persists the whole chain to `unhandled_private_payments` and processes it via `updateLinkProofsOfPrivateChain`/`rerequestLostJointsOfPrivatePayments`, which likewise walk the chain hop by hop: [6](#0-5) 

Because chain-building (`buildPrivateElementsChain`) also walks strictly one hop at a time via recursive sequential queries (`readPayloadAndGoUp`), there is no way to parallelize or bound the cost: [7](#0-6) 

This is structurally identical to the reported bug class: a queue (here, a private-payment chain) that must be fully processed in strict order before the "later" (victim's) element can be validated/spent, with no cap on how much cheap "filler" an attacker can insert ahead of the victim's item, and no way for the victim to jump their own item to the front.

### Impact Explanation
A victim who receives an attacker-crafted private payment with an extremely long chain is forced to:
- request and validate every intermediate unit and private element in the chain before their wallet will show the funds as usable/spendable, and
- pay disproportionate CPU/DB/network cost (unbounded number of sequential DB queries and, for light clients, unbounded catch-up/link-proof requests) merely to accept a private payment.

Until this chain is fully validated, the transferred private funds are effectively frozen/unusable for the victim (the output cannot be safely spent because `validateAndSavePrivatePaymentChain`/`initPrivatePaymentValidationState` require full-chain validation first). This matches the accepted impact category of AA/user fund freezing and forces victims (or hubs relaying such payments on their behalf) to expend excessive resources — a direct griefing vector with no cost proportional to the damage caused to the victim, consistent with the Medium-severity classification given to the original finding.

### Likelihood Explanation
Any unprivileged private-asset issuer/holder can trigger this: issuing a private asset and re-transferring it to oneself is cheap (only requires paying normal transaction fees for many small units), and no consensus rule limits the resulting chain length. Sending the final transfer to any target address (a normal wallet, an exchange, a service) forces that recipient into the expensive full-chain validation path automatically, without any special conditions required (unlike the original report which needed active vault positions). This makes the attack easy and reliably reproducible against any wallet or hub willing to accept a private payment from an unknown/adversarial party.

### Recommendation
- Introduce and enforce a maximum private-payment chain length (or a maximum total chain "cost"/hop count) that a node/wallet will accept or attempt to validate; reject longer chains outright and let the sender re-issue with a legitimately-created shorter chain.
- Allow chain validation and unit retrieval to be resumed/paused/canceled and to run with a bounded time/resource budget per user request, rather than requiring the entire chain to be pulled and validated atomically.
- Consider caching per-unit chain-validation results more aggressively (they already are cached in `outputs`/`inputs` tables for public/witnessed units) so repeated hops by the same attacker do not multiply cost linearly with chain length for every new recipient.

### Proof of Concept
1. Attacker issues a private (hidden-denomination) asset unit `U0` (an `issue` private element).
2. Attacker repeatedly composes indivisible/divisible private-asset payment units `U1 → U2 → ... → Un` (n very large, e.g. tens of thousands), each transferring the coin back to an address the attacker controls, via `composeIndivisibleAssetPaymentJoint`/`buildPrivateElementsChain` machinery in `indivisible_asset.js`. Each hop costs only the minimal per-unit network fee.
3. Attacker finally sends the coin in unit `Un+1` to the victim's address, and forwards the full private element chain `[Un+1, Un, ..., U1, U0]` to the victim via `network.handleOnlinePrivatePayment` / `wallet.js`'s `handlePrivatePaymentChains`.
4. The victim's node/wallet must call `parsePrivatePaymentChain` (`indivisible_asset.js:187`) which validates all `n+1` elements strictly in sequence (`async.forEachOfSeries`), each requiring several DB queries, and (for light wallets) must first fetch every referenced past unit via `findUnfinishedPastUnitsOfPrivateChains` (`private_payment.js:11`). No length cap stops the attacker from making `n` arbitrarily large, so the victim is forced to expend processing time/resources proportional to the attacker-chosen chain length before the received funds can be used, effectively freezing them and imposing outsized cost relative to the trivial cost paid by the attacker.

### Citations

**File:** indivisible_asset.js (L20-42)
```javascript
function validatePrivatePayment(conn, objPrivateElement, objPrevPrivateElement, callbacks){
		
	function validateSpendProof(spend_proof, cb){
		profiler.start();
		conn.query(
			"SELECT spend_proof, address FROM spend_proofs WHERE unit=? AND message_index=?", 
			[objPrivateElement.unit, objPrivateElement.message_index], 
			function(rows){
				profiler.stop('spend_proof');
				if (rows.length !== 1)
					return cb("expected 1 spend proof, found "+rows.length);
				var stored_spend_proof = rows[0].spend_proof;
				var spend_proof_address = rows[0].address;
				if (stored_spend_proof !== spend_proof)
					return cb("spend proof doesn't match");
				if (objPrevPrivateElement && objPrevPrivateElement.output.address !== spend_proof_address)
					return cb("spend proof address does not match src output");
				if (input.address && input.address !== spend_proof_address)
					return cb("spend proof address does not match issuer address");
				cb();
			}
		);
	}
```

**File:** indivisible_asset.js (L86-180)
```javascript
	profiler.start();
	validation.initPrivatePaymentValidationState(
		conn, objPrivateElement.unit, objPrivateElement.message_index, payload, callbacks.ifError, 
		function(bStable, objPartialUnit, objValidationState){
		
			profiler.stop('initPrivatePaymentValidationState');
			var arrFuncs = [];
			var spend_proof;
			var input_address; // from which address the money is sent
			if (!input.type){ // transfer
				if (typeof input.unit !== 'string')
					return callbacks.ifError("invalid unit in private payment");
				if (!ValidationUtils.isNonnegativeInteger(input.message_index))
					return callbacks.ifError("invalid input message_index");
				if (!ValidationUtils.isNonnegativeInteger(input.output_index))
					return callbacks.ifError("invalid input output_index");
				if (!objPrevPrivateElement || !objPrevPrivateElement.output || !objPrevPrivateElement.output.blinding)
					return callbacks.ifError("no prev output blinding");
				if (!objPrevPrivateElement.payload || !objPrevPrivateElement.payload.outputs)
					return callbacks.ifError("no prev outputs");
				var src_output = objPrevPrivateElement.output;
				var prev_hidden_output = objPrevPrivateElement.payload.outputs[input.output_index];
				if (!prev_hidden_output)
					return callbacks.ifError("no prev hidden output");
				input_address = src_output.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						unit: input.unit,
						message_index: input.message_index,
						output_index: input.output_index,
						address: src_output.address,
						amount: prev_hidden_output.amount,
						blinding: src_output.blinding
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc transfer spend proof: " + e.message);
				}
				console.log("validation spend proof: "+JSON.stringify({
					asset: payload.asset,
					unit: input.unit,
					message_index: input.message_index,
					output_index: input.output_index,
					address: src_output.address,
					amount: prev_hidden_output.amount,
					blinding: src_output.blinding
				}));
				arrFuncs.push(validateSourceOutput);
				objValidationState.src_coin = {
					src_output: src_output,
					denomination: payload.denomination,
					amount: prev_hidden_output.amount
				};
			}
			else if (input.type === 'issue'){
				if (objPrevPrivateElement)
					return callbacks.ifError("prev payload and initial input");

				input_address = (objPartialUnit.authors.length === 1) ? objPartialUnit.authors[0].address : input.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						address: input_address,
						serial_number: input.serial_number, // need to avoid duplicate spend proofs when issuing uncapped coins
						denomination: payload.denomination,
						amount: input.amount
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc issue spend proof: " + e.message);
				}
			}
			else
				return callbacks.ifError("neither transfer nor issue in private input");
			
			if (!objPartialUnit.authors.some(function(author){ return (author.address === input_address); }))
				return callbacks.ifError("input address not found among unit authors");

			arrFuncs.push(function(cb){
				validateSpendProof(spend_proof, cb);
			});
			arrFuncs.push(function(cb){
				// we need to unhide the single output we are interested in, other outputs stay partially hidden like {amount: 300, output_hash: "base64"}
				var partially_revealed_payload = _.cloneDeep(payload);
				var our_output = partially_revealed_payload.outputs[objPrivateElement.output_index];
				our_output.address = objPrivateElement.output.address;
				our_output.blinding = objPrivateElement.output.blinding;
				validation.validatePayment(conn, partially_revealed_payload, objPrivateElement.message_index, objPartialUnit, objValidationState, cb);
			});
			async.series(arrFuncs, function(err){
			//	profiler.stop('validatePayment');
				err ? callbacks.ifError(err) : callbacks.ifOk(bStable, input_address);
			});
		}
```

**File:** indivisible_asset.js (L186-236)
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
}
```

**File:** indivisible_asset.js (L640-720)
```javascript
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
```

**File:** private_payment.js (L11-20)
```javascript
function findUnfinishedPastUnitsOfPrivateChains(arrChains, includeLatestElement, handleUnits){
	var assocUnits = {};
	arrChains.forEach(function(arrPrivateElements){
		assocUnits[arrPrivateElements[0].payload.asset] = true; // require asset definition
		for (var i = includeLatestElement ? 0 : 1; i<arrPrivateElements.length; i++) // skip latest element
			assocUnits[arrPrivateElements[i].unit] = true;
	});
	var arrUnits = Object.keys(assocUnits);
	storage.filterNewOrUnstableUnits(arrUnits, handleUnits);
}
```

**File:** private_payment.js (L113-118)
```javascript
	if (conf.bLight)
		findUnfinishedPastUnitsOfPrivateChains([arrPrivateElements], false, function(arrUnfinishedUnits){
			(arrUnfinishedUnits.length > 0) ? callbacks.ifWaitingForChain() : validateAndSave();
		});
	else
		validateAndSave();
```

**File:** network.js (L2404-2410)
```javascript
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
	}
```
