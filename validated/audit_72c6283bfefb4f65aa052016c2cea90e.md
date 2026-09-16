## Analysis

The private (indivisible) asset payment chain in `indivisible_asset.js` is a direct structural analog to the LayerEdge `stakerTierHistory` bug: an array (`arrPrivateElements`, the ownership history of a single private coin) grows by one element every time the coin is transferred, and **every future transfer must re-validate and re-walk the entire chain from the current owner all the way back to the original issuance**, with no length cap.

### Title
Unbounded growth of private (indivisible) asset payment chains causes validation cost to scale linearly forever, permanently freezing the coin - (File: indivisible_asset.js)

### Summary
`buildPrivateElementsChain()` and `parsePrivatePaymentChain()` in `indivisible_asset.js` reconstruct and validate the *complete* transfer history of a private indivisible-asset output every time it is spent again. Nothing bounds the number of hops in this chain, so repeated transfers (whether organic or attacker-driven self-transfers) make the chain, and therefore the per-spend validation cost, grow without limit — eventually making the coin practically impossible to spend/validate.

### Finding Description
When a private (indivisible) asset output is spent, the sender must supply `arrPrivateElements`, an array representing the full transfer chain from the original issuance to the current output. `buildPrivateElementsChain()` walks this chain backwards recursively via `readPayloadAndGoUp()`, following the `inputs` table until it reaches an `issue` input: [1](#0-0) [2](#0-1) 

On the receiving/validating side, `parsePrivatePaymentChain()` then iterates the entire chain with `async.forEachOfSeries`, calling `validatePrivatePayment()` (which itself issues DB queries and a `graph.determineIfIncluded` DAG-inclusion check) for **every single element in the chain**, regardless of chain length: [3](#0-2) 

`validatePrivatePayment()` performs a spend-proof lookup and (when not light) a `graph.determineIfIncluded` traversal for each hop: [4](#0-3) 

There is no maximum enforced anywhere on the length of `arrPrivateElements` / the depth of the transfer chain (no `MAX_..._CHAIN_LENGTH` type constant exists for this path, unlike other size caps present elsewhere in the codebase such as `MAX_MESSAGES_PER_UNIT`, `MAX_COMPLEXITY`, etc.). Each transfer of the same coin appends one more link, and every subsequent transfer/validation must redo the full walk from tip to issuance — an unbounded, ever-growing computation, exactly mirroring the reported `stakerTierHistory` pattern where a per-user history array is iterated in full on every action and grows with every state transition.

An unprivileged coin holder can trivially inflate the chain length by repeatedly self-transferring the same private indivisible-asset coin to themselves (posting normal payment units), each hop being a cheap, ordinary transaction. Because private-asset spends require the *sender* to hand the *entire* chain to the recipient/hub (`arrPrivateElements`), and the recipient/light-vendor/full node must reconstruct/re-validate that whole chain (`buildPrivateElementsChain`, `restorePrivateChains`, `parsePrivatePaymentChain`), the cost of any single further transfer is proportional to the total historical transfer count of that specific coin — with no ceiling.

### Impact Explanation
As the chain length grows (organically through normal re-spending, or deliberately through repeated self-transfers), the per-spend cost of walking and validating the entire private chain grows without bound. Beyond some length, validating (or even composing) a further transfer of that coin becomes computationally infeasible within practical time/DB-round-trip budgets, so the coin can no longer be reliably spent, received, or proven — its value becomes effectively frozen/lost to its owner, mirroring the "affected user loses all staked funds and can never withdraw" impact in the reference report, but here applied to indivisible private-asset coins.

### Likelihood Explanation
Likelihood is high for a determined attacker and non-trivial even organically: a coin holder only needs to keep transferring the same private coin (e.g., self-transfers) some number of times using ordinary wallet operations to grow the chain; every additional transfer is cheap for the attacker but linearly increases the cost imposed on all future validators of that coin (including the attacker's own future spends, or, if griefing someone else, the recipient who must reconstruct the whole history to accept the payment).

### Recommendation
Impose an explicit maximum depth/length on private payment chains (`arrPrivateElements`), rejecting or refusing to walk/validate chains beyond that bound, similar to the size/complexity limits already enforced elsewhere (`MAX_MESSAGES_PER_UNIT`, `MAX_COMPLEXITY`, `MAX_OPS`). Alternatively, introduce a mechanism to "collapse"/checkpoint historical chain segments (e.g., periodic re-issuance or a stored proof of prior validity) so that spending no longer requires re-walking the full history from genesis on every transfer.

### Proof of Concept
Conceptually:
1. Issue a private indivisible-asset coin to address A.
2. A repeatedly self-transfers the coin to itself N times (each a normal `payment` unit with a `transfer` input referencing the previous output), growing `arrPrivateElements`'s effective depth to N.
3. On the N+1-th transfer, the sender must compose/serialize the full N-element chain (`buildPrivateElementsChain`), and any validating peer (recipient, hub, or full node in `parsePrivatePaymentChain`) must sequentially validate all N elements, each requiring a DB round trip and a `graph.determineIfIncluded` DAG walk.
4. As N grows (attacker fully controls this via cheap repeated self-spends), validation time/resources grow linearly without bound, eventually preventing the transfer from completing within acceptable time, effectively freezing the coin. [5](#0-4) [3](#0-2)

### Citations

**File:** indivisible_asset.js (L20-52)
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
	
	function validateSourceOutput(cb){
		if (conf.bLight)
			return cb(); // already validated the linkproof
		profiler.start();
		graph.determineIfIncluded(conn, input.unit, [objPrivateElement.unit], function(bIncluded){
			profiler.stop('determineIfIncluded');
			bIncluded ? cb() : cb("input unit not included");
		});
	}
```

**File:** indivisible_asset.js (L187-236)
```javascript
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
