### Title
Unbounded in-memory recursion when rebuilding private-payment chains can OOM-crash a node - ([File: indivisible_asset.js])

### Summary
The reported BtcPoller bug is a class of "collect unbounded data into memory before a single commit" defect: a loop with no upper bound accumulates results in an array and only writes them out once the whole range has been traversed. In `ocore`, the function `buildPrivateElementsChain` in `indivisible_asset.js` exhibits the same pattern for indivisible (blackbyte-style) private asset payments: it walks the private-payment chain backwards from the head element to the original issuance, recursively pushing every hop into `arrPrivateElements` in memory, with no depth limit and no incremental flush/commit. [1](#0-0) [2](#0-1) 

### Finding Description
`buildPrivateElementsChain(conn, unit, message_index, output_index, payload, handlePrivateElements)` starts with the head element of a payment chain and, unless the input is of type `issue`, recursively calls `readPayloadAndGoUp` to fetch the previous hop's `inputs`/`outputs` and pushes a new `objPrivateElement` onto `arrPrivateElements` for every hop, continuing until it finally reaches an `issue` input: [3](#0-2) 

There is no cap on the number of hops that can be traversed, and the whole chain is materialized in memory (`arrPrivateElements`) before `handlePrivateElements` is invoked. This function is reached from two important call paths:
1. When composing a new private payment, via `getSavingCallbacks`'s `preCommitCallback`, which calls `buildPrivateElementsChain` for every output and then immediately calls `validateAndSavePrivatePaymentChain(conn, _.cloneDeep(arrPrivateElements), ...)`, cloning and persisting the whole chain inside one connection/transaction context. [4](#0-3) 
2. When restoring wallet history via `restorePrivateChains`, which likewise builds the full chain for every relevant output. [5](#0-4) 

Because indivisible-asset transfers can be re-spent (transferred) an unlimited number of times before being consumed, an unprivileged private-payment counterparty can deliberately construct — and repeatedly forward to a victim — a coin that has been transferred through an extremely large number of hops (e.g. tens or hundreds of thousands of chained "transfer" private elements) before finally being spent or restored. When the victim's wallet later composes a payment using that coin, or restores/rebuilds its private-chain history, `buildPrivateElementsChain` recurses through every hop, holding the complete chain (units, message indexes, inputs, outputs, blinding factors) in memory at once, and the save path additionally deep-clones the whole array (`_.cloneDeep(arrPrivateElements)`), doubling memory pressure just before writing every hop's rows in a single `async.series` batch of SQL queries (`validateAndSavePrivatePaymentChain`, `parsePrivatePaymentChain`). [6](#0-5) 

This mirrors the `BtcPoller.Bootstrap` bug exactly: a loop that cannot be bounded by policy (there, activation height cannot change; here, the chain length is decided by the adversarial counterparty who created/forwarded the coin) accumulates the entire history in RAM and only commits once the full traversal completes.

### Impact Explanation
A sufficiently long private-payment chain forces the victim's node to allocate memory proportional to the number of hops when it (a) composes a spend using the tainted coin or (b) restores/reconstructs the chain for wallet history. If the chain is deep enough, this can exhaust process memory and crash the node/wallet process, denying it the ability to spend or track its own private funds — a loss-of-availability impact directly analogous to the "staking indexer can't be started" impact in the original report. Because private-payment validation and saving happen inside a single open DB transaction (`conn.query("BEGIN") ... validateAndSavePrivatePaymentChain`), a crash mid-way can also leave partially-applied state depending on transaction rollback behavior, though the primary and clearest impact is denial of service against the wallet/node processing the coin.

### Likelihood Explanation
Any private-payment counterparty can create arbitrarily long transfer chains for indivisible assets simply by repeatedly re-transferring the same coin between addresses they control before finally sending it to the victim — this requires no special privilege, no protocol violation, and no cooperation from witnesses or hubs. Because indivisible assets are commonly used for private payments in ocore/Obyte, and building/forwarding such deep chains is entirely within the normal capabilities of a private-payment sender, the likelihood of triggering this is comparable to or higher than the original Babylon bootstrap scenario (which only required "starting a new server after some time").

### Recommendation
Impose an explicit maximum chain depth (e.g., a `MAX_PRIVATE_CHAIN_LENGTH` constant) in `buildPrivateElementsChain`, aborting with an error if the recursion exceeds that limit before continuing. Additionally, avoid holding the whole chain in memory for validation and saving: process and persist each hop incrementally as it is fetched (similar to the recommended fix for `BtcPoller.Bootstrap`, which commits in fixed-size batches instead of buffering everything), and avoid the extra `_.cloneDeep(arrPrivateElements)` when passing the chain into `validateAndSavePrivatePaymentChain`.

### Proof of Concept
1. Attacker creates an indivisible-asset coin (`issue`).
2. Attacker repeatedly performs private "transfer" hops of the same coin between addresses they control, N times (N large, e.g. 100,000), each hop referencing the previous one via `payload.inputs[0]` (`unit`, `message_index`, `output_index`), as processed in `parsePrivatePaymentChain`. [7](#0-6) 
3. Attacker finally sends/forwards the N-hop-deep coin to the victim as a normal private payment.
4. When the victim's wallet later spends this coin (composing a new payment) or restores its private-chain history, `buildPrivateElementsChain` recursively walks all N hops back to the `issue` element, materializing an `arrPrivateElements` array of length N (each element containing full input/output/blinding data) in memory, then deep-clones it before saving. [8](#0-7) [9](#0-8) 
5. With N large enough, this allocation and processing can exhaust available memory on the victim's node, crashing the process — analogous to `BtcPoller.Bootstrap` loading every block since the Babylon activation height into memory before a single commit.

### Citations

**File:** indivisible_asset.js (L198-229)
```javascript
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
```

**File:** indivisible_asset.js (L239-296)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
			profiler.start();
			var arrQueries = [];
			for (var i=0; i<arrPrivateElements.length; i++){
				var objPrivateElement = arrPrivateElements[i];
				var payload = objPrivateElement.payload;
				var input_address = objPrivateElement.input_address;
				var input = payload.inputs[0];
				var is_unique = objPrivateElement.bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				if (!input.type) // transfer
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, src_unit, src_message_index, src_output_index, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,?,'transfer',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.unit, input.message_index, input.output_index, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else if (input.type === 'issue')
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, serial_number, amount, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,'issue',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.serial_number, input.amount, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else
					throw Error("neither transfer nor issue after validation");
				var is_serial = objPrivateElement.bStable ? 1 : null; // initPrivatePaymentValidationState already checks for non-serial
				var outputs = payload.outputs;
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO outputs \n\
						(unit, message_index, output_index, amount, output_hash, asset, denomination) \n\
						VALUES (?,?,?,?,?,?,?)",
						[objPrivateElement.unit, objPrivateElement.message_index, output_index, 
						output.amount, output.output_hash, payload.asset, payload.denomination]);
					var fields = "is_serial=?";
					var params = [is_serial];
					if (output_index === objPrivateElement.output_index){
						var is_spent = (i===0) ? 0 : 1;
						fields += ", is_spent=?, address=?, blinding=?";
						params.push(is_spent, objPrivateElement.output.address, objPrivateElement.output.blinding);
					}
					params.push(objPrivateElement.unit, objPrivateElement.message_index, output_index);
					conn.addQuery(arrQueries, "UPDATE outputs SET "+fields+" WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0", params);
				}
			}
		//	console.log("queries: "+JSON.stringify(arrQueries));
			async.series(arrQueries, function(){
				profiler.stop('save');
				callbacks.ifOk();
			});
		}
	});
```

**File:** indivisible_asset.js (L619-638)
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

**File:** indivisible_asset.js (L869-898)
```javascript
					if (bPrivate){
						preCommitCallback = function(conn, cb){
							async.eachSeries(
								Object.keys(assocPrivatePayloads),
								function(payload_hash, cb2){
									var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
									var payload = assocPrivatePayloads[payload_hash];
									// We build, validate, and save two chains: one for the payee, the other for oneself (the change).
									// They differ only in the last element
									async.forEachOfSeries(
										payload.outputs,
										function(output, output_index, cb3){
											// we have only heads of the chains so far. Now add the tails.
											buildPrivateElementsChain(
												conn, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
													validateAndSavePrivatePaymentChain(conn, _.cloneDeep(arrPrivateElements), {
														ifError: function(err){
															cb3(err);
														},
														ifOk: function(){
															if (output.address === to_address)
																arrRecipientChains.push(arrPrivateElements);
															arrCosignerChains.push(arrPrivateElements);
															cb3();
														}
													});
												}
											);
										},
```

**File:** indivisible_asset.js (L984-1052)
```javascript
function restorePrivateChains(asset, unit, to_address, handleChains){
	var arrRecipientChains = [];
	var arrCosignerChains = [];
	db.query(
		"SELECT DISTINCT message_index, denomination, payload_hash, version \n\
		FROM outputs JOIN messages USING(unit, message_index) CROSS JOIN units USING(unit) WHERE unit=? AND asset=?", 
		[unit, asset], 
		function(rows){
			async.eachSeries(
				rows,
				function(row, cb){
					var payload = {asset: asset, denomination: row.denomination};
					var message_index = row.message_index;
					db.query(
						"SELECT src_unit, src_message_index, src_output_index, denomination, asset FROM inputs WHERE unit=? AND message_index=?", 
						[unit, message_index],
						function(input_rows){
							if (input_rows.length !== 1)
								throw Error("not 1 input");
							var input_row = input_rows[0];
							if (input_row.asset !== asset)
								throw Error("assets don't match");
							if (input_row.denomination !== row.denomination)
								throw Error("denominations don't match");
							if (input_row.src_message_index === null || input_row.src_output_index === null)
								throw Error("only transfers supported");
							var input = {
								unit: input_row.src_unit,
								message_index: input_row.src_message_index,
								output_index: input_row.src_output_index
							};
							payload.inputs = [input];
							db.query(
								"SELECT address, amount, blinding, output_hash FROM outputs \n\
								WHERE unit=? AND asset=? AND message_index=? ORDER BY output_index", 
								[unit, asset, message_index],
								function(outputs){
									if (outputs.length === 0)
										throw Error("outputs not found for mi "+message_index);
									if (!outputs.some(function(output){ return (output.address && output.blinding); }))
										throw Error("all outputs are hidden");
									payload.outputs = outputs;
									var hidden_payload = _.cloneDeep(payload);
									hidden_payload.outputs.forEach(function(o){
										delete o.address;
										delete o.blinding;
									});
									var payload_hash = objectHash.getBase64Hash(hidden_payload, row.version !== constants.versionWithoutTimestamp);
									if (payload_hash !== row.payload_hash)
										throw Error("wrong payload hash");
									async.forEachOfSeries(
										payload.outputs,
										function(output, output_index, cb3){
											if (!output.address || !output.blinding) // skip
												return cb3();
											// we have only heads of the chains so far. Now add the tails.
											buildPrivateElementsChain(
												db, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
													if (output.address === to_address)
														arrRecipientChains.push(arrPrivateElements);
													arrCosignerChains.push(arrPrivateElements);
													cb3();
												}
											);
										},
										cb
									);
								}
```
