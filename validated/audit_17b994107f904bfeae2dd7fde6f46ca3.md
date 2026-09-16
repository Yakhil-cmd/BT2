### Title
Stale change output re-appended to shared `outputs` array on payment-composition retry — corrupted payment payload ([File: divisible_asset.js])

### Summary
`composeDivisibleAssetPaymentJoint()` in `divisible_asset.js` aliases the caller-supplied outputs array (`payment.outputs`, ultimately `params.asset_outputs` / `params.outputs_by_asset[asset]`) instead of cloning it, then mutates it in place by pushing a change output. `composer.composeJoint()` retries the whole `retrieveMessages` step (which is the same closure that performs this mutation) whenever the initial attempt fails with `NOT_ENOUGH_FUNDS`, either through the `minimal`/`trySubset` address-widening loop or through the "input coins" `pickDivisibleCoinsForAmount` failure path. Because the same `arrOutputs` reference is reused (and already mutated) across retries, a partially-failed attempt leaves a stale `change` output in the array that is retained and joined by a second, newly computed change output on the retry — producing a payment message with duplicate/incorrect change outputs, i.e. data corruption of the composed payload analogous to the aliased page_frag data corruption in the mptcp CVE.

### Finding Description
In `divisible_asset.js`: [1](#0-0) 
`arrAssetPayments` entries reference the caller's arrays directly (`params.asset_outputs`, `params.outputs_by_asset[a]`), not clones.

Inside the `retrieveMessages` callback passed to `composer.composeJoint`, the same reference is aliased again and mutated with `push`: [2](#0-1) 
```js
var arrOutputs = payment.outputs;
var change = total_input - target_amount;
if (change > 0){
    var objChangeOutput = {address: params.change_address, amount: change};
    arrOutputs.push(objChangeOutput);
}
...
arrOutputs.sort(composer.sortOutputs);
var payload = { asset: payment.asset, inputs: ..., outputs: arrOutputs };
```
`arrOutputs` here is not a defensive copy — it *is* `payment.outputs`, which in turn *is* the original `params.asset_outputs` (or `outputs_by_asset[asset]`) array supplied by the caller (e.g. `wallet.js` `sendMultiPayment`), and it is captured by the `retrieveMessages` closure that `composer.composeJoint` invokes.

`composer.composeJoint()` retries this exact closure (unchanged, same captured `arrAssetPayments`/`payment.outputs`) under two circumstances:
1. The `minimal`/`send_all=false` subset-widening retry loop: [3](#0-2) 
On `ifNotEnoughFunds`, `trySubset(count+1)` re-invokes `composeJoint(try_params)` with the same `retrieveMessages` function object referenced from the outer `divisible_asset.js` closure.
2. The base-asset input-selection stage, which runs *after* `retrieveMessages` already executed and pushed the asset payment's change output: [4](#0-3) 
If `pickDivisibleCoinsForAmount` for the *base* asset fails with `NOT_ENOUGH_FUNDS` after the asset-level `retrieveMessages` step already mutated `arrOutputs`, and the outer caller retries the whole composition (e.g. `composeMinimalJoint`'s `trySubset`, or an application-level retry using the same `params` object), `retrieveMessages` runs a second time on the *already-mutated* array: it computes a fresh `total_input`/`change` and pushes a *second* change output onto the same array, without removing the first.

This is the same bug class as CVE-2021-47152: a routine (`mptcp_frag_can_collapse_to`, here `composeDivisibleAssetPaymentJoint`'s output builder) assumes it is the sole and first user/owner of a buffer/array (`page_frag`, here `payment.outputs`) and appends to its tail, but the buffer is actually shared/reused across an unrelated retry pass, so old and new data (stale change output vs. new change output) coexist and corrupt the resulting structure.

### Impact Explanation
A corrupted `payload.outputs` array containing two change outputs (one stale, from the failed attempt, one fresh) changes the effective payment: the sum of outputs no longer matches `total_input - target_amount` for a single, consistent attempt, and the second change output silently sends additional confirmed value to `params.change_address` (typically the sender's own change address) — but more importantly it desynchronizes `payload_hash` computation from what the wallet/UI believes was composed, and, in the private-asset branch, feeds a corrupted `hidden_payload`/`private_payload` into the private-chain-building/validation logic (`buildPrivateElementsChain`, `validateAndSaveDivisiblePrivatePayment`) with output counts/blinding that don't match what was actually spendable. Depending on how downstream validation reconciles `total_input` vs. `sum(outputs)+fees`, this can result in the composed unit being rejected (denial of the node's own ability to confirm a payment) or, in the worst case, an incorrectly composed multi-output payment that spends/allocates funds inconsistently with the caller's intent (fund-loss/incorrect-payment class), matching the "concrete unauthorized spending" / "node disagreement on validity" bar required by the validation rules.

### Likelihood Explanation
Triggering requires an attacker or normal user flow that causes `composeDivisibleAssetPaymentJoint`'s `retrieveMessages` to be invoked more than once against the same output array — this happens naturally via the `minimal` paying-address-widening retry (`composer.js` `trySubset`) whenever the initially chosen paying addresses are insufficient, or via base-asset fee/input insufficiency after the asset payload was already built. Both paths are reachable by an ordinary unprivileged wallet user composing a divisible-asset payment (no privileged/peer/node access needed), making this a self-triggerable local-state corruption during normal AA/asset-payment flows described as in-scope ("payment inputs/outputs... asset issuance and transfer conditions... private payment chains").

### Recommendation
Clone the outputs array before appending the change output in `composeDivisibleAssetPaymentJoint` (and audit the analogous code in `indivisible_asset.js`'s `createAdditionalMessages`), e.g.:
```js
var arrOutputs = payment.outputs.slice(); // or _.cloneDeep
```
so each invocation of the `retrieveMessages` closure starts from the pristine caller-supplied outputs, and any retry recomputes change cleanly rather than mutating a shared, potentially already-mutated array. Additionally, `composer.composeJoint`'s retry paths (`trySubset`, and any caller-level retry after `ifNotEnoughFunds`) should ensure `retrieveMessages`/its captured state is idempotent or freshly re-derived per attempt.

### Proof of Concept
Conceptual reproduction (not verified end-to-end in this session due to ask-only/reasoning constraints):
1. Call `divisibleAsset.composeAndSaveDivisibleAssetPaymentJoint` (via `wallet.sendMultiPayment`) with `paying_addresses` that are sufficient for the asset but insufficient for base-asset fees, using `minimal: true` or an outer retry that reuses `params`.
2. `retrieveMessages` runs, computes `change`, and does `arrOutputs.push(objChangeOutput)` on `params.asset_outputs` (or `outputs_by_asset[asset]`), producing one legitimate change output.
3. The base-asset input-selection step in `composer.js` (lines 498-520) fails with `NOT_ENOUGH_FUNDS` because the fee-paying addresses lack funds.
4. The composition is retried (either by `composeMinimalJoint`'s `trySubset` widening the address set, or by application code calling `composeAndSaveDivisibleAssetPaymentJoint` again with the same `params` object) — `retrieveMessages` executes again on `payment.outputs`, which still contains the first change output, and appends a second change output with a different `amount`.
5. The resulting `payload.outputs` array now has two change entries, and the composed/signed unit no longer represents the amounts the caller intended, while `total_input`/fee accounting was computed against only the last attempt.

### Citations

**File:** divisible_asset.js (L212-220)
```javascript
	var arrAssetPayments = [];
	if (params.to_address)
		arrAssetPayments.push({ asset: params.asset, outputs: [{ address: params.to_address, amount: params.amount }] });
	else if (params.asset_outputs)
		arrAssetPayments.push({ asset: params.asset, outputs: params.asset_outputs });
	else if (params.outputs_by_asset)
		for (var a in params.outputs_by_asset)
			if (a !== 'base')
				arrAssetPayments.push({ asset: a, outputs: params.outputs_by_asset[a] });
```

**File:** divisible_asset.js (L259-272)
```javascript
								var arrOutputs = payment.outputs;
								var change = total_input - target_amount;
								if (change > 0){
									var objChangeOutput = {address: params.change_address, amount: change};
									arrOutputs.push(objChangeOutput);
								}
								if (objAsset.is_private)
									arrOutputs.forEach(function(output){ output.blinding = composer.generateBlinding(); });
								arrOutputs.sort(composer.sortOutputs);
								var payload = {
									asset: payment.asset,
									inputs: arrInputsWithProofs.map(function(objInputWithProof){ return objInputWithProof.input; }),
									outputs: arrOutputs
								};
```

**File:** composer.js (L166-190)
```javascript
	// try to use as few paying_addresses as possible. Assuming paying_addresses are sorted such that the most well-funded addresses come first
	if (params.minimal && !params.send_all){
		var callbacks = params.callbacks;
		var arrCandidatePayingAddresses = params.paying_addresses;

		var trySubset = function(count){
			if (count > constants.MAX_AUTHORS_PER_UNIT)
				return callbacks.ifNotEnoughFunds("Too many authors.  Consider splitting the payment into two units.");
			var try_params = _.clone(params);
			delete try_params.minimal;
			try_params.paying_addresses = arrCandidatePayingAddresses.slice(0, count);
			try_params.callbacks = {
				ifOk: callbacks.ifOk,
				ifError: callbacks.ifError,
				ifNotEnoughFunds: function(error_message){
					if (count === arrCandidatePayingAddresses.length)
						return callbacks.ifNotEnoughFunds(error_message);
					trySubset(count+1); // add one more paying address
				}
			};
			composeJoint(try_params);
		};
		
		return trySubset(1);
	}
```

**File:** composer.js (L455-520)
```javascript
		// messages retrieved via callback
		function(cb){
			if (!fnRetrieveMessages)
				return cb();
			console.log("will retrieve messages");
			fnRetrieveMessages(conn, last_ball_mci, bMultiAuthored, arrPayingAddresses, function(err, arrMoreMessages, assocMorePrivatePayloads){
				console.log("fnRetrieveMessages callback: err code = "+(err ? err.error_code : ""));
				if (err)
					return cb((typeof err === "string") ? ("unable to add additional messages: "+err) : err);
				Array.prototype.push.apply(objUnit.messages, arrMoreMessages);
				if (assocMorePrivatePayloads && Object.keys(assocMorePrivatePayloads).length > 0)
					for (var payload_hash in assocMorePrivatePayloads)
						assocPrivatePayloads[payload_hash] = assocMorePrivatePayloads[payload_hash];
				cb();
			});
		},
		function(cb){ // input coins
			objUnit.headers_commission = objectLength.getHeadersSize(objUnit);
			var naked_payload_commission = objectLength.getTotalPayloadSize(objUnit); // without input coins
			vote_count_fee = objUnit.messages.find(m => m.app === 'system_vote_count') ? constants.SYSTEM_VOTE_COUNT_FEE : 0;

			if (bGenesis){
				var issueInput = {type: "issue", serial_number: 1, amount: constants.TOTAL_WHITEBYTES};
				if (objUnit.authors.length > 1) {
					issueInput.address = constants.v4UpgradeMci === 0 ? params.witnesses[0] : arrWitnesses[0];
				}
				objPaymentMessage.payload.inputs = [issueInput];
				objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
				total_input = constants.TOTAL_WHITEBYTES;
				return cb();
			}
			if (params.inputs){ // input coins already selected
				if (!params.input_amount)
					throw Error('inputs but no input_amount');
				total_input = params.input_amount;
				objPaymentMessage.payload.inputs = params.inputs;
				objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
				const oversize_fee = (last_ball_mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci) : 0;
				if (oversize_fee)
					objUnit.oversize_fee = oversize_fee;
				return cb();
			}
			
			// all inputs must appear before last_ball
			const naked_size = objUnit.headers_commission + naked_payload_commission;
			const paid_temp_data_fee = objectLength.getPaidTempDataFee(objUnit);
			const oversize_fee = (last_ball_mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(naked_size - paid_temp_data_fee, last_ball_mci) : 0;
			var target_amount = params.send_all ? Infinity : (total_amount + naked_size + oversize_fee + (objUnit.tps_fee||0) + (objUnit.burn_fee||0) + vote_count_fee);
			inputs.pickDivisibleCoinsForAmount(
				conn, null, arrPayingAddresses, last_ball_mci, target_amount, naked_size, paid_temp_data_fee, bMultiAuthored, params.spend_unconfirmed || conf.spend_unconfirmed || 'own',
				function(arrInputsWithProofs, _total_input){
					if (!arrInputsWithProofs)
						return cb({ 
							error_code: "NOT_ENOUGH_FUNDS", 
							error: "not enough spendable funds from "+arrPayingAddresses+" for "+target_amount
						});
					total_input = _total_input;
					objPaymentMessage.payload.inputs = arrInputsWithProofs.map(function(objInputWithProof){ return objInputWithProof.input; });
					objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
					console.log("inputs increased payload by", objUnit.payload_commission - naked_payload_commission);
					const oversize_fee = (last_ball_mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci) : 0;
					if (oversize_fee)
						objUnit.oversize_fee = oversize_fee;
					cb();
				}
			);
```
