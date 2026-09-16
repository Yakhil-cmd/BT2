Based on my research, I found a strong structural analog to the Tigris bug: a numeric-limit check enforced in one balance-mutation code path but silently skipped in a sibling code path that mutates the exact same state.

### Title
AA final balance update skips the `MAX_BALANCE` overflow check enforced on initial balance update - (File: aa_composer.js)

### Summary
In `handleTrigger()`, an AA's byte/asset balances are mutated at two points during trigger processing: once when the trigger's incoming payment is credited (`updateInitialAABalances`), and again after the AA sends its response messages, when consumed inputs and produced outputs are netted (`updateFinalAABalances`). The first path enforces `objValidationState.assocBalances[address][asset] > MAX_BALANCE ⇒ "balance overflow"`, but the second path performs the identical `balance += delta` mutation with no equivalent bound check.

### Finding Description
`updateInitialAABalances` explicitly guards against a balance overflow: for every asset added from `trigger.outputs`, it checks `objValidationState.assocBalances[address][asset] > MAX_BALANCE` and sets `bOverflow`, causing the trigger to bounce with `"balance overflow"` (gated by `mci >= constants.pemCurvesFixMci`). [1](#0-0) [2](#0-1) 

Later in the same trigger handling flow, `updateFinalAABalances` recomputes per-asset deltas from consumed inputs and newly sent payment outputs and applies them directly to `objValidationState.assocBalances[address][asset] += assocDeltas[asset]` (and to the DB via `UPDATE aa_balances SET balance=balance+?`). This function has no `MAX_BALANCE` check whatsoever on the resulting balance: [3](#0-2) 

This is structurally identical to the Tigris finding: a cap/limit is enforced on the "primary" state-changing operation (initial credit / opening a position) but omitted on a secondary operation that mutates the same guarded quantity (final balance settlement / `addToPosition`). An AA whose logic causes it to receive large payments across multiple secondary triggers/bounces within one primary trigger's response chain (each individually under `MAX_BALANCE`, but summed via `updateFinalAABalances`'s uncapped `+=`), or that receives large amounts back from another AA/response as part of the same response chain, can push `assocBalances[address][asset]` above `MAX_BALANCE` without the bounce guard ever firing, because that guard only runs inside `updateInitialAABalances`, not `updateFinalAABalances`.

### Impact Explanation
`MAX_BALANCE` exists to bound the numeric range AAs and the formula engine are designed to safely operate on. If an AA's stored balance can exceed this bound via the final-balance path while bypassing the dedicated overflow check, this can cause: (a) inconsistent behavior between nodes if the unguarded overflow interacts differently with JS `Number` precision in different execution contexts, risking node disagreement on AA state/validity, and (b) subsequent AA formula computations (e.g. payouts, fee calculations, or accounting logic that assumes balances stay within `MAX_BALANCE`) to silently produce incorrect results, potentially enabling fund loss/miscalculated payouts from the AA.

### Likelihood Explanation
Requires an AA definition whose response chain triggers `updateFinalAABalances` with deltas large enough, combined across multiple secondary responses in one primary-trigger execution, to exceed `MAX_BALANCE`, even though `updateInitialAABalances` never individually saw a value above the cap. This is plausible for AAs designed to accumulate/relay large payment amounts across chained responses (a documented, supported AA pattern), similar to how the Tigris bug required only a >500% price move to be triggerable — an externally-influenceable but realistic condition rather than a contrived one.

### Recommendation
Add the same `assocBalances[address][asset] > MAX_BALANCE` check (mirroring `updateInitialAABalances`'s guard, gated the same way by `mci >= constants.pemCurvesFixMci`) inside `updateFinalAABalances` after applying `assocDeltas`, and propagate the resulting error through `cb()` so the caller can bounce the trigger, exactly as `updateInitialAABalances` does today.

### Proof of Concept
1. Deploy an AA definition that, within a single primary trigger's response chain, causes multiple secondary AA responses to route large asset payments back into the same AA address (a bouncer/reflection pattern, similar to the `bouncer_aa`/`asset_aa` test fixture already used in the repo's test suite for chained AA responses). [4](#0-3) 
2. Structure the deltas so that each individual `updateInitialAABalances` invocation stays at or below `MAX_BALANCE`, but the cumulative `assocDeltas[asset] += ...` applied in `updateFinalAABalances` across the chain pushes `assocBalances[address][asset]` above `MAX_BALANCE`.
3. Observe that no bounce occurs and `aa_balances.balance` is persisted above `MAX_BALANCE`, because the overflow check present in `updateInitialAABalances` (lines 483-489, 512-513) is never evaluated for the delta applied in `updateFinalAABalances` (lines 576-583).

### Citations

**File:** aa_composer.js (L474-490)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```

**File:** aa_composer.js (L499-514)
```javascript
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
```

**File:** aa_composer.js (L543-587)
```javascript
	function updateFinalAABalances(arrConsumedOutputs, objUnit, cb) {
		if (trigger_opts.bAir)
			throw Error("updateFinalAABalances shouldn't be called with bAir");
		var assocDeltas = {};
		var arrNewAssets = [];
		arrConsumedOutputs.forEach(function (output) {
			if (!assocDeltas[output.asset])
				assocDeltas[output.asset] = 0;
			assocDeltas[output.asset] -= output.amount;
			// this might happen if there is another pending invocation of our AA that created the outputs we are spending now
			if (!objValidationState.assocBalances[address][output.asset])
				arrNewAssets.push(output.asset);
		});
		objUnit.messages.forEach(function (message) {
			if (message.app !== 'payment')
				return;
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address !== address)
					return;
				if (!assocDeltas[asset]) { // it can happen if the asset was issued by AA
					assocDeltas[asset] = 0;
					arrNewAssets.push(asset);
				}
				assocDeltas[asset] += output.amount;
			});
		});
		var arrQueries = [];
		if (arrNewAssets.length > 0) {
			var arrValues = arrNewAssets.map(function (asset) { return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", 0)"; });
			conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
		}
		for (var asset in assocDeltas) {
			if (assocDeltas[asset]) {
				conn.addQuery(arrQueries, "UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=?", [assocDeltas[asset], address, asset]);
				if (!objValidationState.assocBalances[address][asset])
					objValidationState.assocBalances[address][asset] = 0;
				objValidationState.assocBalances[address][asset] += assocDeltas[asset];
			}
		}
		if (assocDeltas.base)
			byte_balance += assocDeltas.base;
		async.series(arrQueries, cb);
	}
```

**File:** test/aa_composer.test.js (L450-526)
```javascript
test.cb.serial('issue recently defined asset', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { define: true }, address: trigger_address };

	// a chain of 3 AA responses
	// 1. define asset, save var['asset'] state var, and send bytes to bouncer AA
	// 2. bouncer reflects the bytes back
	// 3. the 1st AA acts again, it reads the state var and issues the asset

	var bouncer_aa = ['autonomous agent', {
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
		]
	}];
	var bouncer_address = objectHash.getChash160(bouncer_aa);
	addAA(bouncer_aa);

	var asset_aa = ['autonomous agent', {
		messages: {
			cases: [
				{
					if: "{trigger.data.define}",
					messages: [
						{
							app: 'asset',
							payload: {
								cap: 1e6,
								is_private: false,
								is_transferrable: true,
								auto_destroy: false,
								fixed_denominations: false,
								issued_by_definer_only: true,
								cosigned_by_definer: false,
								spender_attested: false,
							}
						},
						{
							app: 'payment',
							payload: {
								asset: 'base',
								outputs: [
									{address: bouncer_address, amount: "{trigger.output[[asset=base]] - 1000}"}
								]
							}
						},
						{
							app: 'state',
							state: `{
								var['asset'] = response_unit;
							}`
						}
					]
				},
				{
					if: `{trigger.address == '${bouncer_address}' AND var['asset']}`,
					messages: [{
						app: 'payment',
						payload: {
							asset: "{var['asset']}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{asset[var['asset']].cap}"}
							]
						}
					}]
				},
			]
		}
	}];
	var asset_address = objectHash.getChash160(asset_aa);
```
