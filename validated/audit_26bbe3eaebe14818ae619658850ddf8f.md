### Title
AA balance overflow not checked when applying final balance deltas (payment outputs consumed by the AA response) - ([File: aa_composer.js])

### Summary
This is the same bug class as the LiquidityManager report: an unchecked/unvalidated addition to a persisted balance accumulator that can silently overflow, corrupting accounting instead of reverting. In `ocore`, the analog is the AA balance bookkeeping in `aa_composer.js`, where `MAX_BALANCE` overflow checks are applied only when the *initial* trigger balance is credited, but not when the *final* balance deltas (from consumed outputs and payment messages sent to the AA itself) are applied.

### Finding Description
`handleTrigger()` maintains `objValidationState.assocBalances[address][asset]` as the running truth for an AA's per-asset balance during a single trigger handling, backed by the `aa_balances` table. `MAX_BALANCE` is deliberately capped below `2**63-1` specifically to leave headroom for the sum of at most `MAX_MESSAGES_PER_UNIT * MAX_CAP` additions in one unit: [1](#0-0) 

`updateInitialAABalances()` correctly checks this bound after adding the trigger's own outputs, both for the in-memory (`bAir`) path and DB-backed path, and bounces the trigger with "balance overflow" if it is exceeded (gated by `pemCurvesFixMci`): [2](#0-1) [3](#0-2) 

However, `updateFinalAABalances()` — which applies the balance deltas from (a) outputs the AA itself consumed as inputs (negative deltas) and (b) any `payment` messages in the AA's own response unit that pay back to itself — recomputes `objValidationState.assocBalances[address][asset]` and `byte_balance` with plain unchecked JS addition, with **no re-check against `MAX_BALANCE`**: [4](#0-3) 

Because an AA can be triggered repeatedly (chained/bounced AA-to-AA calls, secondary triggers via `bSecondary`, or externally by any permissionless unit poster funding the AA with payments up to `MAX_CAP` each), and because asset issuance/definitions are themselves permissionless (`validateAssetDefinition` only bounds a single asset's `cap` at `MAX_CAP`, it does not bound the *sum* of balances an address can accumulate across many small deposits over time), an attacker who can post units into the AA over many triggers can grow `assocBalances[address][asset]` (and the persisted `aa_balances.balance` row, `UPDATE aa_balances SET balance=balance+?`) without ever tripping the overflow guard, since that guard only fires inside `updateInitialAABalances`, not in the code path that finalizes state after messages are composed.

This mirrors the LiquidityManager class of bug precisely: a bound (`type(uint128).max` there, `MAX_BALANCE` here) is enforced at only one of the two mutation points (`use()`/`deposit()` there, `updateInitialAABalances` here) while the other mutation point (`restore()` there, `updateFinalAABalances` here) applies the delta unchecked, allowing the invariant to be silently violated instead of reverting.

### Impact Explanation
If `assocBalances[address][asset]` (and the DB `aa_balances.balance` value) silently wraps or loses precision beyond `Number.MAX_SAFE_INTEGER` due to unchecked accumulation in `updateFinalAABalances`, the AA's internal accounting of its own funds becomes wrong. Since AA `balance[...]` reads and payment authorization formulas (`balance[base]`, `bounce()` conditions, and payment outputs sized by `trigger.output[[...]]` or state vars) rely on this same balance state, a corrupted/understated or wrapped balance can let an AA emit payments that exceed what it actually received (fund loss to the AA / other legitimate users), or falsely reject legitimate withdrawals (fund freezing). This satisfies the "AA fund loss or freezing" impact category.

### Likelihood Explanation
This requires an attacker (or attacker-controlled asset issuer) to repeatedly trigger a target AA with outputs/consumed-inputs over many rounds until the cumulative deltas processed exclusively through `updateFinalAABalances` push the tracked balance past `MAX_BALANCE`/`Number.MAX_SAFE_INTEGER`. This is achievable by any unprivileged AA trigger sender since AA triggering and asset creation are fully permissionless, and multiple units/messages can be chained (bounces, secondary triggers) without requiring special privileges — but it does require sustained, high-volume interaction over time (likely many units, given `MAX_CAP` per output is 9e15 and `MAX_BALANCE` is `2**63-1 - MAX_MESSAGES_PER_UNIT*MAX_CAP`), so exploitation is nontrivial but not implausible for a determined attacker targeting a specific high-value AA.

### Recommendation
Apply the same `MAX_BALANCE` bound check in `updateFinalAABalances()` that is already applied in `updateInitialAABalances()`, for both the `objValidationState.assocBalances[address][asset]` computation and the `byte_balance` accumulation, and bounce the trigger (or fail the AA response) if the bound is exceeded rather than silently continuing.

### Proof of Concept
Not independently reproducible from the indexed code alone (this analysis is based on static code review of `aa_composer.js`'s two balance-update functions, not on a runnable exploit script). Conceptually: repeatedly trigger a target AA such that its response consumes and re-receives outputs so that the cumulative deltas applied inside `updateFinalAABalances` (line 543-587) push `assocBalances[address][asset]` past `MAX_BALANCE` without ever passing back through `updateInitialAABalances`'s check, then observe the tracked/persisted balance diverge from the AA's real funds.

### Citations

**File:** aa_composer.js (L48-49)
```javascript
// some precision loss in this calc (it's entirely beyond MAX_SAFE_INTEGER) but that's inconsequential
const MAX_BALANCE = 2 ** 63 - 1 - constants.MAX_MESSAGES_PER_UNIT * constants.MAX_CAP;
```

**File:** aa_composer.js (L475-490)
```javascript
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

**File:** aa_composer.js (L506-514)
```javascript
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
