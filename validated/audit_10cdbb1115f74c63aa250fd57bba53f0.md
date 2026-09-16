### Title
AA balance accounting uses native JS numbers that lose precision above `Number.MAX_SAFE_INTEGER` while the overflow gate allows balances far beyond it - ([File: aa_composer.js])

### Summary
`aa_composer.js` accumulates AA coin balances (both the coins received in a trigger and the running `aa_balances` table value) using plain JavaScript number arithmetic (`+`), not the `Decimal.js` type used everywhere else in the formula engine for precision-safe math. The only guard against unbounded growth, `MAX_BALANCE`, is deliberately set far above `Number.MAX_SAFE_INTEGER` (2^53-1 ≈ 9.007e15), so a balance can legally reach values where native `+` silently rounds instead of throwing, analogous to the CVE's "several additions in a row without an intermediate bound check" overflow pattern.

### Finding Description
`getTrigger()` sums all payment outputs addressed to the AA across every payment message in the triggering unit without any cap: [1](#0-0) 
Each individual payment message is separately validated so that a single message's `total_output` cannot exceed `constants.MAX_CAP` (9e15): [2](#0-1) 
but nothing limits the number of payment messages per unit other than `constants.MAX_MESSAGES_PER_UNIT` (128), so `trigger.outputs[asset]` in `getTrigger` can be the sum of up to 128 messages, each up to `MAX_CAP`.

`updateInitialAABalances()` then adds this trigger amount to the AA's balance using native JS arithmetic, both for the in-memory air-drop path and for the DB-backed path: [3](#0-2) 
The only defense against unbounded growth is:
```
const MAX_BALANCE = 2 ** 63 - 1 - constants.MAX_MESSAGES_PER_UNIT * constants.MAX_CAP;
``` [4](#0-3) 
The comment in the source explicitly acknowledges that this constant itself is already beyond safe double precision ("some precision loss in this calc ... but that's inconsequential"), and the resulting threshold (~9.22e18) is roughly three orders of magnitude larger than `Number.MAX_SAFE_INTEGER` (~9.007e15). This means a balance can legitimately sit in the range `[2^53, MAX_BALANCE]` without ever being rejected, yet every addition performed on it via plain `+` (line 511, and `byte_balance += assocDeltas.base` in `updateFinalAABalances`) can silently lose precision once it crosses `2^53`.

Assets without a `cap` are allowed unlimited re-issuance (the cap-equality check in `validatePaymentInputsAndOutputs` is skipped for uncapped assets): [5](#0-4) 
so an attacker who defines and issues such an asset can, across multiple payment messages/units, accumulate outputs to a target AA large enough that the JS-side `objValidationState.assocBalances` value used to drive AA logic diverges from the exact integer value that is actually written into the `aa_balances` DB column (that write is performed by the SQL engine using exact integer arithmetic: `UPDATE aa_balances SET balance=balance+?`). Once `objValidationState.assocBalances` (used for `balance` reads inside the oscript/ojson `evaluate()` engine, e.g. `balance[...]` and bounce/response decisions) diverges from the true stored balance, the AA's own logic can behave inconsistently with its real on-chain funds.

### Impact Explanation
If the cached, formula-visible balance value diverges (due to floating-point rounding) from the exact value persisted in `aa_balances`, an AA's state-machine logic that branches on `balance[...]` can make decisions inconsistent with its real funds — e.g., approving a payout it can't actually cover, or incorrectly bouncing/refusing a valid operation. This is a fund-loss/fund-freezing class impact for the affected AA, reachable purely by an unprivileged unit poster who defines an uncapped asset and drives enough issuance/transfer volume into an AA trigger.

### Likelihood Explanation
Exploitation requires accumulating balances in the multi-quadrillion-to-exa range for a single AA/asset pair, which requires the attacker (as the asset's own issuer, since uncapped assets can be minted arbitrarily) to actually construct and confirm a large volume of issuance/transfer traffic directed at the target AA. This is technically reachable without any privileged role, but the practical cost (many confirmed units, or extremely large single-message amounts near `MAX_CAP` repeated up to `MAX_MESSAGES_PER_UNIT` times) makes it non-trivial, and I could not fully verify from the code available whether any additional AA-side accounting reconciliation exists elsewhere in the codebase that would catch the divergence before funds are actually mis-spent. This uncertainty should be treated as an open verification item.

### Recommendation
Replace native JS-number arithmetic for AA balances in `aa_composer.js` (`updateInitialAABalances`, `updateFinalAABalances`, and the `byte_balance` accumulation) with `Decimal.js` (already used throughout `formula/evaluation.js`) or an equivalent BigInt-safe path, and lower `MAX_BALANCE` to a value that is provably representable exactly as a JS double (i.e., at most `Number.MAX_SAFE_INTEGER`), removing the acknowledged precision-loss gap between the enforced cap and the actual safe-integer range.

### Proof of Concept
1. Define and issue an asset with no `cap` field (unlimited supply is legal for such assets per `validation.js:2321-2327`).
2. Over time (or within a single unit, bounded by `MAX_MESSAGES_PER_UNIT`=128 payment messages each ≤ `MAX_CAP`=9e15), send a series of payments of this asset to a target AA address such that the cumulative amount recorded by `getTrigger()`/`updateInitialAABalances()` for that asset crosses `2^53` (9,007,199,254,740,992).
3. Observe that `objValidationState.assocBalances[address][asset]` (JS number arithmetic, `aa_composer.js:511`) can diverge from the exact value written to the `aa_balances` table by the SQL `balance=balance+?` update, since the latter is computed by the database's exact integer arithmetic while the former is subject to IEEE-754 double rounding once past `2^53`.
4. Trigger AA logic (in oscript/ojson) that reads `balance[...]` and branches on it; demonstrate that the AA's in-run decision uses the rounded (incorrect) value while its actual persisted balance differs, producing an outcome inconsistent with real AA funds.

### Citations

**File:** aa_composer.js (L48-49)
```javascript
// some precision loss in this calc (it's entirely beyond MAX_SAFE_INTEGER) but that's inconsequential
const MAX_BALANCE = 2 ** 63 - 1 - constants.MAX_MESSAGES_PER_UNIT * constants.MAX_CAP;
```

**File:** aa_composer.js (L382-391)
```javascript
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
```

**File:** aa_composer.js (L475-514)
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
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
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

**File:** validation.js (L2151-2197)
```javascript
	for (var i=0; i<payload.outputs.length; i++){
		var output = payload.outputs[i];
		if (!isNonemptyObject(output))
			return callback("output must be a non-empty object");
		if (hasFieldsExcept(output, ["address", "amount", "blinding", "output_hash"]))
			return callback("unknown fields in payment output");
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+JSON.stringify(output.amount));
		if (output.amount > constants.MAX_CAP)
			return callback("output too large: " + output.amount);
		if (objAsset && objAsset.fixed_denominations && output.amount % denomination !== 0)
			return callback("output amount must be divisible by denomination");
		if (objAsset && objAsset.is_private){
			if (("output_hash" in output) !== !!objAsset.fixed_denominations)
				return callback("output_hash must be present with fixed denominations only");
			if ("output_hash" in output && !isStringOfLength(output.output_hash, constants.HASH_LENGTH))
				return callback("invalid output hash");
			if (!objAsset.fixed_denominations && !(("blinding" in output) && ("address" in output)))
				return callback("no blinding or address");
			if ("blinding" in output && !isStringOfLength(output.blinding, 16))
				return callback("bad blinding");
			if (("blinding" in output) !== ("address" in output))
				return callback("address and blinding must come together");
			if ("address" in output && !isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (output.address)
				count_open_outputs++;
		}
		else{
			if ("blinding" in output)
				return callback("public output must not have blinding");
			if ("output_hash" in output)
				return callback("public output must not have output_hash");
			if (!isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (prev_address > output.address)
				return callback("output addresses not sorted");
			else if (prev_address === output.address && prev_amount > output.amount)
				return callback("output amounts for same address not sorted");
			prev_address = output.address;
			prev_amount = output.amount;
		}
		if (output.address && arrOutputAddresses.indexOf(output.address) === -1)
			arrOutputAddresses.push(output.address);
		total_output += output.amount;
		if (total_output > constants.MAX_CAP)
			return callback("total output too large: " + total_output);
```

**File:** validation.js (L2321-2327)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
```
