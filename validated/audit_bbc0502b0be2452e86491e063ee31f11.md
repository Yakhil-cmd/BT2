### Title
Funds sent to an AA below its `bounce_fees` are silently and permanently absorbed when the sender bypasses the wallet's `checkAAOutputs` guard - (File: aa_composer.js)

### Summary
The ERC721 report's root problem is that a transfer to a recipient is executed without first verifying the recipient can actually process/return it, causing a permanent loss. In `ocore`, the analogous safety check exists for AA (Autonomous Agent) recipients — `aa_addresses.checkAAOutputs()` verifies a payment covers the target AA's declared `bounce_fees` before a unit is composed. But this check is enforced only in the high-level wallet composer path (`wallet.js:sendMultiPayment`), not in the protocol's unit-validation layer (`validation.js:validateAATrigger`) or in the low-level `composer.js:composeJoint`. Any unit poster that bypasses `sendMultiPayment` (custom scripts, other clients, AA-to-AA "secondary" triggers) can send bytes/asset amounts to an AA address that are below the AA's required `bounce_fees`; the network will accept the unit, but the AA engine will neither execute the AA's messages nor send back a bounce refund, permanently absorbing the payment into the AA's balance with no path to recover it.

### Finding Description
When a trigger unit is processed in `aa_composer.js:handleTrigger`, the engine requires the trigger's `outputs.base` to be at least the AA's configured `bounce_fees.base` (default `constants.MIN_BYTES_BOUNCE_FEE`) before it will even attempt to execute the AA logic or send a bounce refund: [1](#0-0) 

If this condition fails, `bounce()` is invoked, but `bounce()` itself refuses to emit any refund message when the trigger doesn't have enough base bytes to cover the fee: [2](#0-1) 

The result is `finish(null)` — the AA runs no messages, sends no refund, but the underlying protocol logic (`updateInitialAABalances`/`insertAADefinitions`) has already credited the received amount to the AA's balance. The sender has no recourse: the AA's oscript logic never executes for this trigger (so no state path can be crafted to route the money back), and the base protocol has no separate "unspendable AA balance" recovery mechanism.

The only place this scenario is proactively prevented **before** committing to send the unit is `aa_addresses.checkAAOutputs()`: [3](#0-2) 

which computes each output address's aggregate amount per asset, looks up whether the address is an AA, and rejects the payment client-side if the amount is below the AA's `bounce_fees`. This function is invoked only from `wallet.js:sendMultiPayment`: [4](#0-3) 

Neither `composer.js` (the lower-level joint composer used by non-wallet callers/bots/other engines) nor `validation.js:validateAATrigger` (the consensus-level check run for every unit, including ones from arbitrary posters) perform this check: [5](#0-4) 

Consequently, protection against "recipient can't handle the incoming value" is opt-in and UI-only, exactly mirroring the ERC721 report's finding that `_mint` (unsafe) is used instead of `_safeMint` (verified) — except here the "safe" check (`checkAAOutputs`) exists but is not applied uniformly at the point where funds actually become unrecoverable (unit validation/AA-engine execution).

### Impact Explanation
Any bytes/asset sent to an AA address in an amount below that AA's declared `bounce_fees` are permanently and silently absorbed by the AA with no state change and no refund, effectively burning the sender's funds. This is a direct, unauthorized-style fund loss/freezing condition (funds become inaccessible to both the sender and the AA's own logic, since the AA's oscript is never executed for that trigger and has no way to reference or move balance it never "saw" as `trigger.outputs`).

### Likelihood Explanation
Likelihood is elevated by the fact that the safeguard (`checkAAOutputs`) is not part of the consensus rules and not present in the lower-level `composer.js` path. Any bot, alternative client, custom integration, hub-relayed payment, or user who composes units without going through GUI wallet's `sendMultiPayment` (e.g., using `composer.composeJoint` directly, which is a commonly used, documented low-level API for headless/bot applications) can trigger this. Given how common headless/bot usage of AAs is (the primary reason AAs exist), this is a realistically reachable path for an ordinary, unprivileged unit poster — not requiring any privileged role.

### Recommendation
Move the `bounce_fees` sufficiency check out of the optional wallet composer path and into a place that is always enforced, e.g.:
- Add the check to `validation.js:validateAATrigger` (or a related pre-execution check) so that units carrying payments to AA addresses below the required `bounce_fees` are rejected as invalid at validation time, forcing the poster to fix the amount before the unit can ever be included; or
- Add a corresponding check inside `composer.js:composeJoint` so all composition paths (not just `wallet.js`) enforce it before finalizing a unit.

### Proof of Concept
1. Define an AA with `bounce_fees: { base: 10000 }` (as in the test fixtures, e.g. `test/aa_composer.test.js:161`, `191`, `927`, `947`).
2. Using `composer.js:composeJoint` directly (bypassing `wallet.js:sendMultiPayment`/`aa_addresses.checkAAOutputs`), compose and broadcast a unit sending, say, 5000 bytes to that AA's address.
3. The unit passes `validation.js` (no bounce-fee check exists there — see `validateAATrigger`, `validation.js:986-1039`).
4. When the AA engine processes the trigger in `aa_composer.js:handleTrigger`, the check at `aa_composer.js:1852` fails (`5000 < 10000`), `bounce()` is called (`aa_composer.js:928-929`), and because `trigger.outputs.base < bounce_fees.base`, `finish(null)` is invoked with no refund message generated.
5. The 5000 bytes remain permanently credited to the AA's balance (via `updateInitialAABalances`/`aa_balances`) with no state update and no way for the sender or the AA logic to retrieve them, since the AA's `messages` were never evaluated for this trigger.

### Citations

**File:** aa_composer.js (L909-929)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
```

**File:** aa_composer.js (L1850-1863)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```

**File:** aa_addresses.js (L120-156)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (err, rows) {
		if (err)
			return handleResult(err);
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
}
```

**File:** wallet.js (L2186-2194)
```javascript
	if (!opts.aa_addresses_checked) {
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
			if (err)
				return handleResult(err);
			opts.aa_addresses_checked = true;
			sendMultiPayment(opts, handleResult);
		});
		return;
	}
```

**File:** validation.js (L986-1039)
```javascript
async function validateAATrigger(conn, objUnit, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || objValidationState.bAA || !objValidationState.last_ball_mci) {
		if ("max_aa_responses" in objUnit)
			return callback(`max_aa_responses should not be there`);
		if (objValidationState.bAA || !objValidationState.last_ball_mci)
			return callback();
	}
	if ("content_hash" in objUnit) { // messages already stripped off
		objValidationState.count_primary_aa_triggers = 0;
		return callback();
	}
	if (objUnit.max_aa_responses === 0 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback(`max_aa_responses=0 is not allowed`);
	let outputCounts = {};
	for (let m of objUnit.messages) {
		if (m.app === 'payment' && m.payload) {
			const asset = m.payload.asset || 'base';
			for (let o of m.payload.outputs) {
				if (!outputCounts[o.address])
					outputCounts[o.address] = {};
				if (!outputCounts[o.address][asset])
					outputCounts[o.address][asset] = 0;
				outputCounts[o.address][asset]++;
			}
		}
	}
	const arrOutputAddresses = Object.keys(outputCounts);
	if (arrOutputAddresses.length === 0)
		return callback("no output addresses found in payment messages");

	// Look for AA triggers
	// There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes
	const rows = await conn.query("SELECT address FROM aa_addresses WHERE address IN (?) AND mci<=?", [arrOutputAddresses, objValidationState.last_ball_mci]);
	if (rows.length === 0) {
		if ("max_aa_responses" in objUnit)
			return callback(`no outputs to AAs, max_aa_responses should not be there`);
		return callback();
	}
	objValidationState.count_primary_aa_triggers = rows.length;
	if (objValidationState.count_primary_aa_triggers > 1) {
		if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci)
			return callback(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`);
		if (storage.getMinRetrievableMci() > constants.pemCurvesFixMci)
			return callback(createTransientError(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`));
	}
	if ((objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) && objValidationState.count_primary_aa_triggers === 1) {
		const address = rows[0].address;
		for (let asset in outputCounts[address]) {
			if (outputCounts[address][asset] > 1)
				return callback(`more than 1 output to the same AA ${address} for asset ${asset}`);
		}
	}
	callback();
}
```
