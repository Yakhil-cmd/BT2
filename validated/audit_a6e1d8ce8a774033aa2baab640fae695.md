### Title
AA owners can front-run their own fee/rate state variables to drain user deposits, because state-variable updates take effect immediately with no timelock and trigger execution order is influenced by the attacker's own unit-level choice - (File: `aa_composer.js`, `main_chain.js`)

### Summary
Any Autonomous Agent (AA) can implement a "vault"-like design where a state variable read at trigger time (a fee %, exchange rate, tax, etc.) is used to compute how much of the user's deposit is returned/kept. There is no protocol-level timelock or delay between an AA owner (or any address whose trigger the AA code trusts) posting a unit that changes such a state variable and that new value taking effect for the very next trigger that is ordered ahead of a pending user deposit. Because AA triggers execute in an order determined by `(mci, level, unit, address)` and `level` is computed locally from the parents an author chooses at compose time, a party that is racing to change the fee variable can pick parents that do not descend from the victim's already-broadcast (but not-yet-stable) unit and obtain a lower or equal level, causing their "set fee" unit to be processed before the victim's large deposit. This is the direct analog of the NFTX pool-manager front-running a fee to 100%.

### Finding Description
State variables are stored and applied immediately, without delay: [1](#0-0) 

They can be freely rewritten by any `state` message that the AA code allows to run (e.g. an owner-restricted branch keyed off `trigger.address`), as illustrated by state vars such as `founder_tax`, `team_..._amount`, or a computed exchange fee/amount used directly in a `payment` output: [2](#0-1) 

AA triggers are collected per stabilized MCI and processed in a fully deterministic order based on `level`, not on when the corresponding unit was first broadcast to the network: [3](#0-2) [4](#0-3) 

Because `level` is derived from the parents an author selects when composing their own unit (not from wall-clock broadcast time), a party racing to update a fee-like state var can watch the DAG for the victim's pending high-value trigger unit and immediately compose a competing unit built on parents that exclude the victim's unit, giving their own unit an equal-or-lower level so that it is processed first once both become part of the same or an earlier stabilized MCI. There is no cooldown/timelock mechanism anywhere in `handleTrigger` that forces a delay between a state-variable write and its use by a subsequent trigger: [5](#0-4) 

### Impact Explanation
Any AA that computes user payouts, exchange rates, or "fee" percentages from a mutable state variable (a very common and encouraged pattern, e.g. the fundraising/founder-tax and exchange-rate examples shipped in this repo's own sample AAs) is exposed to the same class of loss described in the NFTX report: the party who controls the state-changing branch of the AA can observe a large pending deposit in the DAG and race a "raise the fee/tax to (near) 100%" unit ahead of it, extracting nearly the entire value of the victim's deposit before the victim's trigger is evaluated. This is a direct AA fund-loss/value-theft vector reachable by any unprivileged trigger sender who is allowed by the AA's own logic to modify the relevant state variable (e.g., an AA "owner" address that is not otherwise trusted, exactly mirroring the untrusted "pool manager" in the original report).

### Likelihood Explanation
Exploitation requires only: (1) an AA whose code lets some address update a fee/rate variable without a timelock (an extremely common pattern for AA "owner" functions, tips, taxes, or exchange curves), and (2) the ability to observe a pending large trigger unit in the DAG before it stabilizes and quickly compose a competing unit with parents chosen to keep an equal-or-lower level. Watching the DAG for large pending deposits and reacting quickly is well within reach of any semi-automated bot, similar to classical MEV/front-running on other DAG/blockchain systems, making this a realistic and repeatable attack whenever an AA author intentionally or carelessly designs a fee-adjustable AA.

### Recommendation
- Introduce an explicit timelock/delay for any fee/rate-changing state variable at the application (oscript) level, e.g., require that a new fee value only takes effect after N stabilized MCIs or seconds have passed since it was proposed.
- At the protocol/documentation level, warn AA authors that state-variable updates take effect for the very next processed trigger regardless of real-world broadcast order, and that trigger processing order is a function of unit `level`, not receipt time — so any mutable "fee"-like variable used directly in payouts is front-runnable.
- Provide/encourage a standard "commit-then-apply" pattern (store the new value plus an effective MCI, and read the old value until that MCI is reached) as a template for safe parameter changes in AAs.

### Proof of Concept
1. An AA implements a `case`/`state` branch, restricted to its "owner" trigger address, that sets `var['fee'] = X` and a separate branch that computes a user payout as `trigger.output[[asset=base]] * (1 - var['fee'])` (as in the sample exchange/tax AAs in this repo, e.g. `founder_tax`/exchange-rate patterns at `test/ojson.test.js:1510-1519` and `test/samples/51_attack_game.oscript:127-128`).
2. Victim broadcasts unit `V` containing a large payment trigger to the AA while `var['fee']` is low (e.g. 1%).
3. Owner observes `V` propagating in the DAG before it is included/stabilized, and immediately composes and broadcasts unit `F` (a trigger setting `var['fee'] = 0.99`) using parents that do not descend from `V`, so that `F.level <= V.level`.
4. When the MCI containing both units stabilizes, `aa_composer.handleAATriggers` orders triggers by `(mci, level, unit, address)` (`main_chain.js:1691-1706`, `aa_composer.js:59-69`), so `F` is processed before `V`.
5. `var['fee']` is now 0.99 before `V`'s trigger reads it (`aa_composer.js:1487-1502` — updates persist immediately with no delay), and the victim's payout is computed using the new 99% fee, resulting in near-total loss of the deposited value to the AA owner.

### Citations

**File:** aa_composer.js (L59-69)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
```

**File:** aa_composer.js (L1431-1463)
```javascript
	function executeStateUpdateFormula(objResponseUnit, cb) {
		if (bBouncing)
			return cb();
		if (!objStateUpdate) {
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			return cb();
		}
		var opts = {
			conn: conn,
			formula: objStateUpdate.formula,
			trigger: trigger,
			params: params,
			locals: objStateUpdate.locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStateVarAssignmentAllowed: true,
			bStatementsOnly: true,
			objValidationState: objValidationState,
			address: address,
			objResponseUnit: objResponseUnit
		};
		formulaParser.evaluate(opts, [], objStateUpdate.xpath, function (err, res) {
		//	console.log('--- state update formula', objStateUpdate.formula, '=', res);
			if (res === null)
				return cb(err.formattedError || "formula " + objStateUpdate.formula + " failed: "+err);
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			cb();
		});
	}
```

**File:** aa_composer.js (L1487-1502)
```javascript
	function saveStateVars() {
		if (bSecondary || bBouncing || trigger_opts.bAir)
			return;
		for (var address in stateVars) {
			var addressVars = stateVars[address];
			for (var var_name in addressVars) {
				var state = addressVars[var_name];
				if (!state.updated)
					continue;
				var key = "st\n" + address + "\n" + var_name;
				if (state.value === false) // false value signals that the var should be deleted
					batch.del(key);
				else
					batch.put(key, getTypeAndValue(state.value)); // Decimal converted to string, object to json
			}
		}
```

**File:** test/ojson.test.js (L1510-1519)
```javascript
						{ // exchange asset to bytes
							if: `{trigger.output[[asset=$asset]] > 0 AND var['mm_asset_outstanding']}`,
							init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]]; // 10Kb fee
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_bytes_balance = round($p / balance[$asset]);
					$amount = $bytes_balance - $new_bytes_balance; // we can deduct exchange fees here
				}`,
```

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```
