### Title
Intra-transaction reentrant AA-chain price manipulation of `balance[asset]`-based AMM/lending logic - (File: `aa_composer.js`)

### Summary
Obyte's AA execution engine allows a single root unit to trigger a chain of AA-to-AA calls (primary trigger → secondary triggers → possibly back into the same AA) that all execute **atomically**: if any AA in the chain bounces, the *entire* chain is rolled back to the pre-trigger savepoint at no cost beyond bounce fees. Any AA that prices assets from its own live `balance[asset]`/`balance[base]` (the documented pattern used by the bundled `uniswap_like_market_maker.oscript` sample and any bonding-curve/lending AA built the same way) can have its "spot price" pushed around by chaining self-referential calls within that same atomic unit, and the attacker can costlessly abort the whole sequence if the final state isn't favorable. This mirrors the RoeFinance bug class: a Balancer flash loan let the attacker atomically inflate/deflate an AMM reserve (donate + `sync()`), borrow against the manipulated valuation, and revert risk-free within one transaction.

### Finding Description
`handleTrigger` in `aa_composer.js` processes a primary AA trigger and, after sending the response unit, calls `handleSecondaryTriggers`, which recursively re-invokes `handleTrigger` for every AA that received an output from the response unit, using the *same* `conn`/`batch`/`trigger_opts` context so state and balance mutations are visible to later invocations in the chain: [1](#0-0) 

Crucially, this composed chain is transactional as a whole: if any secondary AA in the chain bounces, `revert()` rolls the whole chain back to the initial-balances savepoint and re-tries as a bounce, at the cost of only `bounce_fees`: [2](#0-1) [3](#0-2) 

This "reflect back into the same AA" pattern is explicitly exercised and validated by the test-suite (an AA is invoked, sends funds to a "bouncer" AA, which reflects the funds back, re-triggering the *original* AA a second time within the same atomic unit): [4](#0-3) 

Any AA that reads its own live balance to compute an exchange rate is exposed to this, e.g. the bundled AMM sample: [5](#0-4) [6](#0-5) 

The `balance[asset]` formula operator reads the exact current in-memory `objValidationState.assocBalances`, which is mutated by every prior step of the atomic chain, not a manipulation-resistant checkpoint: [7](#0-6) 

Put together: an attacker can post one root unit that (a) invests/swaps against the target AMM AA, (b) via a chain of reflector/secondary AAs, re-enters the same AMM AA one or more additional times while its `balance[$asset]`/`balance[base]` are in an attacker-favorable intermediate state, (c) extracts value (e.g. divesting `mm_asset` shares at an inflated `balance[base]`, or getting a better swap rate than the pre-manipulation market), and (d) if the sequence isn't profitable, simply causes a bounce anywhere downstream so the *entire* chain (including all the "manipulation" steps) reverts for the cost of bounce fees only — functionally identical to the flash-loan borrow/manipulate/repay-or-revert primitive abused in the RoeFinance exploit.

### Impact Explanation
Any AMM-, bonding-curve-, or lending-style AA on Obyte that values shares/collateral via its own current `balance[asset]` (as documented and recommended in the shipped `uniswap_like_market_maker.oscript` reference pattern) is exposed to atomic, cost-bounded, risk-free price manipulation using AA-to-AA reentrant chains, leading to fund loss for the AA (and its other users) analogous to the RoeFinance flash-loan drain.

### Likelihood Explanation
The chained/reentrant AA-call and atomic bounce-revert mechanics are core, intentional, and well-tested features of the AA composer (not edge-case bugs), and the reference AMM template that ships with ocore itself relies on `balance[asset]` for pricing without any TWAP/anti-manipulation safeguard, so any author following the documented pattern inherits the exposure. Exploitation only requires composing a "reflector" AA plus the target AA's public interface, all reachable by an ordinary unprivileged unit poster.

### Recommendation
- Document (or protocol-enforce) that AAs computing prices/exchange rates from `balance[asset]` must not trust the value read within a chain that can be extended or aborted atomically by the caller; recommend AAs use committed/finalized balances from a prior stable MCI, external oracle data feeds with `min_mci`, or explicit TWAP-style accounting rather than instantaneous `balance[]`.
- Consider providing a "locked" or "pre-trigger-snapshot" balance accessor for AA authors that reflects balances as of the primary trigger's arrival rather than the live value mutated by preceding steps of the same atomic reentrant chain.

### Proof of Concept
1. Attacker deploys a reflector/looping AA chain (as demonstrated feasible in `test/aa_composer.test.js`'s "issue recently defined asset" / "chain of AAs" tests) that, from one root unit, calls into the target AMM AA (e.g., an AA built like `uniswap_like_market_maker.oscript`), performs one or more `invest`/`swap` operations that shift `balance[$asset]`/`balance[base]`, then reflects back to re-trigger the target AA again in the same atomic unit while its `init` block reads the now-shifted `balance[...]`.
2. The attacker computes off-chain whether the resulting divest/swap in the second invocation yields a profit versus the first; if not, any downstream AA in the chain returns an error, causing `revert()` to roll back the whole chain to the `initial_balances` savepoint, so the attacker only pays bounce fees.
3. If profitable, the chain completes and the attacker walks away with value extracted from the AMM's manipulated intra-transaction balance, mirroring the RoeFinance flash-loan borrow→manipulate→repay-or-revert pattern.

### Citations

**File:** aa_composer.js (L909-945)
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
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```

**File:** aa_composer.js (L1702-1741)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
```

**File:** test/aa_composer.test.js (L450-527)
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
	addAA(asset_aa);
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-101)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
			},
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```
