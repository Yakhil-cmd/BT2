## Title
Exchange-rate / bonding-curve AAs relying on `balance[asset]` are vulnerable to attacker-controlled balance inflation (donation attack) - (File: `formula/evaluation.js`, `aa_composer.js`)

### Summary
The reported issue is a "price/exchange-rate derived from a manipulable pool balance" bug class: an attacker inflates the balances read by the pricing formula (via direct deposit) before the price is computed, skewing the resulting exchange rate. ocore exposes the exact same primitive to any Autonomous Agent (AA) author through the `balance[asset]` opcode, which returns the AA's current confirmed on-chain balance — a value that is fully attacker-influenceable by simply sending coins to the AA address, either within the very unit that triggers the price-dependent case or in a prior, non-triggering unit.

### Finding Description
`balance[asset]`/`balance[address][asset]` in `formula/evaluation.js` resolves to `objValidationState.assocBalances[address][asset]`, which is the AA's live on-chain balance held in the `aa_balances` table (or the equivalent in-memory value during dry-run/estimation): [1](#0-0) 

Critically, this balance already includes the coins that arrived in the *current* triggering unit. `getTrigger()` sums up **all** outputs sent to the AA address across **every** payment message contained in the triggering unit into `trigger.outputs[asset]`: [2](#0-1) 

`updateInitialAABalances()` then adds `trigger.outputs[asset]` directly onto the AA's persisted balance *before* the AA's `init`/case formulas (including price/ratio calculations) run: [3](#0-2) 

Because a single unit can carry multiple `payment` messages, an unprivileged trigger sender fully controls how much extra value lands in `balance[asset]` at formula-evaluation time — this is functionally identical to a malicious actor pre-depositing into `CURVE_POOL` to inflate `CURVE_POOL.balances(i)` before `get_dy`/LP-value is computed in the referenced report. Bonding-curve or AMM-style AAs (the exact pattern shown in the shipped sample `test/samples/uniswap_like_market_maker.oscript`) that read `balance[asset]` to derive ratios/prices are exposed to this unless every such read is carefully offset by subtracting `trigger.output[[asset=...]]`: [4](#0-3) [5](#0-4) 

Additionally, `balance[asset]` reflects balance changes from *any prior* unit that silently sent coins to the AA without matching a case (a common accept-catch-all pattern), so an attacker can pre-fund the AA's balance in an earlier, cheap unit and then immediately submit the price-sensitive trigger, achieving the same effect atomically from the perspective of DAG ordering.

### Impact Explanation
Any AA whose messages/state formulas compute a price, exchange rate, or share/LP issuance amount from `balance[asset]` (its own or another AA's, via the two-parameter form) without excluding the attacker-controlled inbound amount can be manipulated to mis-price a swap or a share-issuance/redemption, leading to direct fund loss for the AA (over-issuing shares/tokens) or for other users (getting a worse rate than the true pool state implies). This maps to concrete unauthorized-value-extraction / AA fund-loss impact, the same class flagged in the reported Curve vault issue.

### Likelihood Explanation
High for any AA author who writes a bonding-curve/AMM/exchange-rate AA and reads `balance[asset]` directly (rather than subtracting `trigger.output[[asset=...]]`, as ocore's own sample correctly does). No special privilege is needed — a single ordinary unit with one or more payment messages to the AA address is sufficient to control the value returned by `balance[asset]` at the moment the price formula executes.

### Recommendation
- Document explicitly (and enforce via linting/sample templates) that any AA computing ratios/prices from `balance[asset]` must always subtract `trigger.output[[asset=...]]` (and account for possible multiple payment messages within the same unit) to obtain the pre-trigger balance, as already done in `uniswap_like_market_maker.oscript`.
- Consider exposing a dedicated opcode/field that returns the AA's balance strictly *before* the current trigger's outputs are applied, removing the need for manual subtraction and eliminating a common source of author error.
- For AAs that accept unsolicited/side-channel deposits (silent "accept coins" cases), recommend explicitly quarantining or ignoring donated balances that arrive outside of the expected trigger flow before they're used in price-sensitive computations.

### Proof of Concept
1. Deploy an AA implementing a bonding-curve/AMM case that computes `$ratio = balance[asset_A] / balance[asset_B]` (or similar) without subtracting `trigger.output`.
2. Attacker composes a single unit containing two `payment` messages to the AA address: one for the real trigger payload/output, and one extra "donation" output in `asset_A`, both landing in `trigger.outputs` per `getTrigger()` (`aa_composer.js:375-397`).
3. `updateInitialAABalances()` merges the donation into `assocBalances[address][asset_A]` prior to the case's `init` formula running (`aa_composer.js:474-527`), so `balance[asset_A]` read by the pricing formula already reflects the inflated value.
4. The AA computes a skewed ratio/price and issues an incorrect amount of shares/tokens or accepts an incorrect swap amount, resulting in fund loss to the AA or to other participants.

### Citations

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

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
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
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L474-527)
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
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
```

**File:** test/samples/uniswap_like_market_maker.oscript (L33-47)
```text
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
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
