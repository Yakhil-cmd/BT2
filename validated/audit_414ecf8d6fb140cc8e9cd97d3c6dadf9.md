### Title
Missing slippage/minimum-output protection in AMM-pattern AAs enables sandwich-attack fund extraction — ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The Alchemix `RevenueHandler` bug is a "no minimum-received check tied to actual market conditions" flaw: the contract computes an expected output purely from the current pool state at execution time and accepts any result that is merely `>= input`, so an attacker can move the pool price immediately before the victim's trade executes and move it back after, pocketing the difference. Obyte's reference constant-product-AMM AA pattern (shipped as `test/samples/uniswap_like_market_maker.oscript`, and parsed/validated identically in `test/ojson.test.js:1382-1537`) implements the exact same anti-pattern inside an Autonomous Agent (AA): the exchanged amount is derived solely from the AA's own current `balance[...]` at trigger time, with no trader-supplied minimum-output/maximum-slippage parameter and no oracle cross-check.

### Finding Description
In the AMM AA, both swap branches compute the output amount from the constant-product invariant using only the AA's balances observed at the moment the trigger is processed: [1](#0-0) [2](#0-1) 

There is no `min_amount_out` / slippage-bound field in `trigger.data`, and the `if` condition for the case only gates on `trigger.output[[asset=...]] > 0`, not on any expected-price agreement. The "invest"/"divest" cases have a partial check (`$expected_asset_amount != trigger.output[[asset=$asset]]` bounce), but that check is evaluated against the pool's balance at the same instant the investment trigger executes — an attacker who fronts a large opposite-direction trade in a unit that gets ordered immediately before the victim's trigger (and reverses it in a unit ordered immediately after) can move `$asset_balance`/`$bytes_balance` used in the ratio calculation, exactly mirroring the Curve-pool sandwich described in the report.

AA trigger execution order in ocore is deterministic but attacker-influenceable via DAG construction: triggers become due for execution as soon as their containing unit's MCI stabilizes, and multiple pending triggers targeting the same AA are processed in `ORDER BY units.level, units.unit, address` (a deterministic order the poster can attempt to shape via unit content/parent selection), as seen in the trigger-collection query: [3](#0-2) 

Because `balance[...]` reads reflect only the AA's ledger state at the moment each trigger is processed (before/after prior triggers in the same batch), and the AMM AA has no protection tying the executed price to a trader-approved bound, an attacker who can get their manipulating unit ordered adjacent to the victim's unit captures the price impact that should have accrued to the AA's liquidity/shareholders — the same economic mechanism as the reported Alchemix issue.

### Impact Explanation
This causes **direct loss of funds** for holders of the AA's pooled assets (analogous to veALCX stakers in the original report): value that should remain in the AMM pool (and thus be reflected in `mm_asset`/base-asset balances redeemable by investors) is siphoned off by the attacker executing a front-run + victim-trade + back-run sequence, extracting the price-impact spread. Because the AA design pattern is shipped by the ocore project itself as a reference/example for AA authors (and is exercised by the test suite), any AA author who builds a production exchange/market-maker AA following this documented pattern inherits the vulnerability, and any unprivileged trigger sender can act as both the attacker and/or victim without special privileges.

### Likelihood Explanation
Executing the attack requires only the ability to post ordinary payment units to the AA address (which any user can do) and enough capital to move the pool's ratio meaningfully — no privileged role, oracle manipulation, or node compromise is needed. The economic incentive scales with trade size and pool depth exactly as in the original report (larger revenue/trade amounts and thinner pools increase attacker profit), making this a realistic, repeatable griefing/theft vector against any AA instantiated from this pattern.

### Recommendation
The AMM/exchange AA pattern should require the trigger sender to supply an explicit minimum-acceptable-output (or maximum-acceptable-price) parameter in `trigger.data`, and bounce the trigger if the computed `$amount` (or ratio) does not satisfy that trader-specified bound — mirroring standard AMM slippage protection rather than accepting whatever the instantaneous pool state yields. Since this is a documented example intended to guide AA authors, the sample/documentation should be updated to demonstrate this protection so that AAs built from it are not systemically vulnerable to sandwich attacks.

### Proof of Concept
Conceptual reproduction against `uniswap_like_market_maker.oscript`:
1. Attacker observes a victim's pending "exchange bytes to asset" trigger unit (large `trigger.output[[asset=base]]`) targeting the AMM AA before it stabilizes.
2. Attacker posts unit A: a large "exchange asset to bytes" (or vice-versa) trigger that shifts `$asset_balance`/`$bytes_balance` unfavorably, constructed/timed so it is ordered before the victim's trigger.
3. Victim's trigger executes against the now-skewed pool, receiving less `$asset` than the true pre-manipulation price would have given, per the formula at [4](#0-3) 
4. Attacker posts unit B immediately after, reversing their original trade, restoring the pool and capturing the price-impact spread as profit — identical in structure to the reported Curve-pool sandwich, just executed via ocore AA triggers/units instead of Ethereum flash-loan transactions.

### Citations

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

**File:** test/samples/uniswap_like_market_maker.oscript (L124-145)
```text
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
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```

**File:** main_chain.js (L1691-1723)
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
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
```
