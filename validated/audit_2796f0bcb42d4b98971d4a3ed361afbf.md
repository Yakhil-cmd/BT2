## Title
Missing slippage protection in AMM-style AA swaps enables MCI/level-ordering "sandwich" attacks - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The reported bug class describes an AMM DEX swap executed without minimum-output ("slippage") protection, letting an attacker front-run and back-run the victim's trade to extract value ("sandwich attack"). The ocore repository ships an official reference AMM Autonomous Agent template, `uniswap_like_market_maker.oscript`, that implements the exact same swap pattern (constant-product pricing based on current AA balance) with **no minimum-received / maximum-price guard** supplied by the trigger. Because AA triggers in ocore are executed deterministically in main-chain-index/level order rather than strictly in the order users submit them, an attacker who controls unit parents/level can order their own trigger unit immediately before and after a victim's swap trigger, replicating a sandwich attack against any AA built from this pattern.

### Finding Description
The "exchange bytes to asset" and "exchange asset to bytes" cases compute the AMM output purely from the AA's current balance and the incoming trigger output, with no way for the caller to bound the acceptable price: [1](#0-0) [2](#0-1) 

Unlike a traditional AMM front-run scenario (mempool ordering by miner/validator), ocore's AA execution model determines the processing order of trigger units by (`main_chain_index`, `level`, `unit`, `address`) once a unit becomes stable, not by wall-clock submission order: [3](#0-2) [4](#0-3) 

Because `level` is derived from the unit's chosen parents (attacker-controlled) and MCI is fixed only once the DAG stabilizes, an attacker who observes an unstable/unconfirmed victim trigger targeting the market-maker AA can construct: (1) a unit that will stabilize with a lower `(mci, level)` than the victim's trigger (executes first, moving the AMM price against the victim), and (2) a unit that stabilizes with a higher `(mci, level)` (executes after the victim, reversing the attacker's own position for profit) — the classic sandwich pattern, but achieved via DAG-ordering manipulation instead of miner mempool manipulation.

### Impact Explanation
Any AA deployed using this pattern (or the exact sample if used as-is) allows an attacker to systematically extract value from every trigger that swaps against the AMM, because the swap formulas at lines 108-110 and 130-132 accept whatever price results from the balances at execution time, with no `min_amount` check against `trigger.data`. This is a fund-loss issue for AA users (Medium/High depending on liquidity and swap sizes), matching "AA fund loss" impact criteria.

### Likelihood Explanation
Likelihood is constrained by the difficulty of reliably controlling `level`/MCI placement relative to a specific victim unit and by the cost of posting extra units, similar to the "rare and hard to exploit" conditions noted in the original report. It requires an attacker to monitor pending triggers to this AA and race unit composition/witnessing, which is feasible but not trivial — consistent with a Medium likelihood.

### Recommendation
Autonomous Agents implementing AMM-style swaps should accept an explicit slippage bound from `trigger.data` (e.g., `trigger.data.min_amount` or `trigger.data.max_price`) and `bounce()` if the computed output/price violates it, mirroring standard AMM slippage protection. This guidance should be added to the reference `uniswap_like_market_maker.oscript` sample so that developers building on it do not inherit the vulnerability.

### Proof of Concept
1. Attacker monitors the DAG for an unstable unit sending `base` to the market-maker AA (an "exchange bytes to asset" trigger).
2. Attacker posts unit A (parents chosen to obtain a lower `level` within the same eventual MCI, or an earlier MCI) that swaps `base`→asset first, shifting `$asset_balance`/`$bytes_balance` unfavorably for the victim.
3. Victim's trigger executes next per the deterministic `(mci, level, unit, address)` ordering, receiving fewer assets than expected, since no `messages: [{app:'payment'...}]` output check exists at lines 112-121.
4. Attacker posts unit B (ordered after the victim) that swaps back asset→`base`, capturing the price impact created in step 2/3 as profit — no state anywhere validates that the executed price matches what the victim intended. [1](#0-0) [5](#0-4)

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

**File:** aa_composer.js (L59-68)
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
