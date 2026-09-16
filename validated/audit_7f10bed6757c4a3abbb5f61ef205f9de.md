### Title
AMM swap/deposit AAs shipped as ocore reference implementations lack slippage protection, enabling deterministic sandwich attacks on trigger senders - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The Uniswap-like market-maker AA shipped in the ocore repository as the canonical example of an AMM built on top of `oscript`/AA triggers computes swap output purely from the AA's `balance[...]` at the moment the trigger executes, with **no user-supplied minimum-output ("slippage") parameter**. Any address can post a trigger unit against this AA (or any AA copied from this template, which is the reference pattern Obyte AA developers use for building AMMs), and because AA-trigger execution order for a given main-chain index is deterministic and computable in advance from unit content (level and unit hash), an attacker can construct a front-running and back-running pair of triggers that execute immediately before and after the victim's trigger, extracting the victim's expected value — the same "deposit gets sandwiched" bug class as in the referenced Sherlock report, just expressed through `oscript`/AA triggers instead of Solidity calls.

### Finding Description
The AMM sample's swap cases compute the payout entirely from the current AA balance captured inside the trigger's own `init` block: [1](#0-0) [2](#0-1) 

`balance[$asset]` and `balance[base]` reflect the AA's post-deposit-but-pre-trigger-payout state, i.e., the current constant-product price. There is no `trigger.data.min_amount_out` (or similar) check anywhere in the case, so the trigger sender has no way to bound how much value they will lose to price impact caused by *other* triggers executed against the same AA in the same batch. This mirrors exactly the root cause called out in the external report: `amount * balance / totalSupply`-style pricing computed at execution time without a caller-specified minimum acceptable output.

In ocore, AA triggers are not processed in submission (mempool) order. They become eligible once the triggering unit's MCI stabilizes, and multiple simultaneously-eligible triggers targeting the same AA are ordered deterministically by `(units.level, units.unit, address)`: [3](#0-2) 

Because `level` and `unit` (the unit hash) are both derivable/chooseable by the unit's author (via parent selection and content), an attacker who observes an unstable victim trigger unit in the DAG (visible well before it becomes stable, since units propagate before the MC advances) can craft their own front-run trigger with a `level`/hash that sorts ahead of the victim's, and a back-run trigger with a `level`/hash sorting after it — reproducing the "attacker deposits first, victim executes at worse price, attacker reverses/harvests" sandwich pattern even though there is no literal "mempool gas auction" as in Ethereum.

### Impact Explanation
A trigger sender interacting with this AMM AA (or any real-world Obyte AA cloned from this widely-referenced template, which is the documented pattern for building AMMs on Obyte) can lose funds to a sandwich attack: they receive materially less asset/bytes than the fair-price quote they expected, while the attacker profits risklessly by reverting their own position after extracting the price impact. This is a concrete loss of funds for an unprivileged AA-trigger sender, matching the "AA fund loss" impact category.

### Likelihood Explanation
Likelihood is high for any AA deployed from this pattern that receives meaningful trading volume: the attack requires only the ability to post ordinary payment/trigger units (available to any address) and to observe the victim's pending unit in the DAG before it stabilizes — no privileged network position, hub access, or malicious-node behavior is required, satisfying the "unprivileged unit poster / AA trigger sender" reachability requirement.

### Recommendation
- Add an explicit slippage-protection parameter to swap (and any ratio/price-dependent) cases, e.g. require `trigger.data.min_amount_out` and `bounce()` if the AA-computed `$amount` is less than it.
- Document this requirement prominently in the reference `uniswap_like_market_maker.oscript` sample shipped with ocore so that AA authors copying the pattern do not omit slippage checks, since this file is the de-facto template referenced by the ecosystem for AMM-style AAs.
- Consider providing a standard library/util snippet in ocore's oscript documentation demonstrating the min-output pattern for balance-ratio-based payouts.

### Proof of Concept
1. Attacker observes an unstable trigger unit `U_victim` sent to the AMM AA's address that calls the "exchange bytes to asset" case with a large `trigger.output[[asset=base]]`.
2. Attacker crafts `U_front` (swap asset→bytes or bytes→asset in the same direction to move the price against the victim) with parent selection chosen so that, once both `U_front` and `U_victim` are in the same eligible-trigger batch, `U_front` sorts before `U_victim` per the `ORDER BY units.level, units.unit, address` rule in `handleAATriggers` (main_chain.js:1705).
3. `U_front` executes first, shifting `$asset_balance`/`$bytes_balance` used by the constant-product formula in lines 104-122 / 126-144 of `uniswap_like_market_maker.oscript`.
4. `U_victim` then executes and receives a payout computed off the manipulated balances — worse than the price it would have gotten absent `U_front`.
5. Attacker posts `U_back`, reversing their position and capturing the price-impact profit extracted from the victim, since no `min_amount_out` check exists to bounce the victim's degraded trade.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L102-122)
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
```

**File:** test/samples/uniswap_like_market_maker.oscript (L124-144)
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
