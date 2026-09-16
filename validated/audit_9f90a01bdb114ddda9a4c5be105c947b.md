### Title
Spot-balance-based valuation in the Uniswap-like AA template allows LP-share manipulation to drain co-investors - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The bundled Uniswap-like market-maker AA template computes both LP-share issuance ("invest in MM") and LP-share redemption ("divest MM shares") directly from the AA's *instantaneous* `balance[$asset]` / `balance[base]` at the time of the triggering unit, with no time-weighted or otherwise resistant price reference. This is the same root cause as the Vader H-18 finding: pro-rata payouts are computed off a spot pool balance that the same actor can move immediately beforehand, letting a partial LP holder extract more than their fair share of the pool at the expense of the other investors.

### Finding Description
The AMM template defines four cases sharing one pooled balance:

- "invest in MM" issues `$mm_asset` in proportion to `trigger.output[[asset=base]] / $bytes_balance`, where `$bytes_balance = balance[base] - trigger.output[[asset=base]]` — the pool balance *at the moment of this trigger* [1](#0-0) .
- "exchange bytes to asset" / "exchange asset to bytes" perform a constant-product swap using `balance[$asset]` and `balance[base]` computed at trigger time [2](#0-1) .
- "divest MM shares" redeems `$mm_asset` for `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])`, again reading the live `balance[...]` [3](#0-2) .

In Obyte's AA engine, `balance[asset]` is read from `objValidationState.assocBalances`, which is simply the AA's current on-chain balance (updated immediately when a trigger unit's outputs are credited), not any moving/weighted average [4](#0-3) . Each AA response is computed and posted as soon as the triggering unit is processed by `handlePrimaryAATrigger`/`handleTrigger`, and the AA's balance table (`aa_balances`) is updated synchronously with that response via `updateFinalAABalances` [5](#0-4) . There is no TWAP, delay, or averaging window built into the engine or into this template — the "price" used for every action is whatever the balance happens to be right after the previous action settled.

Because a single wallet can hold `mm_asset` (LP shares) and also freely trigger the swap cases, it can:
1. Post a unit that triggers the "exchange asset to bytes" (or "exchange bytes to asset") case with a large one-sided swap, skewing `balance[$asset]` vs `balance[base]` far from the pool's fair value (the attacker only needs enough of one side; if they control a large share of `mm_asset_outstanding` they don't even need to own outside capital proportionate to the whole pool, since the swap only needs to move the *ratio*, not the total value).
2. Immediately post a second unit (as soon as the first AA response is posted, without waiting for stabilization) triggering "divest MM shares", redeeming their `mm_asset` for `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])` computed off the now-skewed balances.
3. Optionally post a third unit reversing the swap (or letting other traders/arbitrageurs restore the ratio later), leaving the attacker with a redemption disproportionate to their true share of pool value.

Because `$investor_share` is a fixed fraction of `mm_asset_outstanding` but is multiplied against *both* asset and base balances measured at the manipulated instant, an LP holding fraction `f` of the shares can, by skewing the ratio right before divesting, receive more than `f` of the pool's fair value in the favored asset, with the shortfall coming out of the remaining LPs' redeemable balance. This mirrors exactly the Vader H-18 pattern: "swap to move price → immediately act on the moved price → restore/ignore afterward", enabled by the absence of any TWAP-style protection.

### Impact Explanation
Any address holding `mm_asset` LP shares (an ordinary, unprivileged trigger sender / AA author's own template users) can extract value from other LP holders of the same market-maker AA by sequencing a self-swap immediately before a divest. This causes AA fund loss/mis-distribution for other investors in the pool — the direct analog of the Vader "attacker gains IL reimbursement risk-free" impact. Because this is a bundled example/template that developers are expected to copy when building AA-based AMMs (as evidenced by its inclusion in the test/ojson fixtures documenting supported oscript patterns), any AA built from this template inherits the vulnerability, and it is only mitigated by gas/bounce-fee cost and the size of the attacker's own LP share, exactly as in the original report.

### Likelihood Explanation
Likelihood is Medium-High for any AMM/LP-style AA built following this exact documented template, because: (a) the engine offers `balance[...]` as the only "current price" primitive with no built-in TWAP feed, so template authors default to spot balances; (b) an attacker only needs to be an existing LP holder able to also send a swap trigger to the same AA address, both of which are unprivileged, ordinary user actions; (c) response processing (balance updates) happens immediately when a trigger unit arrives, requiring no wait for MC stability between the manipulating swap and the divest, so the two units can be posted back-to-back with minimal cost beyond the swap's own price impact and any bounce fee (10000 bytes per the template's divest-fee comment).

### Recommendation
- Do not use raw spot `balance[...]` for LP share issuance/redemption ratios in AA templates that are expected to be copied for production AMMs; instead accumulate a running time-weighted average of the pool ratio in state vars (e.g., update an accumulator on every trigger weighted by `timestamp - var['last_ts']`) and use that TWAP for divest/invest valuation.
- Alternatively, impose a minimum holding/cooldown period on `mm_asset` between mint and burn, or split invest/divest into two-phase (request + settle-after-N-mci) operations so that a single sender cannot both move the ratio and redeem shares before the ratio can be arbitraged back by third parties.
- Document prominently in `test/samples/uniswap_like_market_maker.oscript` that the spot-balance based invest/divest formulas are unsafe for multi-investor deployment without a TWAP or cooldown safeguard, since this file appears to serve as a reference implementation for community-built AAs.

### Proof of Concept
1. Deploy the AA from `test/samples/uniswap_like_market_maker.oscript` with `$asset` and `$mm_asset` initialized, and two investors, Alice (majority attacker) and Bob (victim), each depositing to receive `mm_asset` proportional to their contribution via the "invest in MM" case [6](#0-5) .
2. Alice posts a unit sending a large amount of `$asset` to the AA, triggering "exchange asset to bytes", which shifts `balance[$asset]` up and `balance[base]` down according to the constant-product formula [7](#0-6) .
3. Immediately (next unit, no wait for stability) Alice posts a unit sending her `mm_asset` shares to trigger "divest MM shares"; the payout is computed as `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])` using the now-skewed balances [3](#0-2) .
4. Because `balance[$asset]` is inflated at that moment, Alice's redemption of the `$asset` leg is worth more than her fair share of the pre-manipulation pool value; the deficit is paid for out of Bob's remaining claim on the pool once he tries to divest later.
5. Alice can later post a reversing swap to restore the ratio (or let the market/other traders do so), completing a risk-limited extraction of value from Bob, the other LP holder, with no TWAP mechanism in the engine (`formula/evaluation.js` `balance[...]` handler [4](#0-3) ) to prevent it.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-65)
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
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$mm_asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $issue_amount }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] += $issue_amount;
						}`
					},
				]
```

**File:** test/ojson.test.js (L1453-1479)
```javascript
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
```

**File:** test/ojson.test.js (L1488-1519)
```javascript
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
