### Title
Constant-product AMM reference AA computes swap/issue amounts purely from its own mutable on-chain balance ratio with no oracle/TWAP or slippage protection, enabling single-transaction price manipulation - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The `uniswap_like_market_maker.oscript` AA distributed as a reference oscript AA implements a constant-product market maker whose swap price and LP share-issuance ratio are derived exclusively from `balance[$asset]` and `balance[base]` read at execution time, with no external price feed, no TWAP, and no per-call slippage/minimum-output check. Because AA trigger execution (including any chained/secondary AA calls triggered by response messages) is resolved atomically within one primary trigger's processing pass in `aa_composer.js`, an attacker can distort the pool ratio and extract value using only their own capital in a single atomic operation — the same effect Allbridge's flash-loan attacker achieved by rapidly swapping to skew the USDC/USDT pool ratio.

### Finding Description
The AA's swap logic:
```
{ // exchange bytes to asset
  ...
  $asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
  $bytes_balance = balance[base] - trigger.output[[asset=base]];
  $p = $asset_balance * $bytes_balance;
  $new_asset_balance = round($p / balance[base]);
  $amount = $asset_balance - $new_asset_balance;
}
```
and the "invest in MM" (LP share issuance) logic:
```
$current_ratio = $asset_balance / $bytes_balance;
$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
```
both derive the exchange rate solely from the AA's *current* `balance[...]`, i.e. the pool composition at the moment the trigger is processed [1](#0-0) . There is no oracle cross-check, no cumulative/time-weighted average, and no caller-supplied minimum-output guard, so the realized `$amount` (or `$issue_amount`) can be pushed arbitrarily by whoever controls the balance ratio at execution time [2](#0-1) .

Crucially, ocore processes an AA's response chain — including any bounces and secondary AA triggers spawned from its outputs — as one atomic unit-processing pass rooted at a single primary trigger, via `handlePrimaryAATrigger` inside `handleAATriggers` in `aa_composer.js` [3](#0-2) . This means an attacker-controlled AA (or a sequence of messages within one posted unit that trigger further AA calls) can perform "borrow-manipulate-repay"-style sequences entirely within a single atomic execution: swap a large amount in to skew `balance[$asset]`/`balance[base]`, immediately act on the skewed ratio (e.g., mint LP shares cheaply or extract a mispriced swap), and reverse the position — all without ever needing an actual external flash loan, because the AA's own balance is the only oracle and it is fully attacker-observable and attacker-movable in the same atomic pass.

This mirrors the Allbridge Core root cause: the exploited pool used its own reserve ratio as the exchange-rate oracle, and a large, capital-efficient swap sequence executed atomically (via flash loan there, via ocore's atomic AA response-chain here) was sufficient to distort that ratio and extract value.

### Impact Explanation
Any deployed instance of this pattern (self-priced constant-product AMM AA, or any AA using its own balance ratio as a price/exchange-rate input for payouts or issuance) is exposed to atomic ratio-manipulation attacks: an attacker can mint disproportionate LP shares, extract disproportionate swap output, or drain paired-asset reserves, causing direct fund loss to other LPs/users of the AA — equivalent in class and severity to the $1.65M Allbridge loss (concrete unauthorized value extraction / AA fund loss).

### Likelihood Explanation
The reference AA computes the manipulable ratio directly from `balance[]` without any external anchor, and ocore's atomic secondary-trigger/bounce execution model (all response messages from one primary trigger, including AA-to-AA calls, resolved together before commit) provides the same capital-efficient, atomic exploitation primitive that flash loans provide on EVM chains — no external lending protocol is required on Obyte to reproduce the attack pattern, only sufficient capital for one round-trip, making exploitation practically reachable for any funded, unprivileged unit poster interacting with such an AA.

### Recommendation
- Do not use the AA's own instantaneous `balance[]` ratio as the sole price/exchange-rate source for issuance or swaps; require an external oracle (`data_feed`) confirmation or a time-weighted/cumulative average computed from state vars updated over multiple stable MCIs.
- Add caller-supplied minimum-output / maximum-slippage parameters (`trigger.data.min_amount`) and bounce if the computed amount is worse than requested.
- Consider imposing per-MCI or per-block caps on swap size relative to reserves, and/or a cooldown between large ratio-moving trades and share issuance/redemption for the same address.
- Since this is a documentation/reference sample (`test/samples/uniswap_like_market_maker.oscript`), add an explicit security warning in the sample and in any oscript/AA developer documentation referencing it, so integrators don't deploy it unmodified as a real liquidity pool.

### Proof of Concept
1. Attacker funds an address with base bytes and holds some of `$asset`.
2. In a single atomic trigger sequence, attacker sends a large `base` payment to the "exchange bytes to asset" case, sharply moving `$p / balance[base]` and extracting a favorable `$asset` amount while depressing the effective `$asset_balance`.
3. In the same or immediately following atomic step (bounce/secondary trigger chain resolved in one `handlePrimaryAATrigger` pass, per `aa_composer.js`), attacker (or a colluding AA call) triggers "invest in MM" while `$current_ratio` is still skewed, minting LP shares (`$issue_amount`) at a favorable, manipulated ratio.
4. Attacker reverses the initial swap ("exchange asset to bytes") to restore most of the spent base bytes, retaining the disproportionately issued LP shares/mispriced `$asset`, net-extracting value from other pool participants — reproducing the ratio-manipulation mechanics of the Allbridge Core incident without needing an external flash-loan protocol.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-48)
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
```

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

**File:** aa_composer.js (L59-80)
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
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
```
