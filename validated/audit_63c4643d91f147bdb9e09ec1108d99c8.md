### Title
Malicious AA trigger senders can inflate an AA's balance via retained bounce fees to manipulate share/ratio-based accounting, causing donation-style DoS and unfair dilution in vault-like AAs - (File: aa_composer.js, test/samples/uniswap_like_market_maker.oscript)

### Summary
The external report describes a donation attack against an ERC-4626-style vault: an attacker sends tokens directly to the vault (bypassing `deposit()`), inflating `totalAssets()` relative to `totalSupply()`, so that the `MIN_SHARES` check makes it prohibitively expensive (or impossible) for subsequent depositors to mint shares — a share-price-manipulation DoS. The analogous reachable pattern in this ocore/Obyte codebase is an Autonomous Agent (AA) that computes proportional shares/ratios from its own on-chain `balance[...]`, exactly as implemented in the reference `uniswap_like_market_maker.oscript` sample. Any unprivileged unit poster that becomes an AA trigger sender can inflate the AA's tracked `balance[base]` (or another asset balance) without a corresponding increase in the AA's own accounting (e.g., `var['mm_asset_outstanding']`) by exploiting the bounce-fee mechanism in `aa_composer.js`, since a bounced trigger permanently leaves `bounce_fees` behind in the AA's balance while state variables are rolled back.

### Finding Description
An AA that fails to match any `case`, or that explicitly calls `bounce(error)`, reverts all state variable and balance changes it made during evaluation, but the fee configured in `bounce_fees` (default `constants.MIN_BYTES_BOUNCE_FEE` if unspecified) is **not** refunded to the sender: [1](#0-0) 

```
if ((trigger.outputs.base || 0) < bounce_fees.base)
    return finish(null);
var messages = [];
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
```

Only `amount - fee` is refunded to the sender; the `fee` portion stays credited to the AA address's real on-chain balance because it was already added as an incoming payment when the trigger unit was processed. This is confirmed by the pre-check performed before AA logic executes: [2](#0-1) 

Any address can trigger this repeatedly and cheaply (each bounce costs only the configured `bounce_fees.base`, e.g. 10000 bytes as used in the sample AAs), silently growing the AA's `balance[base]` (or any asset for which `bounce_fees` are defined) with no corresponding state-variable update, since `bounce()` explicitly restores `stateVars`/`assocBalances` to their pre-trigger snapshot except for the retained fee: [3](#0-2) 

This is directly analogous to the "donate `USDe` to `StakedUSDe`" root cause: the attacker enlarges the pool's tracked balance without minting a corresponding claim, corrupting any AA that derives price/ratio/shares from `balance[...]`. The reference `uniswap_like_market_maker.oscript` sample is exactly such an AA — it computes the ratio of pooled assets to determine required deposit proportions and to size newly issued shares (`mm_asset`): [4](#0-3) [5](#0-4) 

Because `$bytes_balance` and `$asset_balance` are read straight from `balance[...]`, an attacker who inflates `balance[base]` via free bounce-fee donations (without ever running the "invest" case that increments `var['mm_asset_outstanding']`) shifts `$current_ratio` and the swap constant product `$p`, so legitimate depositors' required proportional payment (`$expected_asset_amount`) no longer matches what they intend to pay, and `bounce('wrong ratio of amounts...')` is triggered — the same "large required amount" DoS/exclusion outcome described in the report, and also lets the attacker front-run a pending deposit to change the ratio just before it lands.

### Impact Explanation
For any AA that uses `balance[...]`-derived ratios/ shares (the officially documented `uniswap_like_market_maker.oscript` pattern, and any real-world AA built on it, e.g. AMM pools, staking vaults, fundraising/shares AAs), an unprivileged trigger sender can:
- Grief/DoS legitimate depositors by shifting the pool ratio just before their deposit lands, causing their deposit to bounce (`wrong ratio of amounts`), similar to the medium-severity "front-run to cause DoS via minimum-shares/ratio checks" impact in the source report.
- Progressively skew the price-per-share so that new investors must supply disproportionately large "paired asset" amounts to match the ratio, effectively freezing out new deposits (fund freezing/participation DoS) — the same class of impact accepted for M-04 (Medium).

This does not directly allow theft of already-deposited funds, matching the "Medium" categorization applied to the large-donation variant of the original finding.

### Likelihood Explanation
Triggering an AA bounce is free of any special privilege — any address can send an Obyte payment to the AA's address with an amount at or slightly above `bounce_fees.base` but insufficient/mismatched to satisfy any `case`'s `if` condition, causing a bounce and leaving the fee in the AA balance. This can be repeated arbitrarily by a single unprivileged party (a "unit poster"/"AA trigger sender") with a linearly increasing cost (`bounce_fees.base` per attempt), making the attack economically comparable to the original report's "donate 1 ether" attack, and it can be executed precisely to front-run a specific pending deposit unit since Obyte units and their parent selection are publicly visible before finalization.

### Recommendation
- AA authors using balance-ratio accounting (as in `uniswap_like_market_maker.oscript`) should not rely on raw `balance[asset]` to compute share price/ratios without separately tracking a trusted, monotonic ledger of deposited principal (e.g., an internal `var[]` counter incremented only on successful "invest" cases), analogous to using virtual/offset shares in ERC-4626 mitigations.
- Consider explicitly subtracting any balance amounts that are not accounted for by internal state (i.e., reconcile `balance[base]` against the sum of internally tracked deposits) before computing ratios, or require a minimum locked "dead" share allocation on the very first deposit to raise the cost of ratio manipulation.
- Document to AA authors that `bounce_fees` are retained by the AA on every bounce and must be accounted for as "untracked income" if their logic derives economic parameters from `balance[...]`.

### Proof of Concept
1. Deploy an AA equivalent to `test/samples/uniswap_like_market_maker.oscript` (bounce fee defaults to `constants.MIN_BYTES_BOUNCE_FEE`, e.g. 10000 bytes, since none is explicitly configured).
2. Attacker sends a trigger unit to the AA with `trigger.outputs.base` just above the bounce-fee threshold and no data/asset payment matching any `case` condition (e.g., a bare payment with `trigger.output[[asset=base]] <= 1e5` and no paired asset) — none of the `if` conditions match, so the AA falls through to `bounce()`.
3. `aa_composer.js`'s `bounce()` refunds `amount - bounce_fees.base` to the attacker but leaves `bounce_fees.base` credited to the AA's balance: [6](#0-5) 
4. Repeat step 2 multiple times to inflate `balance[base]` without ever incrementing `var['mm_asset_outstanding']`.
5. A legitimate investor now sends a proportional deposit computed against the pre-attack ratio; because `$bytes_balance` (`balance[base] - trigger.output[[asset=base]]`) has grown from the accumulated bounce fees, `$expected_asset_amount` computed inside the AA no longer matches what the investor sent, and the deposit bounces with `'wrong ratio of amounts...'`: [7](#0-6) 
6. This can be repeated/timed to front-run any specific pending deposit, denying that investor's ability to deposit at the ratio they computed, and over time raises the cost of participating in the pool for new depositors.

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

**File:** aa_composer.js (L1850-1859)
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
