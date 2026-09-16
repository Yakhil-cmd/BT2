### Title
ERC4626-style Donation/Inflation Attack on Share-Based AAs (e.g. Uniswap-like Market Maker Template) - (File: test/samples/uniswap_like_market_maker.oscript, aa_composer.js)

### Summary
The bundled `uniswap_like_market_maker.oscript` AA template implements a vault/AMM pattern that mints a "share" asset (`mm_asset`) proportional to a deposit relative to the AA's tracked balances, and lets holders redeem shares for a proportional slice of `balance[base]`/`balance[$asset]` — structurally identical to an ERC4626 vault. The share/asset accounting relies on `var['mm_asset_outstanding']` staying in sync with the AA's actual UTXO balances, but `aa_composer.js`'s trigger-handling logic allows an attacker to increase the AA's real balance without going through any case that updates `mm_asset_outstanding`, enabling the classic first-depositor/donation inflation attack described in the ERC4626 report.

### Finding Description
The share-issuance logic is in `test/samples/uniswap_like_market_maker.oscript` lines 33-65 (invest) and 67-101 (divest): [1](#0-0) [2](#0-1) 

Shares minted on deposit are computed as `round($investor_share_of_prev_balance * var['mm_asset_outstanding'])`, where `$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance` and `$bytes_balance = balance[base] - trigger.output[[asset=base]]` (i.e., the AA's *actual* prior balance). On redemption, the payout is `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])` — again based on actual balances, not the tracked `mm_asset_outstanding` accounting alone. This means the exchange rate (shares ⇄ underlying) is driven by the AA's real balance, exactly the vulnerable pattern OZ's `_decimalsOffset`/virtual-shares mitigation was designed to fix in ERC4626.

The root cause that makes the donation step exploitable in ocore (unlike a plain balance mapping in Solidity, where a `transfer()` unconditionally changes balance) is in `aa_composer.js`'s trigger/bounce handling: when a trigger unit's payment output(s) do not satisfy any `if` condition in `messages.cases`, the AA ends up with no messages to send and calls `bounce()`: [3](#0-2) 

Inside `bounce()`, if the attacker's `trigger.outputs.base` amount is below the bounce fee (`bounce_fees.base`, default `constants.MIN_BYTES_BOUNCE_FEE` since this template does not override `bounce_fees`), the function simply calls `finish(null)` and does **not** send any refund message — the funds silently stay with the AA: [4](#0-3) 

Critically, the fee-sufficiency check only inspects the `base` asset amount; for any other asset (like the custom `$asset` in the market maker), `bounce_fees[asset]` is `undefined`/falsy, so the corresponding check `if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset])` is skipped entirely regardless of how large the donated asset amount is: [5](#0-4) 

Consequently, an attacker can craft a single trigger unit that:
1. Sends a tiny amount of bytes to the AA (below `bounce_fees.base`, e.g. below `MIN_BYTES_BOUNCE_FEE`) so that neither the "invest" case (`trigger.output[[asset=base]] > 1e5`) nor the "exchange bytes to asset" case matches.
2. Simultaneously sends a large amount of `$asset` to the same AA address.
3. Because no `if` in `messages.cases` matches this combination and `trigger.outputs.base` is below the bounce-fee threshold, `bounce()` short-circuits to `finish(null)` — no response unit is produced, `var['mm_asset_outstanding']` is untouched, but `balance[$asset]` at the AA address is now permanently inflated by the donated amount (the coins are already at that UTXO address and never get refunded).

This is the "donation" half of the classic ERC4626 inflation attack. Combined with a first (or any) legitimate deposit, a subsequent victim's deposit computation `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` can round down to zero (or far below fair value) because `$bytes_balance`/`$asset_balance` used in the ratio checks are now inflated relative to `mm_asset_outstanding`, letting the attacker (who pre-positioned minimal real shares) redeem a disproportionate amount of the pool including the victim's deposit via the divest case at line 67-101.

### Impact Explanation
Any unprivileged AA trigger sender can permanently donate assets into a share-accounting AA's balance without moving `mm_asset_outstanding`, corrupting the share-to-asset exchange rate. A subsequent victim depositor can have their contribution diluted to zero minted shares (rounding to 0) while the attacker's existing/newly-acquired shares entitle them to redeem the inflated pool, resulting in concrete unauthorized fund loss for the victim and fund theft by the attacker — the same impact class as the reported ERC4626 inflation attack (unauthorized spending / AA fund loss).

### Likelihood Explanation
The attack requires only a single, unprivileged trigger unit crafted by any address holding a small amount of bytes and the target asset — no special privileges, no cooperation from the AA operator, and no race with other network participants beyond ordinary front-running of a victim's deposit (a well-known and easy technique in DAG/mempool-like environments). The underlying AA template (`uniswap_like_market_maker.oscript`) is a documented, ready-to-deploy pattern that real Obyte users are expected to copy/deploy, and the enabling `bounce()` behavior in `aa_composer.js` is core, unconditional protocol logic applicable to any AA using this share/vault pattern.

### Recommendation
- In the AA template, track deposits solely via `trigger.output[[asset=...]]` deltas rather than `balance[...]` snapshots, or maintain an explicit running total-assets state variable (`var['total_base']`, `var['total_asset']`) updated only inside case branches, so out-of-band donations cannot affect the exchange-rate computation.
- Enforce a minimum-liquidity/virtual-shares offset analogous to ERC4626's mitigation: lock a small amount of initial shares permanently, or require `mm_asset_outstanding` and `balance[...]` to be reconciled with an explicit invariant check before minting/redeeming.
- At the protocol level, consider tightening `bounce()` so that "silently absorbed" sub-bounce-fee payments (of any asset, not just base) either always bounce fully or are surfaced to the AA's state logic, preventing untracked balance inflation for AAs relying on `balance[...]`-based accounting.

### Proof of Concept
1. Deploy the `uniswap_like_market_maker.oscript` AA and initialize `mm_asset` via the `define` case (`test/samples/uniswap_like_market_maker.oscript:8-32`).
2. Attacker sends a first tiny "invest" trigger (bytes + a small amount of `$asset`) satisfying the `$asset_balance == 0 OR $bytes_balance == 0` initial-deposit branch (`uniswap_like_market_maker.oscript:38-41`), receiving `mm_asset` shares 1:1 to `balance[base]`.
3. Attacker sends a second trigger unit carrying: (a) bytes strictly below `bounce_fees.base` (default `constants.MIN_BYTES_BOUNCE_FEE`), and (b) a large amount of `$asset`. Because neither `if` condition in `messages.cases` matches this combination, the AA falls into the `bounce('no messages')` path (`aa_composer.js:1868-1877`), and since `trigger.outputs.base < bounce_fees.base`, `bounce()` returns via `finish(null)` without refunding (`aa_composer.js:909-929`), leaving the donated `$asset` permanently in the AA's balance with no update to `var['mm_asset_outstanding']`.
4. A victim now sends a normal "invest" trigger; `$asset_balance` (inflated by the donation) skews `$current_ratio` and `$expected_asset_amount`, and/or `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` rounds down, so the victim receives disproportionately few `mm_asset` shares for their contribution.
5. The attacker then triggers the "divest" case (`uniswap_like_market_maker.oscript:67-101`) with their shares, receiving a payout computed from the now-inflated `balance[$asset]`/`balance[base]`, capturing value contributed by the victim.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L34-47)
```text
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

**File:** test/samples/uniswap_like_market_maker.oscript (L70-98)
```text
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
```

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

**File:** aa_composer.js (L1852-1859)
```javascript
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

**File:** aa_composer.js (L1868-1877)
```javascript
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
```
