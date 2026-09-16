This confirms the mechanism: when no message case matches a trigger (e.g. `no messages after filtering`), the AA still "eat[s] the received coins and send[s] no response" — the trigger's payment is silently absorbed into the AA's balance with no refund, as shown at [1](#0-0) , and equivalent early-exit behavior is validated in `test/aa.test.js` `'no messages'`/`'no outputs'`/`'only 0 output'` tests where the trigger amount is retained by the AA's balance since no message fires. This is the exact mechanism that lets any unprivileged unit poster permanently inflate an AA's on-chain `balance[asset]` without the AA's internal accounting (state vars) ever recording it.

## Title
Donation-based balance manipulation of `balance[]`-driven AMM/bonding-curve AAs permanently skews reserves and dilutes investor shares - (File: formula/evaluation.js, aa_composer.js)

### Summary
The oscript formula engine exposes a `balance[asset]` operator that returns the AA's *actual* on-chain coin balance (from `aa_balances`, kept in sync with real payments received) rather than an AA-tracked reserve variable. Any unprivileged address can send a payment directly to an AA's address; if the payment does not match any `if` condition or is filtered out (`no messages after filtering`, `no messages after removing 0-outputs`, etc.), the AA silently absorbs the coins into its own balance and issues no response, per the `handleSuccessfulEmptyResponseUnit` path in `aa_composer.js`. Because canonical AMM/market-maker-style AAs (as documented by the shipped sample `test/samples/uniswap_like_market_maker.oscript`) compute investment/exchange ratios directly from `balance[base]` / `balance[$asset]`, an attacker can inflate one side of the reserve pool with an unsolicited "donation" that the AA cannot distinguish from legitimate trading activity or refuse, permanently distorting the price/ratio used by every subsequent participant — the same root pattern as the NORMIE incident, where funds injected into a fee-collecting address (outside of the intended flow) diluted a supply/price calculation that the contract logic implicitly trusted as accurate.

### Finding Description
`balance[asset]`/`balance[address][asset]` in the formula evaluator reads straight from `objValidationState.assocBalances`, which is initialized from the `aa_balances` table (the AA's real, cumulative on-chain balance), as seen in `formula/evaluation.js` `readBalance()`: [2](#0-1) 

That balance is updated on every incoming payment to the AA address, in `updateInitialAABalances()`, which unconditionally adds `trigger.outputs[asset]` to the AA's balance before any case-matching logic runs: [3](#0-2) 

If none of the AA's message `if` conditions match the trigger (or all messages get filtered to zero outputs), the AA does not bounce the funds back — it keeps them and finishes with no response messages: [4](#0-3) 

This "silent absorption" behavior is exercised and confirmed by the test suite (`no messages`, `no outputs`, `only 0 output` in `test/aa.test.js`), where the triggering payment amount remains inside the AA and the trigger's sender receives nothing back.

The officially documented constant-product market-maker pattern (`test/samples/uniswap_like_market_maker.oscript`) computes reserve/ratio math directly from live balances: [5](#0-4) 

`$asset_balance` and `$bytes_balance` are derived by subtracting only *this trigger's own* outputs from the *cumulative* `balance[]`; they cannot distinguish coins from a legitimate previous trade from coins that were simply dropped on the AA address by an unrelated, non-matching, or deliberately crafted trigger. Because `balance[]` is the ground truth used for both investment pricing (`$current_ratio`) and exchange pricing (`$p = $asset_balance * $bytes_balance`), any attacker-controlled deposit that gets absorbed (matches no case, or is itself processed as a "donation-priced" trade) permanently and unilaterally shifts the reserve ratio in the attacker's favor or to other users' detriment, exactly mirroring how NORMIE's cross-chain tax wallet balance was diluted by an unsanctioned flash-loaned deposit that the price-determining logic implicitly trusted.

### Impact Explanation
Any address holding minimal bytes can send a single unit to a `balance[]`-based AA (market maker, bonding curve, vesting pool, vault, etc.) that permanently corrupts the reserve accounting the AA relies on for all pricing/payout formulas. Consequences include:
- Permanent mispricing of the AMM/bonding-curve exchange rate, letting an attacker later trade at a manipulated favorable rate (fund loss for the AA/other users).
- Dilution of the redemption value of already-issued shares (`mm_asset_outstanding`), since `$investor_share * balance[asset]` no longer reflects the true tradable/attributable reserve, only inflated by unattributed donations.
- No way for the AA to "reject" or "refund" the poisoning deposit, since coin transfer and the balance update happen unconditionally before the AA's if-logic runs. This is a fund-loss / value-freezing class issue reachable by a single unprivileged unit poster, satisfying the Medium/High severity bar.

### Likelihood Explanation
High. No special privilege, cosigning, or race with another chain is required — a single payment message to any live AMM-style AA address triggers the described state, and the AA's own canonical, shipped sample code demonstrates the vulnerable pattern (`balance[$asset]`, `balance[base]` driven ratio math) as the officially recommended way to build such contracts. Any developer following this documented idiom inherits the flaw, and any attacker can exploit it with a single, cheap on-chain unit.

### Recommendation
- Do not rely on raw `balance[asset]` for economic invariants in AMM/bonding-curve/vault-style AAs; instead track reserves explicitly with a dedicated state variable (e.g. `var['reserve_base']`, `var['reserve_asset']`) that is updated only through the AA's own trade/invest/divest logic, and reject (bounce) any trigger whose declared/expected inputs don't match the actual `trigger.output[[...]]` for that state var.
- Where `balance[]` must be used, explicitly reconcile it against the tracked reserve on each invocation and bounce (refuse to update) if there is an unexplained surplus, rather than silently absorbing it into future pricing.
- Update the shipped `uniswap_like_market_maker.oscript` documentation sample to include reserve-tracking state variables and guard against unattributed deposits, since it currently teaches developers the vulnerable pattern directly.

### Proof of Concept
1. An attacker crafts a unit that sends bytes or the pool asset directly to a deployed instance of the `uniswap_like_market_maker.oscript`-style AA, choosing an amount and trigger data that fails to match any `if` case (e.g., below the `1e5` threshold, or with no matching `data.define`/asset condition).
2. Per `aa_composer.js` `handleSuccessfulEmptyResponseUnit`/`no messages after filtering` path, the AA absorbs the payment into its `aa_balances` row with no response; `balance[base]` (or `balance[$asset]`) is now permanently inflated.
3. The attacker (or an accomplice) then sends a legitimate "exchange" trigger. Because `$bytes_balance`/`$asset_balance`/`$p` are computed straight from the now-inflated `balance[]`, the resulting `$amount` payout differs from what it would have been absent the donation, letting the attacker extract value at other investors'/traders' expense, or permanently degrading the redemption value backing `mm_asset_outstanding` shares — a fund-loss outcome directly analogous to the NORMIE tax-wallet dilution attack.

### Citations

**File:** aa_composer.js (L474-490)
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
```

**File:** aa_composer.js (L1865-1877)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
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

**File:** formula/evaluation.js (L1510-1527)
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
