### Title
Donation-style exchange-rate/share inflation in oscript AAs that price shares from raw `balance[asset]` instead of an independent supply accumulator - ([File: aa_composer.js], [File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The Venus report describes an attacker inflating a pool's internal exchange rate by directly transferring (donating) the underlying asset to the vault contract, bypassing the normal mint path, so the accounted "supply/shares" variable and the raw custodial balance become decoupled, and later redemptions are computed off the inflated raw balance. Ocore's AA engine exposes the exact analogous primitive: `balance[asset]` in oscript reflects the AA's raw on-chain custody balance, tracked in the `aa_balances` table, and is credited unconditionally for **any** payment received by the AA address — independent of whether the AA's case logic recognizes, validates, or proportionally mints against that payment. This is documented and demonstrated by ocore's own shipped example AA scripts.

### Finding Description
Any payment sent to an AA address is folded into the AA's tracked balance before the AA's `messages`/`cases` logic is even evaluated. In `aa_composer.js`, `updateInitialAABalances` unconditionally adds every asset amount in `trigger.outputs` to `aa_balances`/`objValidationState.assocBalances[address]`: [1](#0-0) [2](#0-1) 

This happens regardless of which (if any) `case` in the AA definition later matches the trigger, and regardless of whether the AA's own oscript increments an independent "shares outstanding"/"total accounted" state variable. The formula evaluator's `balance[...]` operator simply reads this raw, unconditionally-credited value: [3](#0-2) 

Ocore's own example AA, `uniswap_like_market_maker.oscript` (validated/tested via `test/ojson.test.js`), is a textbook illustration of the vulnerable pattern: it mints/burns a share asset (`mm_asset`) using an internally tracked `var['mm_asset_outstanding']`, but computes redemption amounts and initial-mint sizing directly from the AA's *raw* `balance[base]` / `balance[$asset]`, not from any invariant that ties the raw balance strictly to `mm_asset_outstanding`: [4](#0-3) [5](#0-4) 

Because `balance[$asset]`/`balance[base]` are credited from any output sent to the AA address (via the mechanism above) whether or not that payment goes through the "invest" case that also bumps `mm_asset_outstanding`, a payment that is accepted by any *other* branch (or simply not bounced) increases the redemption-relevant `balance[...]` without a matching increase in `mm_asset_outstanding` — silently increasing `round($investor_share * balance[$asset])` for every existing/future divesting shareholder. This is the same root-cause shape as Venus's `vTHE` exchange-rate inflation: a supply/shares counter that is not cryptographically or arithmetically bound to the raw balance used to price shares, permitting a "donation" (any accepted payment that isn't routed through the exact mint path) to inflate the redemption rate.

Other shipped ocore examples reinforce that "catch-all accept coins" branches which augment tracked balances/state without symmetric supply accounting are a recurring, sanctioned pattern in oscript (e.g., `a_bank_without_percent.oscript`'s "silently accept coins" case, `sell_asset_for_bytes.oscript`), confirming this is a systemic hazard of the `balance[...]` primitive rather than a one-off scripting mistake. [6](#0-5) 

### Impact Explanation
Any AA (bank/vault/AMM/lending-style contract) that computes per-share or exchange-rate values from `balance[asset]`/`balance[base]` rather than from a self-consistent, mint-path-only accounting variable is exposed to donation-style value extraction: an attacker can inflate the redemption price for share holders (benefiting existing large holders, including the attacker after cheaply acquiring shares) or cause later depositors to receive fewer shares than expected for the same deposit, i.e. fund loss/misallocation for AA participants — the same "supply inflation via donation" impact category as the Venus incident, scoped to any AA reachable by an ordinary trigger sender since it requires no special privileges, only ordinary payment messages sent to the AA address.

### Likelihood Explanation
High for any AA design that (a) exposes redeemable value proportional to `balance[asset]`, and (b) does not gate every possible accepted payment path behind the exact same accounting update as the mint path. Since `aa_balances` crediting is unconditional and occurs in core protocol code (`aa_composer.js`) before case-matching, this is not a corner-case bug but the default behavior of the primitive; the security burden falls entirely on AA authors to reconcile `balance[...]` with their own supply accounting on every branch, which the ocore-shipped `uniswap_like_market_maker.oscript` example itself does not enforce for all incoming payment shapes.

### Recommendation
- For oscript AA authors (and for documentation/examples ocore ships, since they set the template many third-party AAs copy): never price shares/exchange rates directly from `balance[asset]`; instead maintain and use an independent, mint/burn-only state variable for "total accounted balance," and reconcile any unexpected excess (`balance[asset] - accounted_total`) explicitly (e.g., route it to a sweep/donation-handling branch that does not affect redemption price), or bounce any payment that does not exactly match a whitelisted case.
- Update ocore's shipped example AAs (`uniswap_like_market_maker.oscript`, `a_bank_without_percent.oscript`, `sell_asset_for_bytes.oscript`) to demonstrate the safe pattern (bounce-by-default plus an explicit accounted-balance variable), since these are used as reference implementations.
- Consider exposing, alongside `balance[asset]`, an oscript-level convenience for "balance excluding this trigger's own donation-only payments" already partly present (`balance[asset] - trigger.output[[asset=...]]`) but make the safe pattern more discoverable/documented so AA authors do not conflate raw custody balance with accounted supply.

### Proof of Concept
1. Deploy an AA modeled on `uniswap_like_market_maker.oscript`, defining `mm_asset` and performing the first "invest" deposit to establish `mm_asset_outstanding = N` and `balance[base] = B`, `balance[asset] = A`.
2. As a third party (no special privilege required), send the AA a payment that is accepted by the AA's logic (any branch that does not bounce) which increases `balance[base]` or `balance[asset]` without incrementing `mm_asset_outstanding` — e.g., a payment shaped to match a swap/accept branch that legitimately grows the pool via fees, or, for a more naive AA copy (e.g. based on `a_bank_without_percent.oscript`'s "silently accept coins" branch), simply send extra funds that the branch does not attribute to any specific depositor's shares.
3. Call "divest" as an existing mm_asset holder: the AA computes `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])` using the now-inflated raw balances while `mm_asset_outstanding` is unchanged, so the holder (or attacker, if attacker is also a holder) redeems more value than their `mm_asset_outstanding`-proportional share should entitle them to, at the expense of remaining shareholders — mirroring the Venus `vTHE` exchange-rate inflation via donation.

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

**File:** aa_composer.js (L502-514)
```javascript
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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-83)
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
```

**File:** test/samples/a_bank_without_percent.oscript (L31-52)
```text
			{ // silently accept coins
				if: "{!trigger.data.withdraw}",
				messages: [{
					app: 'state',
					state: `{
						$asset = trigger.output[[asset!=base]].asset;
						if ($asset == 'ambiguous')
							bounce('ambiguous asset');
						if (trigger.output[[asset=base]] > 10000){
							$base_key = 'balance_'||trigger.address||'_'||'base';
							var[$base_key] = var[$base_key] + trigger.output[[asset=base]];
							$response_base = trigger.output[[asset=base]] || ' bytes\n';
						}
						if ($asset != 'none'){
							$asset_key = 'balance_'||trigger.address||'_'||$asset;
							var[$asset_key] = var[$asset_key] + trigger.output[[asset=$asset]];
							$response_asset = trigger.output[[asset=$asset]] || ' of ' || $asset || '\n';
						}
						response['message'] = 'accepted coins:\n' || ($response_base otherwise '') || ($response_asset otherwise '');
					}`
				}]
			},
```
