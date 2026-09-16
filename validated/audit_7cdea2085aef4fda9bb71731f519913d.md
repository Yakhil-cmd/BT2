## Analog Found

### Title
AA share-pool contracts using `balance[asset]` can be permanently front-run/donation-attacked because AA addresses are predictable before deployment and pre-funded outputs are folded into `aa_balances` on activation - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The Sherlock report describes a DOS/fund-loss pattern where an attacker predicts a not-yet-deployed contract's address (CREATE2-style) and donates tokens to it before deployment, corrupting an invariant the contract relies on ("exactly one balance/position") the moment it becomes active. Obyte's Autonomous Agents (AA) have the same address-predictability property — an AA's address is `chash160(definition)`, computable by anyone before the AA is ever posted — and the framework explicitly folds any pre-existing outputs sent to that address into the AA's on-chain `aa_balances` once it activates. Pool/market-maker style AAs that trust the raw `balance[asset]` primitive (rather than an explicitly tracked state variable) to decide whether a deposit is the "first/initial" deposit are vulnerable to the same donation-based corruption, enabling a classic share-price inflation attack against real depositors.

### Finding Description
An AA's address is deterministic: it equals `objectHash.getChash160(definition)`, and this can — and is routinely — computed before the AA is posted/activated, exactly as demonstrated in tests such as `test/aa_composer.test.js` ("AA with generated definition of new AA and immediately sending to this new AA"), where `child_aa_address` is derived and paid before the defining unit is even sent: [1](#0-0) [2](#0-1) 

Because addresses are visible on the DAG the moment any output targets them, an attacker can send bytes/assets to a predicted AA address long before its `definition` message is ever broadcast — this is normal ocore behavior, units simply record outputs to any address. When the AA is finally defined and activated, `storage.insertAADefinitions()` explicitly sums up all pre-existing outputs sent to that address and inserts them into `aa_balances`, i.e., "donations" made before deployment become part of the AA's live balance: [3](#0-2) 

The oscript `balance[asset]` operator reads exactly this accumulated real balance (from `aa_balances`, merged with any pending trigger outputs), not a separately tracked ledger: [4](#0-3) 

The bundled sample AA `test/samples/uniswap_like_market_maker.oscript` — a Uniswap-style liquidity pool — uses precisely this raw `balance[]` value to detect whether a deposit is the very first one, and if so mints LP shares 1:1 with the deposited base amount: [5](#0-4) 

If an attacker predicts the pool's address before it is deployed and donates a trivial non-zero amount of the pool's asset directly to that address, then `$asset_balance` will never equal `0` once the AA activates. The legitimate first depositor's "initial deposit" branch (`$issue_amount = balance[base]`, an honest 1:1 mint) is permanently bypassed; instead every deposit goes through the ratio branch:
```
$current_ratio = $asset_balance / $bytes_balance;
...
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```
Since `var['mm_asset_outstanding']` still equals `0` at this point (never actually initialized because the "initial deposit" code path — which is the only place that sets it — was skipped), the pool's economics are corrupted from the very first real deposit: the honest depositor's shares/asset accounting no longer matches the funds they placed, either bricking further legitimate deposits (division/ratio checks bounce) or allowing the attacker, who controls the tiny pre-existing asset balance, to later drain a disproportionate share of the pool's bytes/asset relative to their negligible donation.

### Impact Explanation
This produces "AA fund loss" for depositors: legitimate users' funds sent to a pool AA can be captured or misallocated based on the attacker's front-run donation, analogous to well-known ERC4626 vault "first depositor / inflation" attacks in Solidity, and to the exact wfCash issue cited (an unpriced/duplicated balance check that a griefer/attacker can poison before the victim contract goes live). Because AA addresses are deterministic and visible pre-activation, and ocore intentionally folds pre-activation outputs into `aa_balances`, this attack requires no special network position — any user who can compute or observe the intended AA definition can execute it with a dust-level transfer.

### Likelihood Explanation
Likelihood is Medium: it requires (1) the ability to predict the target AA's address before it activates (straightforward, since the definition is either publicly known — e.g. templates/base AAs, factory-created child AAs as shown in tests — or guessable/observable in the mempool before stabilization), and (2) the AA's own oscript logic relying on raw `balance[asset]` to gate a one-time "initialize the pool" branch instead of an explicit state variable flag. This is a common but avoidable oscript authoring mistake; the bundled example AA in `test/samples/uniswap_like_market_maker.oscript` demonstrates the exact anti-pattern.

### Recommendation
- Document clearly (and update the bundled sample AAs) that AA authors must never use raw `balance[asset]`/`balance[base]` to detect "is this the first deposit" or otherwise gate irreversible pool-initialization logic, since balances can be pre-seeded by donations before or between AA definition and stabilization.
- Recommend using an explicit state variable (e.g., `var['initialized']` or `var['mm_asset_outstanding'] > 0`) as the sole source of truth for whether the pool has been initialized, independent of actual on-chain balance.
- Consider having `insertAADefinitions()`/documentation surface a warning or a distinguishable "pre-funded" balance component so AA authors can detect and reject/quarantine donations received prior to activation.

### Proof of Concept
1. Attacker computes `pool_address = chash160(market_maker_definition)` for a not-yet-posted AA definition (as demonstrated feasible in `test/aa_composer.test.js:942` where `child_aa_address` is derived and funded before the AA exists).
2. Attacker sends `1` unit of the pool's designated asset to `pool_address` before the AA's `definition` unit stabilizes.
3. Once the AA activates, `storage.insertAADefinitions()` sums this pre-existing output into `aa_balances` for `pool_address` (`storage.js:954-962`).
4. The legitimate first liquidity provider sends bytes+asset to `pool_address`. Inside `uniswap_like_market_maker.oscript`, `balance[$asset] - trigger.output[[asset=$asset]]` is now `1`, not `0`, so the `"initial deposit"` branch (`uniswap_like_market_maker.oscript:38-41`) is skipped, and the ratio-based logic — driven by `var['mm_asset_outstanding']` which is still `0` — computes an incorrect/zero `$issue_amount`, corrupting the pool's share accounting and allowing the attacker (holder of the only "real" pre-existing asset balance) to capture value from subsequent deposits.

### Citations

**File:** test/aa_composer.test.js (L942-943)
```javascript
	var child_aa_address = objectHash.getChash160(child_aa);
	
```

**File:** test/aa_composer.test.js (L962-976)
```javascript
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
```

**File:** storage.js (L944-962)
```javascript
					var verb = bAlreadyPostedByUnconfirmedAA ? "REPLACE" : "INSERT";
					// pre-fix, the defining AA unit's own outputs are already in the outputs table and would be double-counted with its secondary trigger
					const or_sent_by_aa = (bAlreadyPostedByUnconfirmedAA || mci >= constants.pemCurvesFixMci) ? "OR is_aa_response=1" : "";
					// for AA-defined AAs, mci is the trigger mci whose triggers were already selected before this AA existed, so outputs on this mci can never trigger it and must be counted here.
					// Also count payments from other AA responses (never primary triggers) except the defining unit's own, which arrives as a secondary trigger
					const bImmediatelyVisible = bForAAsOnly && mci >= constants.pemCurvesFixMci;
					const mci_cond = bImmediatelyVisible
						? "(main_chain_index<=? OR is_aa_response=1) AND outputs.unit!=?"
						: "(main_chain_index<? " + or_sent_by_aa + ")"; // "<" for regular AAs, not including the outputs on the current mci, which will trigger the AA and be accounted for separately; is_aa_response=1 captures outputs to the not-yet-AA by AA responses
					const params = bImmediatelyVisible ? [address, mci, unit] : [address, mci];
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
						params,
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
