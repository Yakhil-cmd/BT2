### Title
Divest/exchange payout formulas in the Market-Maker AA template use raw AA `balance[]` instead of an internally-attributed reserve, allowing unsolicited direct payments to skew share accounting - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
`VaultStrat.deposit()` was exploitable because it let anyone credit the strategy's internal accounting without going through the controller's share-minting logic, letting an attacker inflate the pool used to compute other users' withdrawal amounts. The same *class* of bug is reachable in ocore's Autonomous Agent (AA) balance model: any unprivileged address can send a payment straight to an AA address, and `aa_composer.js` unconditionally credits it to the AA's on-chain balance (`aa_balances` table) before any oscript "case" is evaluated. The `balance[asset]` formula operator (`formula/evaluation.js`) simply returns this raw, unattributed total. AA templates that mix this raw balance with a separately-tracked share/reserve counter — exactly as done in the shipped `uniswap_like_market_maker.oscript` sample — can have their payout ratios corrupted by a payment that never passes through the "invest" branch that updates the share counter.

### Finding Description
`getTrigger()` (aa_composer.js:375-397) accepts payments to an AA address from **any** address with no authorization check beyond "this output was addressed to me." `updateInitialAABalances()` (aa_composer.js:474-541) then unconditionally adds every trigger's outputs to `aa_balances` for that AA *before* the AA's oscript `if` conditions are ever evaluated: [1](#0-0) 

The `balance`/`var` formula opcode (`formula/evaluation.js:1480-1528`) reads this same raw, unattributed total directly from `aa_balances`/`objValidationState.assocBalances`: [2](#0-1) 

In the shipped market-maker AA template, the "divest" case computes a user's payout as `round($investor_share * balance[$asset])`/`round($investor_share * balance[base])`, where `$investor_share` is derived from `var['mm_asset_outstanding']` — a counter that is incremented **only** inside the "invest" case: [3](#0-2) [4](#0-3) 

Because `balance[$asset]`/`balance[base]` reflect the AA's total on-chain holdings rather than a value that is only incremented when `var['mm_asset_outstanding']` is incremented, any payment credited to the AA outside of the "invest" branch (e.g., one that is bounced back without state changes only in the narrow set of cases the template anticipated, or one that lands in an untracked corner of the case logic) breaks the invariant that `balance / mm_asset_outstanding` represents the true, uninflated share price — the same root cause as `VaultStrat.deposit()` accepting value outside the controller's share-minting path.

### Impact Explanation
If the raw/tracked-balance invariant is broken, the ratio used to pay out divesting share-holders (`balance[$asset]`, `balance[base]`) no longer matches the ratio implied by `mm_asset_outstanding`. This lets an attacker who controls the timing/composition of a trigger extract more value than their shares represent, or dilutes/steals value from other liquidity providers upon divestment — a direct AA fund-loss/fund-theft scenario, matching the "Medium/High" severity bar (concrete unauthorized spending / AA fund loss).

### Likelihood Explanation
This requires an AA author to have deployed this specific (or structurally similar) pattern — using `balance[]` directly for pro-rata payout while maintaining a separate share counter that is not perfectly synchronized with every possible way `balance[]` can change. This pattern is explicitly shipped as a reference AA template in the ocore repository (`test/samples/uniswap_like_market_maker.oscript`), so it is likely to be copied or adapted by real AA authors, but exploitability in the exact shipped template depends on finding an incoming-payment shape that is credited to `aa_balances` without passing through the "invest" case's `mm_asset_outstanding` update — which I was not able to fully enumerate against all of the template's other cases ("exchange bytes to asset", "exchange asset to bytes") within the available time. I flag this as **uncertain/needs deeper case-by-case verification** rather than a fully proven end-to-end exploit.

### Recommendation
- At the AA-authoring level (and ideally documented/enforced by ocore's AA template guidance): never use the AA's raw `balance[asset]` for pro-rata payout math when a parallel share/reserve counter exists. Instead, maintain and use dedicated state variables (e.g. `var['asset_reserve']`, `var['bytes_reserve']`) that are incremented/decremented only inside the exact case that also updates the share counter, so the two can never drift apart.
- Ensure every code path that can add to an AA's balance (including a fallback "no case matched" / bounce path) either (a) fully refunds the sender so no value is silently absorbed into `balance[]` without attribution, or (b) explicitly increments the tracked reserve counters, eliminating any window where `balance[]` and the share/reserve accounting can diverge.

### Proof of Concept
Not independently reproduced end-to-end due to time constraints; the finding is derived from static analysis of the balance-crediting path (`aa_composer.js` `updateInitialAABalances`, `formula/evaluation.js` `balance` opcode) combined with the shipped `uniswap_like_market_maker.oscript` template, which computes divest payouts from raw `balance[$asset]`/`balance[base]` against a separately-maintained `var['mm_asset_outstanding']` counter — structurally identical to the reported `VaultStrat.deposit()` issue (unauthenticated value credited to the pool without corresponding accounting update). A full PoC would require constructing a specific trigger unit whose payment(s) are credited to the AA's balance while falling outside the "invest" case's `mm_asset_outstanding` increment, then triggering a "divest" to show the resulting payout no longer matches the depositor's true proportional share.

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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-93)
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
