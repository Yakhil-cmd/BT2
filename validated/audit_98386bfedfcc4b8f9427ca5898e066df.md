### Title
Direct balance donation lets an unprivileged sender distort AA reserve ratios/prices, causing rounding-based fund loss for depositors - (File: test/samples/uniswap_like_market_maker.oscript, aa_composer.js)

### Summary
The reported StRSR bug lets an attacker front-run contract initialization to distort a rate/ratio that subsequent depositors trust for rounding-sensitive share math. The ocore analog is present in the reference "Uniswap-like market maker" AA that ships with ocore: it computes reserve ratios and constant-product prices directly from `balance[asset]`/`balance[base]` (the AA's live on-chain balance) instead of from an internally-tracked reserve variable. Any unprivileged address can inflate that live balance simply by sending funds to the AA — a core capability implemented in `aa_composer.js`'s `updateInitialAABalances`, which unconditionally credits every trigger's outputs to the AA's balance before any case logic runs. This lets an attacker "front-run"/"donate" reserves the same way the StRSR attacker front-ran `rsrRewardsAtLastPayout`, distorting the ratio used for share issuance and causing rounding losses for legitimate depositors.

### Finding Description
In `test/samples/uniswap_like_market_maker.oscript`, the "invest in MM" case computes:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
$current_ratio = $asset_balance / $bytes_balance;
...
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
``` [1](#0-0) 

and the AMM swap cases compute a constant product directly off live balances:
```
$p = $asset_balance * $bytes_balance;
$new_asset_balance = round($p / balance[base]);
$amount = $asset_balance - $new_asset_balance;
``` [2](#0-1) 

Crucially, `balance[asset]` is the AA's actual, live token balance — not an isolated internal accounting variable analogous to Reserve's `stakeRSR`/`totalStakes`. Any address can increase that balance simply by sending an output to the AA. This is confirmed at the protocol level: `aa_composer.js`'s `updateInitialAABalances` adds every trigger's outputs to `aa_balances`/`assocBalances` for the address unconditionally, before any AA case-matching logic executes:
```
for (var asset in trigger.outputs) {
    trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
    ...
}
``` [3](#0-2) 

and outputs sent even before the AA's own `definition` unit stabilizes are folded into `aa_balances` once the AA is defined:
```
var verb = bAlreadyPostedByUnconfirmedAA ? "REPLACE" : "INSERT";
...
conn.query(
    verb + " INTO aa_balances (address, asset, balance) \n\
    SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
    FROM outputs ...
``` [4](#0-3) 

Because the reference AA's price/ratio math trusts this live, attacker-influenced balance rather than a protected internal reserve counter, an attacker (any unprivileged AA trigger sender) can:
1. Donate assets/bytes directly to the known AA address (a payment that doesn't necessarily match the "invest" case, e.g. below the `1e5` threshold, or sent before the AA is even defined/stabilized) to skew `$asset_balance`, `$bytes_balance`, and hence `$current_ratio` / `$p` in their favor, without minting or burning any `mm_asset` shares.
2. Immediately after, execute an "invest" or "exchange" trigger against the distorted ratio/price, extracting value at the expense of the next legitimate depositor, or forcing the depositor's `round()` computations to lose funds to the pool/attacker, mirroring the StRSR `stakeRate` rounding-loss mechanic (rate pushed to an extreme value → `round()` errors dominate small deposits).

This is the classic "donation attack" against naive constant-product AMMs/vaults that read live balance instead of maintaining a separate, mint/burn-gated reserve variable — the same root cause class as the StRSR report (an externally-influenceable balance feeding a rate used for proportional issuance/redemption math).

### Impact Explanation
Any depositor who invests in or swaps against an AA built on this reference pattern can have their proportional share/price rounded unfavorably (down to a much smaller amount than deposited, or up to over-pay on a swap) once an attacker has distorted `$current_ratio`/`$p` via a simple donation. Because ocore ships this exact pattern as an official example for developers to build market-maker/vault AAs on, any AA deployed from it inherits a fund-loss/fund-freezing vector reachable by any unprivileged payment sender — matching the "AA fund loss" impact class.

### Likelihood Explanation
The attack requires only the ability to send a payment output to a known AA address, something every unprivileged unit poster can already do; no privileged role, node/hub compromise, or race against block production is required (the donation can be sent as an ordinary unit at any time before the victim's trigger unit is composed/confirmed). This is directly analogous in ease to the original report's mempool front-running of the StRSR deployment.

### Recommendation
Track pool/vault reserves in dedicated internal state variables (e.g. `var['reserve_base']`, `var['reserve_asset']`) that are only updated by the AA's own mint/burn/swap logic, rather than reading `balance[asset]`/`balance[base]` directly for ratio or constant-product computations. Reject or route unmatched/donated payments so they cannot silently inflate the values used in rounding-sensitive math, and enforce minimum-liquidity/dead-shares protections on the first deposit as is standard practice for share-based vaults and AMMs.

### Proof of Concept
1. AA author deploys `uniswap_like_market_maker.oscript` for asset `$asset` and defines `$mm_asset` via the "define" case.
2. Attacker sends a small payment of `$asset` and/or `base` directly to the AA address in a way that does not match the "invest"/"exchange" case conditions (e.g., `trigger.output[[asset=base]] <= 1e5`), which is still credited to `balance[base]`/`balance[$asset]` per `aa_composer.js`'s `updateInitialAABalances` [5](#0-4) , without triggering any mint/burn of `mm_asset` or update of `var['mm_asset_outstanding']`.
3. A legitimate investor then sends a normal "invest in MM" payment. `$asset_balance`/`$bytes_balance` now include the attacker's donation, skewing `$current_ratio` and the resulting `$expected_asset_amount`/`$issue_amount` [6](#0-5) , so the investor either gets bounced ("wrong ratio of amounts") or receives fewer `mm_asset` shares than their deposit is worth.
4. Alternatively, the attacker donates directly to skew `$p = $asset_balance * $bytes_balance` and then immediately calls the "exchange" case, extracting a favorable `$amount` from the distorted constant-product price [2](#0-1) .

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

**File:** aa_composer.js (L474-489)
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
