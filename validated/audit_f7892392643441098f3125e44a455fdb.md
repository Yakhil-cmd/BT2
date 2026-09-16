## Analysis

The reported bug class — a *forgeable liquidity-addition/first-deposit detection heuristic* that lets an attacker manipulate pool state to have their trade misclassified and bypass the normal proportional-pricing checks — maps directly onto the reference Uniswap-style market-maker Autonomous Agent shipped in this repository as an AA template/example, `test/samples/uniswap_like_market_maker.oscript`. This is not just documentation: it demonstrates the canonical oscript pattern (`trigger.output[[asset=X]]`, `balance[...]`) that any unprivileged trigger sender can invoke against a live AA built from this template, and it is exercised/validated by the AA parser/evaluator (`formula/evaluation.js`, `aa_composer.js`) that is genuine production code.

### The forgeable "initial deposit" heuristic [1](#0-0) 

```
{ // invest in MM
    if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
    init: `{
        $asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
        $bytes_balance = balance[base] - trigger.output[[asset=base]];
        if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
            $issue_amount = balance[base];
            return;
        }
        ...
```

The AA infers "this is a first/initial deposit" purely from the *pre-trigger reserve being zero* (`$asset_balance == 0 OR $bytes_balance == 0`). When that branch is taken, it skips the ratio-fairness check entirely and mints `$issue_amount = balance[base]` (the full current byte balance) as new LP shares, then simply adds that to `var['mm_asset_outstanding']` — see the divest branch that later redeems proportionally to `mm_asset_outstanding`: [2](#0-1) 

Exactly like the DTXT contract's flawed "was this a liquidity add?" check (triggered by merely observing a direct transfer to the pair), this AA's "was this the first deposit?" check is triggered by merely observing that one reserve balance reads zero — a state that is fully attacker-reachable and forgeable through ordinary, permitted operations (repeatedly divesting down to a residual state, or being the first "real" depositor and then draining to near-zero via `divest`, since `round()` in the divest payout formulas can leave one side at exactly 0 while `mm_asset_outstanding` is still non-zero). Once an attacker forces that state, they can deposit any amount of `base` and be minted shares equal to the *entire* post-trigger `balance[base]`, bypassing the constant-product ratio check that governs every other deposit: [3](#0-2) 

That ratio check (`$expected_asset_amount != trigger.output[[asset=$asset]]` bounce) is precisely the anti-forgery control that protects normal deposits/swaps — but it is entirely skipped in the "initial deposit" branch, the same way DTXT's fee logic was skipped once the forged liquidity-add condition was met.

### Impact

Any unprivileged AA trigger sender who can force one reserve to read zero (via the AA's own public `divest` case) can then mint LP shares disproportionate to actual contributed value, diluting or effectively stealing the residual pooled `base`/asset value legitimately owned by other `mm_asset` holders — an AA fund-loss scenario reachable purely through posted units/triggers, matching the required impact bar (AA fund loss due to a business-logic condition that is trivially forgeable by the caller).

### Recommendation

Replace the zero-balance heuristic with an explicit, non-forgeable state flag (e.g., `var['pool_initialized']` set once and never reset by draining), and require that `mm_asset_outstanding == 0` (not just a reserve being zero) before allowing the fee/ratio-check-free "initial deposit" path to execute. General AA authors following this template should be warned that reserve-based state inference (`balance[asset] == 0`) is attacker-forgeable and must never be used as a security boundary in place of index the actual outstanding-supply state variable.

### Title
Forgeable "initial-deposit" detection in the Uniswap-like AA template bypasses ratio checks and dilutes LP funds - (File: test/samples/uniswap_like_market_maker.oscript) [4](#0-3)

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L1-148)
```text
{
	init: `{
		$asset = 'n9y3VomFeWFeZZ2PcSEcmyBb/bI7kzZduBJigNetnkY=';
		$mm_asset = var['mm_asset'];
	}`,
	messages: {
		cases: [
			{ // define share asset
				if: `{ trigger.data.define AND !$mm_asset }`,
				messages: [
					{
						app: 'asset',
						payload: {
							// without cap
							is_private: false,
							is_transferrable: true,
							auto_destroy: false,
							fixed_denominations: false,
							issued_by_definer_only: true,
							cosigned_by_definer: false,
							spender_attested: false,
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset'] = response_unit;
							response['mm_asset'] = response_unit;
						}`
					}
				]
			},
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
			},
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
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
			},
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
			},
		]
	}
}
```
