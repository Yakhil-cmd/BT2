Confirmed: this is a documented, shipped reference AA template (`test/samples/uniswap_like_market_maker.oscript`), described in the wiki's "AA Example Templates" page as a reference implementation for developers building AMMs/DEXs on Obyte. This is the closest reachable analog to the reported bug class.

### Title
Permissionless initial-deposit branch lets first liquidity provider set an arbitrary constant-product price, enabling cheap draining of AA funds - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The bundled/reference AMM-style Autonomous Agent (AA) template that ships with `ocore` as example code for developers (documented on the "AA Example Templates" wiki page) lets any unprivileged trigger sender become the first liquidity provider and unilaterally fix the `$asset`/base exchange rate, with no minimum-liquidity or price sanity checks. This mirrors the reported DEX bug class where a permissionless "create pool" action lets an attacker fix an absurd initial price and then exploit the constant-product formula used by later swaps to drain the pool cheaply.

### Finding Description
The AA's "invest in MM" case computes reserves before the trigger's own deposit and detects an "initial deposit" whenever either side of the pool is currently empty: [1](#0-0) 

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

On this path there is no check that the deposited `$asset` amount and base-byte amount reflect any real market price — the only requirements are `trigger.output[[asset=base]] > 1e5` (a fixed dust threshold, ~100,000 bytes) and `trigger.output[[asset=$asset]] > 0` (any nonzero amount, e.g. 1 unit). Any address can call this case as the very first "investor" and set the pool reserves to an arbitrarily skewed ratio, e.g. depositing 100,001 bytes and only 1 unit of `$asset`, receiving `mm_asset` shares equal to the base amount.

Once this lopsided reserve is set, all subsequent constant-product swaps in the "exchange bytes to asset" and "exchange asset to bytes" cases use `$p = $asset_balance * $bytes_balance` computed directly from these attacker-controlled reserves: [2](#0-1) 

Because one side of the pool was deliberately set extremely small relative to the other, the constant-product math produces extreme price impact for the first few swaps, letting the same attacker (or a colluding second account) immediately swap a small additional amount to extract nearly all of the base-byte or asset-side liquidity the AA holds, and to walk away with almost all outstanding `mm_asset` shares' underlying value while diluting or freezing later depositors' funds. This is the same root cause as the reported issue: a permissionless pool-creation/first-deposit step with no minimum liquidity or cooldown, whose price is fully controlled by whoever deposits first.

### Impact Explanation
Any unprivileged AA trigger sender who wins the race to be the first liquidity depositor can:
- Fix the pool's exchange rate to an arbitrary, illiquid ratio.
- Immediately or shortly after extract almost all of the AA's byte or asset balance via the swap cases, at the expense of the AA's funds and of any later depositors who join at the manipulated price.
- Leave the pool effectively drained/frozen for legitimate use, since there is no mechanism to reset or restrict deployment once created.

This is a fund-loss/fund-freezing issue for any AA deployed from this template, consistent with a High severity finding.

### Likelihood Explanation
The template is shipped as official example/reference code in the `ocore` repository and documented on the wiki as a pattern developers can copy to build AMMs (`test/samples/uniswap_like_market_maker.oscript`). Exploitation requires no special privilege — merely being first to call the "invest" case with a skewed base/asset ratio, which is trivial to front-run since AA definition and first deposit both originate from ordinary, permissionless triggers.

### Recommendation
- Require a minimum absolute liquidity for both sides of the pool on the initial deposit (not just `> 1e5` bytes and `> 0` asset units), so the initial price cannot be set with dust amounts.
- Consider requiring the AA's definer/deployer (rather than an arbitrary first caller) to seed initial liquidity, or enforce a fixed/oracle-derived initial price rather than deriving it purely from whatever the first depositor sends.
- Add a cooldown period after pool creation before swaps are allowed, giving time to detect and react to abnormal initial ratios.

### Proof of Concept
1. Deploy an AA from the `uniswap_like_market_maker.oscript` template.
2. Attacker sends `trigger.data.define` to create `$mm_asset`.
3. Attacker immediately sends a trigger with `trigger.output[[asset=base]] = 100001` and `trigger.output[[asset=$asset]] = 1`, hitting the "invest in MM" case's initial-deposit branch and receiving `mm_asset` shares equal to `100001`, while the pool reserves are now skewed (`asset_balance = 1`, `bytes_balance ≈ 100001`).
4. Attacker (or a colluding address) calls the "exchange asset to bytes" case, sending a small extra amount of `$asset`; because `$p = asset_balance * bytes_balance` was fixed with a near-zero `asset_balance`, the resulting `$new_bytes_balance` computation lets the attacker withdraw nearly all of the AA's byte balance for a negligible additional asset deposit. [3](#0-2)

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

**File:** test/samples/uniswap_like_market_maker.oscript (L102-145)
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
```
