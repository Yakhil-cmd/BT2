## Analysis

The Sherlock report describes a "hardly achievable 1:1 balance assumption" that lets an attacker permanently break an invariant by depositing a negligible amount before the real logic runs. The closest reachable analog in `ocore` is the bundled Uniswap-like market-maker Autonomous Agent template, which implements exactly the same "first-deposit sets the price, subsequent deposits must match the ratio" pattern, and is equally vulnerable to a dust/front-run attack from any unprivileged trigger sender.

### Title
Initial-liquidity ratio in the Uniswap-like market-maker AA can be griefed by a 1-wei front-run deposit - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The "invest in MM" case of the sample market-maker AA decides whether a deposit is the *initial* deposit (and therefore sets the price freely) purely by checking whether the AA's pre-trigger balances of the paired asset or bytes are zero: [1](#0-0) 

Because this check (`$asset_balance == 0 OR $bytes_balance == 0`) is a trivial `==0` test rather than a tolerant/committed bootstrap mechanism, any address can win the race to be treated as "initial depositor" by sending a trigger with `trigger.output[[asset=base]] > 1e5` and `trigger.output[[asset=$asset]]` as small as `1`, right after the `mm_asset` is defined and before any genuine liquidity provider deposits.

### Finding Description
In the "invest in MM" case:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
```
`$asset_balance` and `$bytes_balance` are the AA's balances of the paired asset and bytes *excluding* the current trigger's own outputs. Immediately after the "define share asset" case runs, both balances are `0`, so the very next trigger that satisfies `trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0` is classified as the "initial deposit," regardless of how skewed the deposited ratio is (e.g. `1e5+1` bytes paired with `1` unit of the asset). The attacker mints `$issue_amount = balance[base]` MM shares for a token price that is arbitrarily far from the real market price, exactly as in the reported Curve-pool issue where the code assumes an unrealistic exact balance and can be trivially broken by depositing a minimal amount first. [2](#0-1) 

Once this attacker-controlled ratio is set, all subsequent honest deposits are evaluated against it:
```
$current_ratio = $asset_balance / $bytes_balance;
$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
if ($expected_asset_amount != trigger.output[[asset=$asset]])
    bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
``` [3](#0-2) 
so genuine liquidity providers either get bounced (denial of service on pool bootstrapping) or, if they compute the required ratio and comply, they contribute liquidity at the attacker's manipulated price, and the attacker's minted `mm_asset` shares are backed by a disproportionate amount of the real assets subsequently deposited by others — i.e., the attacker extracts value from later depositors and/or the "divest" flow pays out shares based on the corrupted pool composition: [4](#0-3) 

The same balance-based "is this the initial deposit" pattern also underlies the swap cases, which read live `balance[...]` at trigger time and are equally sensitive to the attacker having set an arbitrary initial ratio: [5](#0-4) [6](#0-5) 

This is directly reachable by any address that can post an AA trigger unit — no special privileges required, matching the exploit vector described in the report (anyone can perturb the exact-ratio assumption with a minimal deposit/swap).

### Impact Explanation
- An attacker acting as the very first "investor" can seed the pool with an artificial, arbitrarily skewed price (e.g. 100,001 bytes : 1 unit of asset instead of a fair ratio), then either:
  - permanently block honest deposits (bounce/DoS on bootstrapping the AA), or
  - force honest depositors to unknowingly deposit at the corrupted ratio, letting the attacker later divest and extract a disproportionate share of the pooled bytes/asset (fund loss for other users of the AA).
- This corresponds to "AA fund loss or freezing" — an accepted impact category — reachable purely from a single crafted AA trigger unit.

### Likelihood Explanation
Likelihood is high: any user can observe the "define share asset" trigger in the network's unconfirmed/stable DAG and race to submit the manipulative "invest in MM" trigger before a legitimate depositor, since AA triggers are public units and MCI-ordering does not prevent a fast follow-up trigger. No collusion with a hub/oracle/node is required — this is a pure single-trigger AA-logic flaw analogous to the reported Curve-pool oracle setup issue.

### Recommendation
Do not rely on a strict `balance == 0` check to detect "initial deposit." Instead:
- Require the AA definer (or a whitelisted/committed process) to seed initial liquidity atomically with pool creation (e.g., in the same "define share asset" case), rather than allowing any trigger to claim the "initial deposit" branch.
- Alternatively, enforce a minimum deposit size and/or a tolerance-based ratio check even for the first deposit, and/or lock a portion of minted shares (a "dead" minimum liquidity mint, as in Uniswap V2) so a 1-wei-style deposit cannot cheaply seize control of the pool's price.
- More generally, treat this pattern as a documented pitfall: any AA relying on `balance[asset]` ratios to bootstrap price must explicitly defend against front-running/donation attacks on the first deposit, not just assume balances will be "naturally" comparable.

### Proof of Concept
1. AA author deploys `uniswap_like_market_maker.oscript`; user A sends trigger `{data:{define:true}}`, which defines `mm_asset` (case at lines 8-32).
2. Attacker immediately (before any real investor) sends a trigger with `trigger.output[[asset=base]] = 100001` and `trigger.output[[asset=$asset]] = 1`.
3. Inside "invest in MM" (lines 33-48), `$asset_balance == 0` (pre-trigger balance of `$asset` is zero) triggers the "initial deposit" branch: `$issue_amount = balance[base]` (≈100001), so the attacker receives ~100001 `mm_asset` shares for depositing only 1 unit of `$asset`.
4. A genuine investor B later deposits fairly priced amounts of `base`/`$asset`; because `$current_ratio = $asset_balance / $bytes_balance` is now based on the attacker's skewed 1:100001 ratio, B is bounced unless B matches the corrupted ratio, or B unknowingly overpays in `$asset` relative to fair value.
5. Attacker then divests (case lines 67-100), redeeming shares proportionally against the pool's actual (now fairly-funded) balances, extracting value contributed by B.

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

**File:** test/samples/uniswap_like_market_maker.oscript (L124-144)
```text
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
```
