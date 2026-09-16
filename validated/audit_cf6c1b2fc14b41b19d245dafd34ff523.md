This confirms that any payment sent to an AA address (whether matched by a trigger case or not) is added directly to `balance[asset]` via `updateInitialAABalances` [1](#0-0)  and `insertAADefinitions`'s balance backfill [2](#0-1) , meaning an attacker can silently "donate" bytes/asset to inflate an AMM-style AA's balance before a victim's deposit is processed — exactly the balance/price-manipulation precondition behind the Four.Meme exploit.

### Title
Front-run/donation price-manipulation drains depositors in AA constant-product market-maker pattern - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The official Obyte AA "Uniswap-like market maker" template computes share issuance and swap prices purely from the AA's current on-chain `balance[asset]`/`balance[base]`, which any unprivileged party can manipulate before a victim's trigger is processed — by (1) becoming the first depositor with a negligible amount, and (2) sending unsolicited "donation" payments directly to the AA address. Because `ocore`'s AA balance accounting adds *any* output sent to an AA address to its balance regardless of whether it matches a message case [1](#0-0) , an attacker can skew the pool ratio the same way the Four.Meme attacker skewed the PancakeSwap v3 pool price before real liquidity was added, causing the next depositor's share calculation to round to (near) zero while the attacker retains a disproportionate claim on the pool.

### Finding Description
The AA sample template implements a constant-product AMM: the "invest" case computes required asset amount from the current ratio, and issues `mm_asset` shares proportional to `trigger.output[[asset=base]] / $bytes_balance` times `var['mm_asset_outstanding']` [3](#0-2) . The very first depositor sets the initial exchange rate arbitrarily and receives shares equal to the entire byte balance with no minimum-liquidity or price-sanity check: `if ($asset_balance == 0 OR $bytes_balance == 0){ $issue_amount = balance[base]; return; }` [4](#0-3) .

Because `handleTrigger`/`updateInitialAABalances` credits an AA's `balance[asset]` for *any* payment sent to its address — not only ones matched by a case in the AA's `messages.cases` — an attacker can: (1) trigger `define` to create the share asset, (2) trigger `invest` with a minimal amount (e.g. 1 byte + 1 unit of asset) to become sole shareholder of `mm_asset` at negligible cost, then (3) send a large plain payment (donation) directly to the AA address, inflating `balance[base]` and/or `balance[asset]` without minting new `mm_asset` shares. The AA has no mechanism to reject or account separately for such unsolicited transfers, exactly as Four.Meme's liquidity-adding logic had no mechanism to detect/reject a maliciously pre-set pool price.

When a legitimate user then sends a deposit sized against the pre-manipulation exchange rate the AA expects (per the `$expected_asset_amount` bounce check [5](#0-4) ), their `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` is computed against the *now-inflated* `$bytes_balance`, so `$investor_share_of_prev_balance` is tiny and rounds their minted shares down to zero (classic ERC4626-style donation/inflation attack), while their deposited funds remain in the pool. The attacker, holding all outstanding `mm_asset`, then divests via the withdraw case and claims `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])` [6](#0-5) , capturing effectively 100% of the pool including the victim's contribution.

### Impact Explanation
Any user who deploys or interacts with this officially shipped AA pattern is exposed to fund loss for legitimate depositors and disproportionate fund extraction by an attacker, matching the "unauthorized spending / AA fund loss" impact class. Since the trigger sender role is fully unprivileged (any address may send a trigger to the AA), this is directly reachable without any special access.

### Likelihood Explanation
Likelihood is high for any deployment that reuses this template as-is: front-running the very first "real" investor deposit only requires monitoring the mempool/DAG for a pending large `invest` trigger and quickly submitting a smaller `invest` trigger plus a bare donation payment before the victim's unit is processed — a standard MEV-style attack pattern, requiring no special privileges, keys, or node access, only an ordinary posted payment/trigger.

### Recommendation
The AMM template (and any derived production AA) should: (1) require a minimum initial liquidity that is burned/locked (as OpenZeppelin's ERC4626 fix does) rather than allowing the first depositor to claim 100% of `balance[base]` as shares; (2) track pool reserves in AA state variables (`var['bytes_reserve']`, `var['asset_reserve']`) instead of trusting live `balance[...]`, so unsolicited donations cannot be used to manipulate the price used for share/swap calculations; and (3) reconcile/reject unexpected balance deltas that don't correspond to a recognized trigger case before performing ratio-based math.

### Proof of Concept
1. Attacker sends trigger `{data:{define:true}}` to create `mm_asset` (case in [7](#0-6) ).
2. Attacker sends trigger with `trigger.output[[asset=base]] = 100001` and `trigger.output[[asset=$asset]] = 1` to become the first "investor" — since `$asset_balance==0`, `$issue_amount = balance[base]` (~100001), giving the attacker all of `var['mm_asset_outstanding']`.
3. Attacker sends a plain (non-matching-case) payment of e.g. 100,000,000 bytes directly to the AA address; this is added to `balance[base]` via `updateInitialAABalances` [1](#0-0)  without minting shares.
4. Victim, computing the expected ratio from the AA's advertised current state, sends a large legitimate `invest` trigger; `$investor_share_of_prev_balance = trigger.output[base] / $bytes_balance` is now minuscule relative to the inflated `$bytes_balance`, so `$issue_amount` rounds to 0 — victim receives no `mm_asset` shares despite depositing real funds.
5. Attacker sends a `divest` trigger burning their `mm_asset` shares and receives `round($investor_share * balance[asset])` and `round($investor_share * balance[base])`, i.e. essentially the entire pool including the victim's deposit [6](#0-5) .

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

**File:** storage.js (L954-962)
```javascript
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

**File:** test/samples/uniswap_like_market_maker.oscript (L8-32)
```text
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
```

**File:** test/samples/uniswap_like_market_maker.oscript (L33-66)
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
			},
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
