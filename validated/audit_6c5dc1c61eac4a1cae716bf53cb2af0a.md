## Finding

### Title
Uniswap-style market-maker AA template allows first-depositor share-price manipulation via unvalidated initial mint — Business Logic Flaw ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The reported sDAO exploit worked because the staking-reward pool (`totalStakeReward`) could be inflated through a path (a raw `transferFrom`/fee-on-transfer) that was never reconciled against the tracked share/paid-out accounting variable (`lastTotalStakeReward`), letting the attacker mint disproportionate rewards relative to the pool's real backing. The ocore repository ships an analogous AA reference template, the "Uniswap-like market maker" AA in [1](#0-0) , whose LP-share accounting (`var['mm_asset_outstanding']`) can likewise be decoupled from the real value backing the pool because the *first* deposit skips the ratio/ownership validation that every subsequent deposit is subject to.

### Finding Description
Every subsequent "invest in MM" trigger is required to deposit assets in the exact current pool ratio, or it is bounced: [2](#0-1) 

But the very first deposit, gated only by `$asset_balance == 0 OR $bytes_balance == 0`, is treated specially:
```
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
``` [3](#0-2) 

`$issue_amount` (the number of `mm_asset` LP shares minted, and the sole determinant of `var['mm_asset_outstanding']`) is set purely from `balance[base]`, completely ignoring how much of `$asset` the same trigger deposited (`trigger.output[[asset=$asset]] > 0` is only checked as a non-zero condition to enter the case, at line 34). Because `balance[$asset]` and `balance[base]` used later for divestment reflect the AA's actual, unvalidated pool composition: [4](#0-3) 

an unprivileged trigger sender who is first to invest can set the asset:base ratio of the pool to any value they like (e.g., deposit a token-side amount vastly disproportionate to the tiny bytes-side amount required to pass the `> 1e5` gate), while the code never checks or bounds this ratio the way it does for every later deposit. This mirrors the sDAO root cause precisely: the reward/share ledger (`mm_asset_outstanding`, analogous to `lastTotalStakeReward`) is updated from only one side of a two-asset deposit, while the pool's real balance (`balance[base]`, `balance[$asset]`, analogous to the fee-inflated `totalStakeReward`) is allowed to diverge arbitrarily from what the share ledger represents — with no reconciliation check at the point the divergence is created.

The evaluation of `balance[...]` used throughout is a plain snapshot read backed by `aa_balances`, computed for the AA address in [5](#0-4)  and populated per-trigger in `updateInitialAABalances`/`updateFinalAABalances` in [6](#0-5) ; nothing at the formula-evaluation or composer layer enforces that `mm_asset_outstanding` and pool `balance[]` stay proportionally consistent — that invariant is left entirely to the AA author's oscript logic, and this reference template fails to enforce it at the critical bootstrap moment.

### Impact Explanation
An unprivileged AA trigger sender who becomes the first investor can set an arbitrary, self-serving asset:base exchange ratio for the pool at essentially no cost (paying only just above the `1e5` byte threshold while depositing a lopsided amount of the paired asset). Because every subsequent depositor's contribution is validated against this attacker-chosen ratio (`bounce('wrong ratio of amounts...')`), legitimate future depositors are forced either to accept the manipulated price or have their triggers bounced — a fund-freezing/denial-of-participation condition — and any depositor who does not notice the skewed ratio before depositing sends funds priced far from fair value, which are absorbed into a pool whose LP-share ledger does not reflect proportional true value. This is the same class of loss as sDAO's exploit: a reward/share accounting variable that can be set independently of the real value it is supposed to represent, enabling fund loss/misallocation for anyone interacting with the pool after the manipulation.

### Likelihood Explanation
This requires only a single unprivileged unit/trigger sent to the AA address — no special privileges, no other AA, and no reliance on network timing — and it works exactly once per pool (the first deposit), which any attacker can guarantee by being first (e.g., immediately after AA definition/`define` message). This is directly reachable by "an unprivileged unit poster / AA trigger sender," matching the allowed threat model.

### Recommendation
Require the first "invest in MM" deposit to also validate or fix a fair initial ratio (e.g., require the depositor to explicitly set the price via a separate `define`-time parameter, or require minimal-amount seeding by the AA's own definer, or mint shares as `min(round(balance[base]), round(balance[$asset]))`-scaled to prevent unilateral ratio-setting) so that `var['mm_asset_outstanding']` is always kept proportional to both sides of the pool balance from inception, closing the same "unaccounted balance vs. tracked share ledger divergence" gap that enabled the sDAO exploit.

### Proof of Concept
1. AA is defined and `define` message is sent to create `mm_asset` (see `test/samples/uniswap_like_market_maker.oscript` case "define share asset").
2. Attacker immediately sends a single trigger with `trigger.output[[asset=base]] = 100001` and `trigger.output[[asset=$asset]] = 1_000_000` (or any lopsided amount) — this satisfies the "invest in MM" `if` condition on line 34 and hits the `initial deposit` branch on lines 38-41, which mints `mm_asset_outstanding = 100001` shares to the attacker while absorbing the full 1,000,000 units of `$asset` into the pool without any check that this composition is fair.
3. Any later depositor must match the resulting skewed ratio (`current_ratio ≈ 9.9999`) or is bounced (line 44-45); a depositor unaware of this ratio either loses value by matching an unfair price or is denied service via bounce.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L1-5)
```text
{
	init: `{
		$asset = 'n9y3VomFeWFeZZ2PcSEcmyBb/bI7kzZduBJigNetnkY=';
		$mm_asset = var['mm_asset'];
	}`,
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

**File:** aa_composer.js (L474-541)
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
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
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
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
	}
```
