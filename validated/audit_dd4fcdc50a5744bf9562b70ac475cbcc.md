<title>
Donation-Based Exchange-Rate Manipulation via Unaccounted `balance[]` in AA Bonding-Curve Logic - (File: formula/evaluation.js, test/samples/uniswap_like_market_maker.oscript)
</title>

### Summary
The Resupply exploit manipulated a controller's exchange rate by donating tokens directly to a contract, inflating a balance-derived rate that was then used to mint disproportionate shares/debt. Ocore's own Autonomous Agent (AA) primitive `balance[asset]` exposes exactly this class of bug: it returns the AA address's raw, cumulative on-chain balance (regardless of how the coins arrived), and AA authors are explicitly encouraged — via ocore's shipped reference AA `test/samples/uniswap_like_market_maker.oscript` — to use this manipulable value directly in bonding-curve/exchange-rate math for minting and redeeming pool shares, without separating "accounted reserves" from "unaccounted donations."

### Finding Description
Any unprivileged unit poster can send a payment to an AA address; this always triggers the AA (via `getTrigger`/`handleTrigger` in `aa_composer.js`), and the specific `case` that runs is selected purely by the `if` condition matching the payload of that unit — there is no requirement that the sender be a legitimate "investor" or that the transferred amount correspond to any expected ratio. [1](#0-0) 

Inside oscript formulas, `balance[asset]` is evaluated by `readBalance()`, which returns the AA's total balance of that asset (from `objValidationState.assocBalances` or the `aa_balances` table), i.e. the raw sum of everything ever paid to that address, with no distinction between "deposits made through the intended flow" and "bare donations." [2](#0-1) 

Ocore's own bundled sample AA, the "Uniswap-like market maker," uses this primitive directly to compute the bonding-curve exchange rate and mint/redeem shares:
- On "invest", if either side of the pool balance is zero it is treated as an "initial deposit" and issues shares equal to the entire current `balance[base]`, not just the newly-received amount: [3](#0-2) 
- On "divest", the payout is `round($investor_share * balance[$asset])` / `balance[base]`, i.e., a claim on the AA's entire current on-chain balance of each asset, proportional to the caller's share of `var['mm_asset_outstanding']`: [4](#0-3) 
- The swap cases likewise compute `$p = $asset_balance * $bytes_balance` and derive amounts from `balance[]`, so any unaccounted balance changes the bonding-curve price for every future action: [5](#0-4) 

Because `balance[]` is simply "whatever coins are currently sitting at this address" and can be inflated by any unprivileged sender making a bare payment to the AA (which will always be accepted by one of the AA's cases, e.g. "exchange asset to bytes"/"exchange bytes to asset" or the catch-all seen in other sample AAs), a party who becomes the first (or dominant) shareholder of `mm_asset_outstanding` can inflate `balance[$asset]`/`balance[base]` through a donation and then redeem their shares for a payout computed from the inflated balance, exactly mirroring the Resupply donation-based rate manipulation: the "exchange rate" (`$current_ratio`, `$p`, `$investor_share`) is derived from a spot-checkable, attacker-influenceable on-chain balance rather than from an accounting variable that only advances via legitimate flows.

### Impact Explanation
Any AA built on this documented ocore pattern (bonding-curve / share-based fund pools using `balance[]` to price shares) permits an unprivileged trigger sender to manipulate the effective share price by donating funds directly to the AA address, then extracting a disproportionate share of the AA's total holdings on divest/redeem — a concrete unauthorized fund loss for other depositors of that AA, structurally identical to the $9.5M Resupply loss caused by donation-based exchange-rate manipulation.

### Likelihood Explanation
The attack requires only two ordinary, unprivileged unit posts to the AA's address (a donation/direct payment, followed by a redeem/divest trigger) — no special privileges, no hub/peer collusion, and no protocol upgrade is needed. It is especially exploitable at pool bootstrap ("initial deposit" branch) or whenever `mm_asset_outstanding` is small relative to the attacker's holdings, both of which are realistic, unprivileged conditions reachable by any AA trigger sender.

### Recommendation
AA authors should not price shares directly from `balance[asset]`. Instead, exchange-rate/bonding-curve state should be tracked exclusively via AA state vars that are updated only through the legitimate deposit/withdraw code paths (as already done correctly in other shipped samples such as `order_book_exchange.oscript`'s `balance_*` state-var pattern), so that unaccounted direct transfers to the AA cannot influence the price used for minting or redeeming pool shares. Ocore's AA documentation/examples should be updated to warn against using `balance[]` for share-price computation without reconciling it against tracked internal reserve variables.

### Proof of Concept
1. AA `M` is deployed using the logic of `test/samples/uniswap_like_market_maker.oscript` (asset `$asset` paired with bytes, share token `mm_asset`).
2. Attacker A is the first investor: sends a trigger with `trigger.output[[asset=base]] > 1e5` and matching `trigger.output[[asset=$asset]]`. Since `$asset_balance == 0` before this trigger, the "initial deposit" branch fires: `$issue_amount = balance[base]` (post-trigger byte balance), giving A effectively 100% of `mm_asset_outstanding`. [3](#0-2) 
3. Attacker A (or a colluding address) sends a large bare payment of `$asset` (and/or bytes) to AA `M`'s address as a "donation." Because the AA is triggered on any incoming payment and the swap cases match purely on `trigger.output[[asset=...]]`, this payment is absorbed into `balance[$asset]`/`balance[base]` without minting any corresponding `mm_asset_outstanding`. [5](#0-4) 
4. Attacker A now sends a "divest" trigger with their `mm_asset` shares. Payout is computed as `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])`, where `$investor_share = $mm_asset_amount / var['mm_asset_outstanding']` ≈ 1 (A holds nearly all shares). A withdraws the donated funds plus their original deposit, extracting value disproportionate to their real net contribution. [4](#0-3) 
5. This reproduces the Resupply pattern: an unprivileged donation to the contract inflates a balance-derived exchange rate that the contract's own logic trusts, enabling extraction of funds beyond the attacker's legitimate deposit.

### Citations

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
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

**File:** test/samples/uniswap_like_market_maker.oscript (L34-48)
```text
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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-100)
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
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
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
