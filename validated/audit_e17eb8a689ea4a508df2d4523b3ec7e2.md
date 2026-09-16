### Title
AA payment outputs that round down to zero are silently dropped instead of bouncing, causing users to lose deposited funds - ([File: aa_composer.js])

### Summary
`ocore`'s Autonomous Agent (AA) response-composition logic in `aa_composer.js` silently filters out any payment output whose computed `amount` evaluates to `0`, and if this leaves a payment message with no outputs (or leaves zero messages at all), the AA sends a **successful empty response unit** instead of bouncing the trigger. This mirrors the reported Notional vault bug class: a formula that computes a proportional/share amount for a depositor can round down to zero, and instead of reverting, the protocol silently accepts the funds and returns nothing to the sender.

### Finding Description
When an AA formula computes an output `amount` for a `payment` message (e.g. minting a proportional share/token for a deposit, similar to `SingleSidedLPVaultBase._mintVaultShares`), `aa_composer.js` explicitly strips 0-amount outputs before finalizing the response: [1](#0-0) 

If this filtering empties a `payment` message's outputs, the whole message is removed: [2](#0-1) 

And if it empties the entire message list, the AA does not bounce; it just logs and produces a **successful** response unit with no outputs at all: [3](#0-2) 

Critically, the trigger unit (the user's deposit) is already an irreversible, confirmed unit on the DAG by the time the AA executes — the deposited bytes/asset are already inside the AA's balance. Since the response is deemed "successful" rather than bounced, there is no automatic refund mechanism: the AA keeps the deposit and the depositor receives nothing back. This is functionally identical to the reported issue: `vaultShares = 0` is accepted silently instead of reverting the mint, so the depositor loses the value of their `lpTokens`/deposit.

Because this logic lives in the core AA-response composer (not a sample script), any AA definition that computes a share/mint-style payment (e.g., `amount: "{round(deposit/total*outstanding)}"`, the exact pattern used in sample AAs like `uniswap_like_market_maker.oscript` and `51_attack_game.oscript`) is vulnerable to this silent-zero behavior whenever a small enough deposit is used: [4](#0-3) [5](#0-4) 

### Impact Explanation
An unprivileged trigger sender can send an amount small enough (relative to the AA's current pool/outstanding-share ratio) that the AA's formula computes a share/payout of `0`. The AA composer treats this as a normal, successful trigger execution (empty response), silently keeping the sender's deposited funds in the AA's balance without minting/returning anything. This is direct, unauthorized fund loss for the depositor — funds are trapped in the AA (and effectively redistributed to remaining shareholders since the pool grows without new shares being minted), which matches the "AA fund loss" impact category.

### Likelihood Explanation
This requires no privileged access — any address can send a trigger unit with a small enough payment. Any AA developer using proportional/ratio-based formulas for minting shares, computing payouts, or refunds (a well-established, encouraged pattern per the shipped sample AAs) is exposed. Because the composer's zero-output filtering and "successful empty response" fallback are unconditional core behaviors, the vulnerability surfaces automatically without any special AA-side handling unless the AA author manually adds a bounce check for zero-amount computed outputs.

### Recommendation
Consider having `aa_composer.js` treat an AA response that would end up with all payment outputs removed due to zero-amount computation as a bounce (refunding the trigger) rather than a "successful" empty response, or at minimum expose/document a way for AA formulas to detect and explicitly `bounce()` on zero-amount computed outputs before the composer discards them. At the AA-authoring level, formulas that mint/pay proportional shares should explicitly check the computed amount and `bounce()` if it is zero, analogous to `require(vaultShares > 0, ...)` in the referenced Solidity report.

### Proof of Concept
1. Deploy an AA similar to `uniswap_like_market_maker.oscript`'s "invest in MM" case, which computes `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` from the trigger's payment. [4](#0-3) 
2. After the pool has accumulated a large `mm_asset_outstanding` relative to `bytes_balance`, send a trigger with a very small `base` payment (just above the `1e5` dust threshold) such that `$issue_amount` rounds to `0`.
3. The AA's `payment` message with `amount: "{ $issue_amount }"` is filtered out by `aa_composer.js`'s zero-output filter. [6](#0-5) 
4. Since this is the only message, `messages.length === 0` and the composer emits a **successful empty response** rather than bouncing. [3](#0-2) 
5. The user's deposited bytes remain in the AA balance permanently; the user receives no `mm_asset` shares and no refund.

### Citations

**File:** aa_composer.js (L1274-1278)
```javascript
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
```

**File:** aa_composer.js (L1280-1281)
```javascript
		// remove messages with no outputs
		messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
```

**File:** aa_composer.js (L1282-1286)
```javascript
		if (messages.length === 0) {
			error_message = 'no messages after removing 0-outputs';
			console.log(error_message);
			return handleSuccessfulEmptyResponseUnit(null);
		}
```

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

**File:** test/samples/51_attack_game.oscript (L116-129)
```text
			{ // pay out the winnings
				if: `{
					if (!$bFinished)
						return false;
					$winner = var['winner'];
					$winner_asset = var['team_' || $winner || '_asset'];
					$asset_amount = trigger.output[[asset=$winner_asset]];
					$asset_amount > 0
				}`,
				init: `{
					$share = $asset_amount / var['team_' || $winner || '_amount'];
					$founder_tax = var['team_' || $winner || '_founder_tax'];
					$amount = round(( $share * (1-$founder_tax) + (trigger.address == $winner AND !var['founder_tax_paid'] ? $founder_tax : 0) ) * var['total']);
				}`,
```
