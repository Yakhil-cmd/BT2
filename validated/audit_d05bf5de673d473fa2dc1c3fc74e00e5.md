### Title
DoS of AA withdraw/payout process via dust-output exclusion causing legitimate payment triggers to bounce - ([File: aa_composer.js])

### Summary
An Autonomous Agent (AA) that tracks user balances/entitlements in state variables and later pays them out via a `payment` message can have its actual spendable balance be lower than its accounted balance, because the unit-composing logic in `aa_composer.js` silently excludes small ("dust") base-asset outputs from being spent. When a payout is requested and the sum of spendable (non-dust, sufficiently stable) outputs is less than the target amount, the whole trigger response bounces, denying the withdraw/payout to a legitimate user — the same class of bug as the reported Balancer issue, where the pool's `cash` balance (actually spendable funds) can be less than the accounted total balance, causing withdraw reverts.

### Finding Description
When an AA sends a payment (e.g., in response to a user's withdraw/claim trigger), `sendUnit()` -> `completePaymentPayload()` selects UTXOs to fund the target amount: [1](#0-0) 

The query for byte (base-asset) outputs explicitly ignores outputs smaller than `FULL_TRANSFER_INPUT_SIZE` to avoid a dust-spam griefing attack:
```
"...AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
    AND sequence='good' AND main_chain_index<=? ..."
``` [2](#0-1) 

In addition to stable, non-dust outputs owned by the AA, only *unstable outputs sent by other AAs* are considered spendable pending stability; unstable outputs sent by regular (non-AA) users are excluded entirely until they become stable: [3](#0-2) 

If, after combining stable outputs and eligible unstable AA-sourced outputs, the accumulated `total_amount` still does not reach `target_amount`, the composer either tries to self-issue (only possible for a non-base asset the AA itself defines) or gives up: [4](#0-3) 

If that fails, the whole message-processing chain returns an error to `cb`, which propagates to `bounce(err)`, reverting the entire trigger response (state changes are rolled back and, if fees are insufficient, even the bounce notice may not be sent): [5](#0-4) 

Because the AA's internal accounting (state variables such as `var['balance_...']`, incremented immediately when a deposit trigger is processed — see the balance-tracking pattern used in `test/samples/order_book_exchange.oscript` / `payment_channels.oscript`) is not required to match the set of *spendable* (non-dust, stable, or AA-authored-unstable) outputs, the AA can believe it has enough funds to honor a withdraw request while the actual composer cannot assemble that amount from usable UTXOs. This mirrors the Balancer bug class: the accounted total balance (`cash + managed`) differs from the actually-withdrawable balance (`cash`), and the discrepancy causes the withdraw transaction/trigger to revert/bounce.

### Impact Explanation
Any AA that credits users with balances in state (deposit/vault-style, order-book, payment-channel, or similar contracts) and later pays them out is exposed: if enough of its incoming base-asset payments arrive as many small ("dust") outputs below `FULL_TRANSFER_INPUT_SIZE`, those funds become part of the AA's `outputs` table balance yet are permanently excluded from being selected as payment inputs. When a legitimate user later triggers a withdrawal for an amount that requires those funds, `completePaymentPayload` cannot reach `target_amount`, and the whole response bounces — the user's withdraw is denied even though the AA "owns" enough total value. Because this exclusion is permanent (dust outputs are never included by this query, not merely delayed), the AA's spendable liquidity can degrade over time, producing a lasting denial of service on withdrawals for an AA-based vault/exchange/settlement contract. This matches the Medium-severity impact criteria: a fund-locking / withdraw DoS condition for AA users.

### Likelihood Explanation
Likelihood is real but conditional: it requires the AA's incoming base-asset payments (deposits, fee refunds, partial trade settlements, etc.) to include outputs smaller than `FULL_TRANSFER_INPUT_SIZE`, which can happen naturally in busy multi-user AAs (e.g., order-book/exchange or payment-channel style AAs where trigger outputs, dust change, or many small deposits accumulate) or can be intentionally engineered by an attacker who sends many small-value trigger units to a target AA to gradually strand a portion of its balance as unusable dust, later timing a legitimate large-withdraw trigger to coincide with an under-funded spendable pool. No special privilege is required — any unprivileged unit poster can send a trigger with small outputs to the AA address.

### Recommendation
- When an AA's state logic promises to pay out a specific amount, the payment composer should surface a clear, catchable insufficiency (already partially done via `bounce`), but AA authors additionally need a documented, reliable way to query "actually spendable balance" (net of the dust filter and stability rules) distinct from the raw output-derived total balance, so contracts can reject/queue a withdraw request instead of silently bouncing and losing state consistency guarantees.
- Consider exposing a helper (e.g., in `formula` evaluation) that returns the AA's currently composer-spendable balance (respecting `FULL_TRANSFER_INPUT_SIZE` and output stability) so AA logic can proactively check `spendable_balance >= requested_amount` before committing to a payout, avoiding a full bounce.
- Alternatively, allow the composer to consolidate ("sweep") dust outputs opportunistically (e.g., during secondary/non-time-critical AA runs) so dust does not perpetually accumulate as unusable balance.

### Proof of Concept
Not directly executable from static review alone; the mechanism is demonstrated structurally by the code paths cited above:
1. Multiple triggers send the AA small base-asset payments individually below `FULL_TRANSFER_INPUT_SIZE`, each of which increments the AA's internal `var['balance_...']` state (per the deposit-accounting pattern shown in `test/samples/order_book_exchange.oscript:100-120` and `payment_channels.oscript:12-30`).
2. A user later triggers a withdraw for an amount that state variables say is available.
3. `sendUnit()` → `completePaymentPayload()` queries `readStableOutputs`, which excludes all outputs `< FULL_TRANSFER_INPUT_SIZE` [6](#0-5) , so `total_amount` under-accumulates relative to `target_amount`.
4. `bFound` stays false, the base-asset branch returns `cb('not enough funds for ' + target_amount + ' bytes')` [7](#0-6) , and the trigger is bounced [5](#0-4) , denying the legitimate withdrawal despite the AA's state believing sufficient funds exist.

### Citations

**File:** aa_composer.js (L1140-1155)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** aa_composer.js (L1157-1173)
```javascript
			function readUnstableOutputsSentByAAs(handleRows) {
			//	console.log('--- readUnstableOutputsSentByAAs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				conn.query(
					"SELECT outputs.unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					CROSS JOIN unit_authors USING(unit) \n\
					CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** aa_composer.js (L1223-1244)
```javascript
			readStableOutputs(function (rows) {
				iterateUnspentOutputs(rows);
				if (bFound && !send_all_output)
					return sortOutputsAndReturn();
				readUnstableOutputsSentByAAs(function (rows2) {
					iterateUnspentOutputs(rows2);
					if (bFound)
						return sortOutputsAndReturn();
					if (!asset)
						return cb('not enough funds for ' + target_amount + ' bytes');
					var bSelfIssueForSendAll = mci < (constants.bTestnet ? 2080483 : constants.aa3UpgradeMci);
					if (!bSelfIssueForSendAll && send_all_output && payload.outputs.length === 1) // send-all is the only output - don't issue for it
						return sortOutputsAndReturn();
					issueAsset(function (err) {
						if (err) {
							console.log("issue failed: " + err);
							return cb('not enough funds for ' + target_amount + ' of asset ' + asset);
						}
						sortOutputsAndReturn();
					});
				});
			});
```

**File:** aa_composer.js (L1346-1350)
```javascript
			function (err) {
				if (err)
					return bounce(err);
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
```
