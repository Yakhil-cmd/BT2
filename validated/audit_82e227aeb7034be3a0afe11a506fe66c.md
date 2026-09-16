### Title
Unbounded accumulation of outputs when composing an AA's "send-all" payment can permanently freeze AA funds and its response logic - (File: `aa_composer.js`, function `sendUnit.completePaymentPayload.iterateUnspentOutputs`)

### Summary
`aa_composer.js`'s `sendUnit()` builds an AA response payment by querying every unspent output sent to the AA for the asset being spent and feeding all matching rows into `payload.inputs` via `iterateUnspentOutputs()`. For a normal (non send-all) output, the loop `break`s as soon as `target_amount` is reached, bounding the number of inputs. But for a "send-all" output (`amount === undefined`), the loop explicitly does `continue` instead of `break` once `bFound` becomes true [1](#0-0) , so it keeps consuming **every single unspent output row** returned by the (unbounded, `LIMIT`-less) SQL queries in `readStableOutputs`/`readUnstableOutputsSentByAAs` [2](#0-1) .

### Finding Description
This is directly analogous to the reported Buffer bug: an unbounded loop that iterates over a per-address collection that any unprivileged user can grow arbitrarily (there, `lockedAmounts`; here, unspent outputs owned by an AA address), used to compute how much can be released/spent. In ocore, any user can post many payment messages sending tiny amounts of a custom (non-base) asset to an AA address. For custom assets, the dust-filter that exists for base-asset outputs (`amount>=FULL_TRANSFER_INPUT_SIZE`) is not applied — only the base asset branch enforces a minimum amount [3](#0-2) . So an attacker can create an unbounded number of tiny-value outputs of a custom asset addressed to a target AA.

If that AA (a common, legitimate pattern) responds by sending back "all" of a received asset (a `send-all` output, i.e. `amount` omitted) — for example a proxy/relay AA, a vault AA that forwards whatever it holds, or an AA using `[[amount=]]`-less output — then every time it is triggered, `sendUnit()` will try to consume **all** of the attacker-inflated set of tiny outputs into a single payment message's `inputs` array, because the `send_all_output` branch never breaks the loop [4](#0-3) . Unlike the general-wallet coin-picker `pickDivisibleCoinsForAmount` in `inputs.js`, which explicitly caps the number of picked inputs to `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2` via a `LIMIT` clause [5](#0-4) , the AA composer's `iterateUnspentOutputs`/`readStableOutputs` path has no such cap for the send-all case.

The resulting unit, once built, is size- and input-count-limited by `validation.js`'s enforcement of `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` and `MAX_UNIT_LENGTH`, so a unit with too many inputs will fail unit validation (`validateAndSaveUnit`), causing `sendUnit()` to bounce with an error [6](#0-5) . Because state changes are rolled back on bounce and the underlying set of tiny outputs remains untouched, the very next trigger of the same AA hits the exact same unbounded set of outputs again — the AA can never successfully compose a valid send-all response once the outputs count exceeds the per-unit input limit. This is a persistent denial of a specific spending path for the AA, matching the impact class "AA fund loss/freezing": funds legitimately owed to the AA's counterparties become permanently unspendable through the send-all code path, while the attacker only pays trivial byte fees per dust output created.

### Impact Explanation
Any AA implementing a "return everything I hold in asset X" response pattern can be permanently DoS'd on that code path by a single unprivileged attacker who cheaply floods it with many small-value custom-asset outputs (no minimum-amount filter applies to non-base assets in `readStableOutputs`/`readUnstableOutputsSentByAAs`). Because the loop for send-all never stops accumulating inputs, and there is no cap analogous to `pickDivisibleCoinsForAmount`'s `LIMIT`, the constructed response unit will eventually exceed `MAX_INPUTS_PER_PAYMENT_MESSAGE`/unit size limits and fail to validate every single time the AA is triggered, bouncing indefinitely and freezing the intended payout.

### Likelihood Explanation
Likelihood is moderate-to-high wherever an AA author uses a send-all output for a custom asset (a documented, encouraged oscript pattern for "forward everything received"): the attack requires only posting many ordinary payment units to the AA's address with tiny amounts of that asset — something any user can do without special privileges, at low cost (bytes fee per unit, no minimum-amount check for non-base assets).

### Recommendation
- Apply a dust-amount minimum filter for non-base (custom) assets analogous to the one already used for base-asset outputs in `readStableOutputs`/`readUnstableOutputsSentByAAs`.
- Cap the number of rows/inputs consumed in `iterateUnspentOutputs` for the send-all branch (e.g., via `LIMIT constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` in the SQL, mirroring `inputs.js`'s `pickMultipleCoinsAndContinue`), and handle the "not all funds spent this round" case gracefully (e.g., partial send-all across multiple responses) rather than failing validation outright.
- Alternatively, reject/merge or ignore below-threshold dust outputs when computing AA balances used for send-all payments, so an attacker cannot inflate the output-row count arbitrarily.

### Proof of Concept
1. Deploy (or use) an AA whose response payment includes a send-all output for a custom asset `A` it may receive, e.g. `outputs: [{address: "{trigger.address}"}]` for asset `A`.
2. As an attacker, repeatedly post cheap payment units transferring dust amounts (e.g., 1 unit) of asset `A` to the AA's address, building up thousands of tiny unspent outputs (no per-output minimum is enforced for non-base assets, per `aa_composer.js` lines 1145-1154).
3. Trigger the AA. `completePaymentPayload` → `iterateUnspentOutputs` iterates the entire unbounded row set because `send_all_output` prevents `break` (lines 1117-1123), appending one `input` per dust output.
4. Once the accumulated `payload.inputs.length` exceeds `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` (or the unit exceeds `MAX_UNIT_LENGTH`), `validateAndSaveUnit` rejects the composed unit and `sendUnit()` bounces.
5. Because the dust outputs are never consumed (the bounced attempt is rolled back) and no cap limits how many are picked next time, every subsequent trigger repeats the same failure — the AA can never again successfully execute its send-all payment path for asset `A`, permanently freezing those funds.

### Citations

**File:** aa_composer.js (L1115-1123)
```javascript
					if (total_amount < target_amount)
						continue;
					if (total_amount === target_amount && payload.outputs.length > 0) {
						bFound = true;
						if (send_all_output)
							continue;
						else
							break;
					}
```

**File:** aa_composer.js (L1140-1173)
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

**File:** aa_composer.js (L1408-1411)
```javascript
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** inputs.js (L144-145)
```javascript
			ORDER BY amount DESC LIMIT ?`,
			[arrSpendableAddresses, constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2],
```
