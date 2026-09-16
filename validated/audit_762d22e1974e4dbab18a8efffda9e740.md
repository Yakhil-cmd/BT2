Based on my investigation, I found the strongest analog in ocore's AA (Autonomous Agent) machinery: the automatic self-issuance path in `aa_composer.js`'s `sendUnit()`/`completePaymentPayload()`/`issueAsset()`, which mirrors the Thetanuts bug where the vault happily minted new shares to cover a shortfall without any real backing check.

### Title
AA self-issuance of uncapped assets mints unbacked supply to cover output shortfalls, enabling silent inflation - ([File: aa_composer.js])

### Summary
When an AA's `payment` message specifies output amounts exceeding the AA's actual spendable balance of a self-issued, uncapped asset, `completePaymentPayload()` in `aa_composer.js` falls through to `issueAsset()`, which mints exactly the shortfall (`target_amount - total_amount`) as a brand-new `issue` input with no verification that any real value (bytes, other assets) was ever deposited to back the newly created units of that asset.

### Finding Description
In `aa_composer.js`, `sendUnit()` composes the AA's response payment messages via `completePaymentPayload()`. The function first tries to satisfy the required `target_amount` from the AA's existing stable/unstable unspent outputs (`readStableOutputs`, `readUnstableOutputsSentByAAs`), and only if that fails does it call: [1](#0-0) 

`issueAsset()` computes `issue_amount = objAsset.cap || (target_amount - total_amount)` and, for the uncapped branch, simply looks up the current max serial number already issued by this AA/asset and mints a fresh `issue` input for exactly the missing amount, with no check whatsoever tying the mint to any deposit, exchange, or accounting invariant (e.g. `mm_asset_outstanding`, an AUM/backing balance, etc.): [2](#0-1) 

This is architecturally the same flaw as the Thetanuts exploit: the vault's `mint()` call created new shares to make the balance/repayment check pass, without any invariant enforcing that new shares are backed by newly deposited/claimed value. Here, any oscript AA that (a) defines an uncapped, `issued_by_definer_only` asset for itself (a very common share/LP-token pattern, as shown in the shipped `uniswap_like_market_maker.oscript` sample) and (b) has any code path where a `payment` message's output amount can be computed or influenced in a way that exceeds the AA's current balance of that asset, will cause `ocore` itself — not the AA's own defined logic — to silently top up the missing supply via `issueAsset()`. The AA author's accounting variables (e.g., `var['mm_asset_outstanding']`) are not consulted by this low-level auto-issuance path, so the real circulating supply and the author's tracked "outstanding" bookkeeping variable can diverge, exactly as in the Thetanuts case where a `mint()` was invoked to plug a shortfall while the actual backing accounting variable was never made to match. [3](#0-2) 

The `bSelfIssueForSendAll` legacy toggle further shows this auto-issuance also fires for "send all" outputs pre-`aa3UpgradeMci`, and post-upgrade it's still triggered for any explicit non-send-all shortfall: [4](#0-3) 

### Impact Explanation
If an AA author's formula has any bug, rounding error, or attacker-influenced computation (via `trigger.data`/`trigger.output`) that causes a requested payout of a self-issued uncapped asset to exceed the AA's tracked/actual balance, `ocore`'s auto-issuance mechanism will fabricate the difference as new supply rather than bouncing the trigger. This constitutes silent, consensus-accepted supply inflation of the asset — a direct analog to "supply inflation" impact, and can be leveraged by an unprivileged trigger sender to extract more of the asset (and, transitively, more of whatever the AA pays out per share) than was ever deposited, draining the AA's real backing assets on subsequent redemptions.

### Likelihood Explanation
Any AA author who follows the extremely common "define an uncapped self-issued share/LP asset, track outstanding supply in a state var, and pay it out based on formulas" pattern — exactly the pattern documented in ocore's own bundled `uniswap_like_market_maker.oscript` sample — is exposed. A single arithmetic/rounding discrepancy between the AA's own `var['..._outstanding']`-based accounting and the actual `payment` output amount computed in a `messages` case is sufficient to trigger the auto-issuance path, since `issueAsset()` performs no cross-check against the AA's declared invariants; only unprivileged trigger senders are needed to reach this code path.

### Recommendation
`issueAsset()`'s uncapped branch should not unconditionally mint the shortfall for AA-authored payment messages. At minimum, `sendUnit()`/`completePaymentPayload()` should bounce (fail) the trigger instead of self-issuing when the AA does not have sufficient existing balance of its own uncapped asset, forcing AA authors' own oscript logic (and its invariants) to be the sole source of truth for issuance, or require an explicit `asset` message issuance in the same response rather than an implicit low-level top-up.

### Proof of Concept
1. An AA defines an uncapped, `issued_by_definer_only` asset (as in `test/samples/uniswap_like_market_maker.oscript`) and tracks `var['mm_asset_outstanding']`.
2. Craft a trigger whose formula path computes a `payment` output amount for that asset (e.g., via a rounding-favorable ratio or a case where `var['mm_asset_outstanding']` is not incremented in lockstep with an actual payout) that exceeds the AA's current spendable balance of the asset.
3. `sendUnit()` -> `completePaymentPayload()` finds insufficient existing unspent outputs, calls `issueAsset()`, which mints exactly the missing amount as a fresh `issue` input with `aa_composer.js:1179` `issue_amount = target_amount - total_amount`, with no reference to `var['mm_asset_outstanding']` or any deposit having occurred.
4. The response unit is validated and accepted network-wide (asset `issued_by_definer_only` check is satisfied because the AA itself is the definer), permanently inflating the asset's real supply beyond what the AA's own bookkeeping (and depositors) accounted for.

### Citations

**File:** aa_composer.js (L1175-1212)
```javascript
			function issueAsset(cb2) {
				var objAsset = assetInfos[asset];
				if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
					return cb2("not a definer");
				var issue_amount = objAsset.cap || (target_amount - total_amount);

				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
				}
				
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
				}
				else{
					conn.query( // filtered by our AA's address, all equally visible on all nodes
						"SELECT MAX(serial_number) AS max_serial_number FROM inputs WHERE type='issue' AND asset=? AND address=?",
						[asset, address],
						function(rows){
							var max_serial_number = (rows.length === 0) ? 0 : rows[0].max_serial_number;
							addIssueInput(max_serial_number+1);
						}
					);
				}
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

**File:** test/samples/uniswap_like_market_maker.oscript (L59-65)
```text
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] += $issue_amount;
						}`
					},
				]
```
