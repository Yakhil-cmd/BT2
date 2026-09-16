### Title
Rounding of `earned_headers_commission_share` / TPS-fee splits allows commission total to diverge from payer amount - ([File: headers_commission.js])

### Summary
The Sherlock finding is a classic "round-down favors the wrong side" ERC4626 bug: `_previewMint`/`_previewWithdraw` rounds a per-share amount down when it should round up, silently shorting the depositor. The reachable analog in ocore is the arithmetic used to split a single, fixed commission (headers commission or witnessing/TPS fee) among **multiple recipients** defined by an ordinary unit author via `earned_headers_commission_recipients`. Each recipient's cut is computed independently with `Math.round(full_amount * share / 100.0)` (and `Math.floor` for TPS fees), so the sum of the rounded per-recipient amounts is not guaranteed to equal the original `full_amount`/`total_tps_fees_delta` that is actually available to spend.

### Finding Description
`calcHeadersCommissions` computes, for every child unit that wins a parent's headers commission, the amount owed to each recipient address independently: [1](#0-0) 

and, in the SQL branch, the same independent per-row rounding: [2](#0-1) 

Each recipient's share is rounded to the nearest integer coin (`Math.round(full_amount * share / 100.0)`), but there is no subsequent normalization step that forces `Σ amount_i == full_amount`. Because `earned_headers_commission_recipients` shares are attacker-controlled fields set by the unit author (any unpriviledged unit poster can define recipients and shares on their own authored unit, subject only to summing to 100 in `validation.js`), an author can choose share fractions (e.g. many recipients with shares like 33/33/34, or fractional percentages that individually round to `.5`) that cause the total of the independently-rounded outputs to exceed the true `full_amount` that was actually earned/available. The identical pattern is used for TPS fee distribution in `storage.js`'s `updateTpsFees`, which uses `Math.floor` per recipient share: [3](#0-2) 

Here `Math.floor` is applied per-recipient instead of Banker's/exact remainder distribution, so summing all recipients' floored deltas can differ from `total_tps_fees_delta` computed once for the whole unit. Because `headers_commission_outputs`/`tps_fees_balances` become spendable balances credited to addresses (used later by `inputs.js`'s `addMcInputs`/`pickDivisibleCoinsForAmount` when building spendable inputs from `headers_commission`/`witnessing` MC inputs), any systematic upward rounding leak lets a set of colluding recipient addresses receive, cumulatively, more base-asset units than the network mechanism intended to disburse for a given unit's `headers_commission`, which is itself deducted from a fixed pool (a parent-unit's declared header commission) rather than being newly minted per recipient.

### Impact Explanation
If the sum of independently rounded per-recipient shares can exceed the `full_amount`/`total_tps_fees_delta` that was actually collected for that unit, addresses controlled by the unit's author can accumulate spendable `headers_commission_outputs`/`tps_fees_balances` credits beyond what the protocol actually collected from spenders, i.e., a supply-inflation / unauthorized-spending vector reachable purely by posting units with self-chosen `earned_headers_commission_recipients` share splits — no privileged role required. This matches the "concrete unauthorized spending / supply inflation" bar for a High-severity analog.

### Likelihood Explanation
Likelihood depends on whether `validation.js`'s summation check for `earned_headers_commission_share` (requiring shares to sum to exactly 100) is strict enough to prevent any residual imbalance after rounding, and whether `writer.js` or `headers_commission.js` performs any compensating adjustment (e.g., giving the last recipient the remainder instead of an independently rounded share) elsewhere in the pipeline that I could not fully confirm from the retrieved snippets. I was only able to confirm the per-recipient independent-rounding code paths in `headers_commission.js` and `storage.js`; I could not fully trace whether a remainder-correction step exists downstream (I did not locate one in the code I retrieved), so likelihood of the imbalance surviving to a spendable output could not be conclusively verified within the available index.

### Recommendation
Use a remainder-distribution algorithm instead of independent per-recipient rounding: compute each recipient's floor amount, sum the floors, and assign the leftover remainder (which is bounded by the number of recipients, not by `full_amount`) to a single designated recipient (e.g., the last one, sorted deterministically), guaranteeing `Σ amount_i === full_amount` for both `headers_commission.js`'s per-recipient split and `storage.js`'s `updateTpsFees` per-recipient split.

### Proof of Concept
Not able to construct a concrete end-to-end PoC unit sequence from the indexed code alone (would require confirming the exact `validation.js` sum-to-100 check and absence of a remainder-correction step in `writer.js`); flagging as a structurally analogous rounding-imbalance bug class based on the confirmed independent-rounding code in [1](#0-0)  and [3](#0-2) , which a Devin session with full repo/test access should verify against `validation.js`'s share-sum enforcement and `writer.js`'s persistence logic.

### Citations

**File:** headers_commission.js (L180-188)
```javascript
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
									}
```

**File:** headers_commission.js (L196-205)
```javascript
											var full_amount = assocWonAmounts[child_unit][payer_unit];
											if (!full_amount)
												throw Error("no amount for child unit "+child_unit+", payer unit "+payer_unit);
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
										}
```

**File:** storage.js (L1265-1271)
```javascript
			const recipients = getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses);
			for (let address in recipients) {
				const share = recipients[address];
				const tps_fees_delta = Math.floor(total_tps_fees_delta * share / 100);
				const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, mci]);
				const tps_fees_balance = row ? row.tps_fees_balance : 0;
				await conn.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", [address, mci, tps_fees_balance + tps_fees_delta]);
```
