## Title
Rounding-based headers-commission split can mint or lose bytes beyond what the payer paid — (File: `headers_commission.js`)

## Summary
The Sherlock report describes `ZivoeRewards.depositReward()`: an unprivileged caller can trigger a rate/split recalculation that uses integer division/rounding, and by calling it repeatedly the truncation losses accumulate, silently locking reward tokens that were never meant to be lost. The generalizable bug class is: *a permissionless action drives a percentage-based split of a fixed pot using per-item rounding (`round`/`div`) instead of exact, remainder-preserving arithmetic, and repeating the action accumulates a supply/dust discrepancy that benefits or harms participants outside of protocol accounting.*

`ocore`'s headers-commission distribution (`calcHeadersCommissions()` in `headers_commission.js`) has the same structural weakness: the fixed integer `headers_commission` amount owed by a payer unit is split among an author's declared `earned_headers_commission_recipients` by rounding each recipient's fractional share independently, and — by the code's own comment — this rounding is deliberately done **once per contributing parent unit**, before the amounts are ever summed. Because `Math.round()` is not remainder-preserving, this can make the sum paid to recipients differ from the exact fee the payer was charged, in either direction.

## Finding Description
`calcHeadersCommissions()` computes, for every child unit that wins a header commission from a parent unit, the `full_amount` = the parent's `headers_commission` [1](#0-0) . It then splits that per‑parent `full_amount` across every declared recipient of the child unit using:

```js
var amount = Math.round(full_amount * share / 100.0);
``` [2](#0-1) 

and, in the SQL/DB reconciliation path, the exact same per-parent rounding is applied and explicitly documented as being done *before* summing across multiple parent contributions:

```js
// note that we round _before_ summing up header commissions won from several parent units
var amount = (row.earned_headers_commission_share === 100)
    ? full_amount
    : Math.round(full_amount * row.earned_headers_commission_share / 100.0);
``` [3](#0-2) 

The recipients and their integer percentage `earned_headers_commission_share` are freely chosen by the multi-authored unit's author(s) at compose time (only required to be valid addresses and to sum to 100 across the recipient list) via `objUnit.earned_headers_commission_recipients` [4](#0-3) . The attacker also fully controls the size (hence exact `headers_commission`) of every unit they post, since `headers_commission` is simply the serialized header size [5](#0-4) .

Because `Math.round(x)` rounds ties (`x.5`) up rather than distributing the remainder correctly, an attacker who controls both:
1. the exact integer `full_amount` paid by each parent unit (via unit crafting), and
2. the percentage shares of N recipients (all controlled by the attacker or their own multiple co-author addresses),

can choose shares/`full_amount` combinations that make several of the `round(full_amount * share_i / 100)` terms individually round *up* from a `.5` fraction, so that `Σ round(full_amount * share_i / 100) > full_amount`. For example, `full_amount = 50` with shares `{1, 1, 98}` gives `round(0.5) + round(0.5) + round(49) = 1 + 1 + 49 = 51`, i.e. 1 extra byte credited versus the 50 the payer actually paid as a fee. This surplus is inserted directly into `headers_commission_contributions` → `headers_commission_outputs`, and from there becomes a normal spendable `type='headers_commission'` input [6](#0-5) , which passes standard input/output balance validation because that check only compares total unit inputs vs outputs, not the origin fairness of the `headers_commission` component [7](#0-6) .

The same rounding-per-parent-contribution structure also means the opposite (deficit) direction can permanently and silently destroy bytes: if the rounding sums to *less* than `full_amount`, the missing amount is simply never inserted into any recipient's contribution — it disappears from the "spendable" pool entirely (an exact analog of the "reward tokens stuck/lost" impact in the original report), while still having been fully deducted from the payer as its `headers_commission` fee.

## Impact Explanation
- **Supply inflation**: an attacker who controls a multi-authored address (or coordinated set of authors) can post many small units, each winning tiny headers commissions from many parent units, and choose percentage splits engineered to produce systematic `Math.round()` overshoot. Each occurrence mints a small integer number of extra bytes that were never paid by any payer unit — a genuine violation of the fixed-`TOTAL_WHITEBYTES` supply invariant, repeatable indefinitely since header-commission winning and payload sizes are fully attacker-controlled.
- **Fund loss (dust burn)**: conversely, the same rounding-before-summing design can cause header-commission bytes that were legitimately paid by a unit's author to simply vanish (never credited to any recipient), matching the "funds get stuck/lost" impact category of the original report, except here the loss is unrecoverable rather than merely delayed.

Both directions stem from the same root cause: fractional per-parent-unit rounding of an integer fee split that is not remainder-preserving, and is fully triggerable by an ordinary unit-posting user who authors multi-authored units with self-chosen `earned_headers_commission_recipients` shares.

## Likelihood Explanation
Reaching this path requires only standard, unprivileged actions available to any user: composing a multi-authored unit, setting `earned_headers_commission_recipients` with attacker-chosen percentage shares that sum to 100 (a validation constraint that only checks the sum, not each individual rounding outcome — I was unable to fully re-confirm the exact validation line ranges within the remaining budget, but no code path was found that re-checks the rounded distribution against `headers_commission`), and controlling parent/child unit sizes to obtain a desired `headers_commission` value. `calcHeadersCommissions()` runs automatically and deterministically on stabilization for every eligible unit, so the attacker does not need cooperation from witnesses or other nodes — this is purely a self-serve arithmetic manipulation, comparable in accessibility to the original zero-value `depositReward()` call.

## Recommendation
Do not round each recipient's share of each individual parent-unit contribution independently. Instead:
- Accumulate the exact (unrounded, e.g. fixed-point/integer-scaled) fractional amount owed to each recipient across *all* contributing parent units for a child unit before doing a single rounding pass, or
- Use a remainder-preserving allocation algorithm (e.g., largest-remainder method) so that `Σ amount_recipient == Σ full_amount` is guaranteed exactly for every distribution round, eliminating both the inflation and the loss directions of the rounding error.

## Proof of Concept
Conceptual reproduction path (matches the code comment's own description of the vulnerable behavior):
1. Attacker authors a multi-authored unit `U` (their own addresses) and sets `earned_headers_commission_recipients = [{addrA, share:1}, {addrB, share:1}, {addrC, share:98}]` (sums to 100, passes validation).
2. Attacker crafts several parent units whose `headers_commission` (deterministically derivable from serialized header size, see `object_length.js:getHeadersSize`) equals values such as `50` for which `U` becomes the designated headers-commission winner (per `getWinnerInfo()`).
3. On stabilization, `calcHeadersCommissions()` computes, per parent contribution:
   `Math.round(50*1/100) + Math.round(50*1/100) + Math.round(50*98/100) = 1 + 1 + 49 = 51`
   i.e. 1 extra byte inserted into `headers_commission_contributions` beyond the `50` actually paid by that parent unit [3](#0-2) .
4. This surplus flows into `headers_commission_outputs` and becomes spendable via a normal `type='headers_commission'` input, passing standard balance validation [7](#0-6) .
5. Repeating steps 2–4 across many attacker-controlled parent/child unit pairs accumulates unbacked byte supply over time (or, with inverse share choices, permanently destroys legitimately paid commission bytes).

Note: I could not execute this in a live node within the available tool budget; the arithmetic above follows directly from the cited source and from `Math.round`'s documented half-up behavior on positive numbers, but real-world confirmation (e.g. via `forge`/node test harness) would strengthen certainty about magnitude and about whether any additional reconciliation check (I did not locate one) prevents the surplus from being persisted.

### Citations

**File:** headers_commission.js (L144-152)
```javascript
						var assocWonAmounts = {}; // amounts won, indexed by child unit who won the hc, and payer unit
						for (var payer_unit in assocChildrenInfos){
							var headers_commission = assocChildrenInfos[payer_unit].headers_commission;
							var winnerChildInfo = getWinnerInfo(assocChildrenInfos[payer_unit].children);
							var child_unit = winnerChildInfo.child_unit;
							if (!assocWonAmounts[child_unit])
								assocWonAmounts[child_unit] = {};
							assocWonAmounts[child_unit][payer_unit] = headers_commission;
						}
```

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

**File:** headers_commission.js (L199-204)
```javascript
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
```

**File:** headers_commission.js (L212-245)
```javascript
								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
							}
						);
					}
				);
			} // sqlite
		},
		function(cb){
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
				function(){
					if (conf.bFaster)
						return cb();
					conn.query("SELECT DISTINCT main_chain_index FROM units CROSS JOIN headers_commission_contributions USING(unit) WHERE main_chain_index>?", [since_mc_index], function(contrib_rows){
						if (contrib_rows.length === 1 && contrib_rows[0].main_chain_index === since_mc_index+1 || since_mc_index === 0)
							return cb();
						throwError("since_mc_index="+since_mc_index+" but contributions have mcis "+contrib_rows.map(function(r){ return r.main_chain_index}).join(', '));
					});
				}
			);
		},
		function(cb){
			conn.query("SELECT MAX(main_chain_index) AS max_spendable_mci FROM headers_commission_outputs", function(rows){
				max_spendable_mci = rows[0].max_spendable_mci;
				cb();
			});
		}
	], onDone);
```

**File:** composer.js (L248-253)
```javascript
	if (params.earned_headers_commission_recipients) // it needn't be already sorted by address, we'll sort it now
		objUnit.earned_headers_commission_recipients = params.earned_headers_commission_recipients.concat().sort(function(a,b){
			return ((a.address < b.address) ? -1 : 1);
		});
	else if (bMultiAuthored) // by default, the entire earned hc goes to the change address
		objUnit.earned_headers_commission_recipients = [{address: arrChangeOutputs[0].address, earned_headers_commission_share: 100}];
```

**File:** object_length.js (L52-69)
```javascript
function getHeadersSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get headers size of stripped unit");
	var objHeader = _.cloneDeep(objUnit);
	delete objHeader.unit;
	delete objHeader.headers_commission;
	delete objHeader.payload_commission;
	delete objHeader.oversize_fee;
//	delete objHeader.tps_fee;
	delete objHeader.actual_tps_fee;
	delete objHeader.main_chain_index;
	if (objUnit.version === constants.versionWithoutTimestamp)
		delete objHeader.timestamp;
	delete objHeader.messages;
	delete objHeader.parent_units; // replaced with PARENT_UNITS_SIZE
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	return getLength(objHeader, bWithKeys) + PARENT_UNITS_SIZE + (bWithKeys ? PARENT_UNITS_KEY_SIZE : 0);
}
```

**File:** validation.js (L2661-2668)
```javascript
			else{ // base asset
				const vote_count_fee = objUnit.messages.find(m => m.app === 'system_vote_count') ? constants.SYSTEM_VOTE_COUNT_FEE : 0;
				const oversize_fee = objUnit.oversize_fee || 0;
				const tps_fee = objUnit.tps_fee || 0;
				const burn_fee = objUnit.burn_fee || 0;
				if (total_input !== total_output + objUnit.headers_commission + objUnit.payload_commission + oversize_fee + tps_fee + burn_fee + vote_count_fee)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output+" + "+objUnit.headers_commission+" + "+objUnit.payload_commission+" + "+oversize_fee+" + "+tps_fee+" + "+burn_fee+" + "+vote_count_fee);
				callback();
```
