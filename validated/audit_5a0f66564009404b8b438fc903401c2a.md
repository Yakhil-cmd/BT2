### Title
Denial-of-Service via `throw Error("earnings === 0")` when a rounded-to-zero headers-commission/witnessing output is picked as an input - (File: `mc_outputs.js`, `inputs.js`, `headers_commission.js`)

### Summary
An unprivileged unit author can craft a unit with an `earned_headers_commission_recipients` list containing many addresses with very small `earned_headers_commission_share` values. When the headers commission is calculated and split among these recipients, `Math.round()`/SQL `ROUND()` can produce a commission amount of `0` for some recipients. This zero-amount row is persisted into `headers_commission_outputs` and can later be picked up by `findMcIndexIntervalToTargetAmount()`, causing `pickDivisibleCoinsForAmount()` to hit an unconditional `throw Error("earnings === 0")`, crashing/DoS-ing the composing logic for the affected address — directly analogous to the reported "revert on zero-amount transfer blocks a batch operation" bug class.

### Finding Description
Any unit author can freely define `earned_headers_commission_recipients` as long as the shares are positive integers summing to 100 and addresses are sorted, per `validateHeadersCommissionRecipients()`: [1](#0-0) 

There is no minimum-share or minimum-recipient-count restriction, so an author can list many recipients with tiny `earned_headers_commission_share` values (e.g., 1%).

When headers commissions are distributed, the earned amount for each recipient is computed by rounding a fraction of the parent unit's `headers_commission`: [2](#0-1) 

For small `headers_commission` values combined with small shares, `Math.round(full_amount * share / 100.0)` (or the equivalent SQL `ROUND(...)`) evaluates to `0`. This zero-amount contribution is aggregated by `SUM(amount)` per address/mci and inserted into `headers_commission_outputs`: [3](#0-2) 

There is no filter anywhere in this pipeline that drops zero-amount rows before they are written to `headers_commission_outputs` (the same rounding-to-zero risk exists in the analogous `witnessing` commission path via `paid_witnessing.js`/`mc_outputs.js`).

Later, when the affected recipient's wallet composes a payment and needs main-chain (`headers_commission`/`witnessing`) inputs, `addMcInputs()` calls `findMcIndexIntervalToTargetAmount()`: [4](#0-3) 

If the query in `mc_outputs.js` returns an interval whose accumulated sum is exactly `0` (which can happen if the only unspent output(s) in the picked range are the zero-amount rows described above), the `ifFound` callback unconditionally throws: [5](#0-4) 

This `throw Error("earnings === 0")` is not routed through an error callback — it is a synchronous throw inside a callback invoked from `async.eachSeries`, meaning it propagates up the call stack uncaught in the normal composing flow, rather than gracefully failing or being filtered out.

### Impact Explanation
Any wallet/address that is designated as an `earned_headers_commission_recipients` recipient with a small enough share can end up with a `0`-amount `headers_commission_outputs` row once that recipient tries to accumulate MC inputs spanning that zero output. This crashes the payment-composing logic (an uncaught `throw`), preventing that address from composing further payments that need headers-commission (or witnessing) inputs until the code path is worked around — a concrete denial-of-service against normal spending/composing functionality, matching the "Medium" severity bug class of the original report (unexpected revert/DoS from a zero-amount transfer/settlement in a batched, all-or-nothing accounting operation).

### Likelihood Explanation
Triggering this requires only posting a normal unit with multiple authors and an `earned_headers_commission_recipients` list containing a recipient with a very small share relative to the unit's `headers_commission` — something entirely within reach of any unprivileged unit poster, without needing witness, hub, or node privileges. The only additional condition is that the zero-amount output ends up being the sole item accumulated in the chosen MC index range for that recipient's address, which is plausible for addresses with low overall headers-commission activity.

### Recommendation
- Filter out zero-amount rows before inserting into `headers_commission_outputs` / `witnessing_outputs` in `headers_commission.js` (and the analogous witnessing distribution code), so a rounded-to-zero share never becomes a persisted spendable-but-empty output.
- Alternatively/additionally, in `mc_outputs.js`/`inputs.js`, treat `earnings === 0` as a benign "skip and continue" case (similar to the existing `earnings <= full_input_size` skip logic) instead of throwing, so a stray zero-amount output cannot crash the composing flow.

### Proof of Concept
1. Compose and broadcast a multi-authored unit whose `earned_headers_commission_recipients` includes an address `X` with a very small `earned_headers_commission_share` (e.g., `1`) while other recipients take the rest, such that `Math.round(headers_commission * 1 / 100)` evaluates to `0` for address `X` (validation only requires shares to sum to 100 and be positive integers — see `validation.js:1101-1124`).
2. Let the unit become stable so `calcHeadersCommissions()` in `headers_commission.js` runs and inserts a `0`-amount contribution/output for `X` at some `main_chain_index`.
3. From wallet `X`, attempt to compose any payment that needs to draw on headers-commission inputs (`pickDivisibleCoinsForAmount` → `addHeadersCommissionInputs` → `addMcInputs` → `mc_outputs.findMcIndexIntervalToTargetAmount`) where the only unspent output(s) in the picked MC-index interval sum to `0`.
4. Observe the uncaught `throw Error("earnings === 0")` in `inputs.js:192-193`, halting the composing logic for address `X`.

### Citations

**File:** validation.js (L1101-1124)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
```

**File:** headers_commission.js (L179-205)
```javascript
										var full_amount = assocWonAmounts[child_unit][payer_unit];
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
									}
								}
								// sql result
								var arrValues = conf.bFaster ? arrValuesRAM : [];
								if (!conf.bFaster){
									profit_distribution_rows.forEach(function(row){
										var child_unit = row.unit;
										for (var payer_unit in assocWonAmounts[child_unit]){
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

**File:** headers_commission.js (L221-238)
```javascript
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
```

**File:** inputs.js (L182-220)
```javascript
	function addMcInputs(type, input_size, max_mci, onStillNotEnough){
		var address_size = ADDRESS_SIZE + (bWithKeys ? ADDRESS_KEY_SIZE : 0);
		var full_input_size = input_size + (bMultiAuthored ? address_size : 0);
		async.eachSeries(
			arrAddresses,
			function(address, cb){
				var target_amount = net_required_amount - total_amount + full_input_size + getOversizeFee(size + full_input_size);
				mc_outputs.findMcIndexIntervalToTargetAmount(conn, type, address, max_mci, target_amount, {
					ifNothing: cb,
					ifFound: function(from_mc_index, to_mc_index, earnings, bSufficient){
						if (earnings === 0)
							throw Error("earnings === 0");
						if (earnings <= full_input_size) // skip net negative MC inputs
							return cb();
						var input = {
							type: type,
							from_main_chain_index: from_mc_index,
							to_main_chain_index: to_mc_index
						};
						if (bMultiAuthored)
							input.address = address;
						arrInputsWithProofs.push({input: input});
						total_amount += earnings;
						net_required_amount += full_input_size;
						size += full_input_size;
						required_amount = net_required_amount + getOversizeFee(size);
						(total_amount > required_amount)
							? cb("found") // break eachSeries
							: cb(); // try next address
					}
				});
			},
			function(err){
				if (!err)
					console.log(arrAddresses+" "+type+": got only "+total_amount+" out of required "+required_amount);
				(err === "found") ? onDone(arrInputsWithProofs, total_amount) : onStillNotEnough();
			}
		);
	}
```
