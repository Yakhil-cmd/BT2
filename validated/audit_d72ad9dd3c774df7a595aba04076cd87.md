### Title
Zero-amount headers-commission/witnessing output causes an unhandled exception in the wallet's coin selector, blocking spending of confirmed funds - (File: inputs.js)

### Summary
### Finding Description
The C4 finding describes a pattern where a strict `require(amount > 0)`-style check reverts a transaction that should otherwise succeed, because the amount computed for a specific slice of funds happens to be exactly zero, even though the overall balance owed is non-zero. The same all-or-nothing zero-check pattern exists in ocore's automatic coin-selection logic for headers-commission and witnessing inputs.

When `pickDivisibleCoinsForAmount` cannot satisfy a payment from plain transfer outputs, it falls back to `addMcInputs`, which calls `mc_outputs.findMcIndexIntervalToTargetAmount` to find a contiguous MCI range of unspent headers-commission/witnessing outputs summing to (at least) the required amount: [1](#0-0) 

If the range returned by `findMcIndexIntervalToTargetAmount` happens to sum to exactly zero, `addMcInputs` does not gracefully skip it or move to the next address — it throws an unhandled JS exception: [2](#0-1) 

A zero-amount headers-commission output can legitimately exist in the `headers_commission_outputs` table: `calcHeadersCommissions` computes each recipient's share as `Math.round(punits.headers_commission*earned_headers_commission_share/100.0)`, which can round down to `0` when a recipient's `earned_headers_commission_share` is small relative to the payer unit's `headers_commission` size: [3](#0-2) [4](#0-3) 

`earned_headers_commission_recipients` is attacker-controlled content of a posted unit (any author can name arbitrary recipient addresses and per-recipient shares, constrained only to positive integers summing to 100): [5](#0-4) 

This is directly analogous to the C4 report's `sharesToTokens(...) - s.staked` evaluating to a boundary value (zero) due to an adversary-influenced parameter (`commissionRate`), causing `require(rewards > 0)` to unexpectedly block a legitimate redemption. Here, an adversary-influenced parameter (`earned_headers_commission_share`) can cause a per-MCI commission output to be exactly zero, and the zero-check in the coin-selection path is implemented as an unconditional `throw` instead of a benign skip/continue.

### Impact Explanation
Once a victim address has a pending zero-amount output in `headers_commission_outputs` (or analogously `witnessing_outputs`) within the MCI range that the coin selector picks as the next spendable range for that address, any subsequent attempt by that victim (or their wallet acting on their behalf) to compose a payment that needs to draw on MC-commission inputs will hit `findMcIndexIntervalToTargetAmount` returning that zero-sum interval, and `addMcInputs` will `throw Error("earnings === 0")`. Because this is a synchronous `throw` inside an asynchronous callback chain (not funneled through the `cb()`/`onDone()` error-handling convention used elsewhere in the same file), it manifests as an uncaught exception in the composer/wallet process rather than a controlled validation failure. This can prevent the victim from composing any unit that needs additional MC-commission inputs until the underlying zero-output is somehow bypassed, effectively freezing that address's ability to spend confirmed commission funds (and potentially crashing the light/full wallet process, depending on how the exception propagates).

### Likelihood Explanation
Requires only a single unprivileged unit poster to author a unit with multiple authors and specify `earned_headers_commission_recipients` where a chosen victim address is given a very small `earned_headers_commission_share` relative to the poster's `headers_commission` size, plus at least one other unit later winning headers commission from that poster's unit and being attributed (even partially) to the victim through the recipient list. Because `headers_commission` for an individual unit is often small (unit headers can be well under a hundred bytes for minimal units), and shares are integer percentages as low as 1%, a rounding-to-zero contribution is readily achievable by a poster who controls both the share value and, indirectly, unit sizing. No special privileges, malicious peers, or network-level manipulation are required — only crafting message content, which matches the allowed "unprivileged unit poster" reach.

### Recommendation
In `inputs.js` `addMcInputs`, replace the `throw Error("earnings === 0")` with a graceful skip (treat a zero-earnings interval the same as `bHasSufficient=false`/insufficient, advance past it, or fall back to the next address/mechanism) instead of raising an unhandled exception. Additionally, consider avoiding storage of zero-amount rows in `headers_commission_outputs`/`witnessing_outputs` at insertion time in `headers_commission.js`/`paid_witnessing.js` (e.g., filter `WHERE amount > 0` on the `INSERT ... SELECT ... SUM(amount)` in `headers_commission.js:222-227`), so that a "nothing to redeem" condition never reaches the coin-selection logic in the first place.

### Proof of Concept
1. Address A (attacker) posts a 2-author unit U1 (A + victim address V) whose `headers_commission` (header size) is small, and sets `earned_headers_commission_recipients` so that V's `earned_headers_commission_share` is a low integer percentage (e.g., `1`), with the remaining share going to A or another address, satisfying `sum === 100`.
2. U1 becomes stable and wins headers commission from a parent unit with a small `headers_commission` value, such that `Math.round(headers_commission * 1 / 100.0)` computed in `calcHeadersCommissions` rounds to `0` for V's contribution (`headers_commission.js:49-52`).
3. This zero-amount row is aggregated into `headers_commission_outputs` for V at some MCI, since the `INSERT ... SUM(amount)` in `headers_commission.js:222-227` does not filter out zero sums.
4. Later, V's wallet attempts to compose any payment that must pull additional funds via `pickDivisibleCoinsForAmount` → `addMcInputs` (`inputs.js:182-220`). `findMcIndexIntervalToTargetAmount` returns V's next spendable MCI interval, which sums to `0`.
5. `addMcInputs` executes `if (earnings === 0) throw Error("earnings === 0")` (`inputs.js:192-193`), causing an uncaught exception instead of a controlled fallback, disrupting V's ability to compose the transaction.

### Citations

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

**File:** headers_commission.js (L49-52)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
					FROM units AS chunits \n\
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
