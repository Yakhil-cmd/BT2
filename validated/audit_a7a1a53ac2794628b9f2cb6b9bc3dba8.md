Based on my research, I found a concrete, production-code analog of the Midas Capital rounding bug: independent per-recipient rounding when distributing headers commissions.

### Title
Independent per-recipient rounding in headers-commission distribution can mint bytes beyond the earned commission - ([File: headers_commission.js])

### Summary
Midas Capital's loss stemmed from an integer-rounding flaw in a Compound v2 fork where a proportional-share calculation could round in the caller's favor, letting an attacker extract more value than legitimately owed. `ocore` has a structurally identical bug class in `calcHeadersCommissions()`, which splits a parent unit's `headers_commission` among multiple `earned_headers_commission_recipients` by rounding each recipient's share independently instead of ensuring the rounded parts sum to the original whole.

### Finding Description
When a unit has multiple authors, or a unit explicitly assigns `earned_headers_commission_share` percentages to multiple addresses (declared via `earned_headers_commission_recipients`, validated only for percentages summing to 100 in `validateHeadersCommissionRecipients` [1](#0-0)  ), the commission payout for each recipient is computed independently with `Math.round`:

```
var amount = Math.round(full_amount * share / 100.0);
```

both in the JS/sqlite path [2](#0-1)  and the MySQL SQL path (`ROUND(punits.headers_commission*earned_headers_commission_share/100.0)`) [3](#0-2) , and again when reconciling per-payer amounts across multiple parent units [4](#0-3) .

Because `Math.round` (round-half-up, applied per recipient) is used instead of a "largest remainder"-style allocation that guarantees the parts sum to `full_amount`, the sum of independently rounded shares can exceed the original `headers_commission` earned from the payer unit whenever the percentages/amounts create non-exact fractional halves distributed across recipients (e.g., 3 recipients at ~33.33% each, or asymmetric splits like 50/30/20 applied to odd `headers_commission` values). Each `.5`-or-above fractional share rounds up independently, so the total awarded commission can be inflated relative to what the payer unit actually earned/paid.

These rounded amounts are inserted into `headers_commission_contributions` and subsequently summed into `headers_commission_outputs` [5](#0-4) , which are directly spendable bytes balances usable in future payment inputs (`type: "headers_commission"`) [6](#0-5)  and counted toward total network supply in `readAllUnspentOutputs` [7](#0-6) . This means rounding errors here directly translate into new spendable base-asset ("bytes") value that was never paid for — i.e., inflation of the byte supply, mirroring the "integer rounding problem" that let the Midas Capital attacker extract more assets than backed by real collateral.

### Impact Explanation
Any unit author can trigger this path by simply constructing a multi-authored unit (or a unit with an `earned_headers_commission_recipients` list) with recipient shares chosen so that each individual rounded share rounds up. Because header commissions are paid out over and over as new units are added to the DAG (an ongoing, attacker-controllable process — an attacker fully controls the number/shares of `earned_headers_commission_recipients` on their own units), a sustained strategy of always splitting commissions to maximize rounding-up across many small payer units could produce a persistent, systemic inflation of the "bytes" base asset over time, which is a supply-integrity violation reachable by an ordinary unposted-unit author (not a hub/witness/operator).

### Likelihood Explanation
The attacker needs no privileged role — any address that posts units (with multiple authors, or naming `earned_headers_commission_recipients`) can pick share percentages designed to maximize rounding gain, and this happens automatically as part of protocol-native stabilization/commission computation, executed identically (and independently verified for consistency between DB and in-RAM paths — but not against the invariant that the sum equals `full_amount`) by every full node.

### Recommendation
Replace independent per-recipient rounding with an allocation algorithm that guarantees the rounded parts always sum exactly to `full_amount` (e.g., "largest remainder" / "Hamilton's method": round down all shares, then distribute the leftover integer units to the recipients with the largest fractional remainders, in a deterministic order such as sorted by address to preserve consensus determinism). Apply this consistently to both the MySQL SQL rounding expression and the JS in-memory computation in `headers_commission.js`, and add a runtime assertion that `SUM(amount)` per payer unit does not exceed `full_amount`/`headers_commission`.

### Proof of Concept
1. Post a genesis-adjacent unit chain where a child unit `C` has multiple authors, e.g., 3 authors A, B, D declared via `earned_headers_commission_recipients` with shares `34, 33, 33` (summing to 100, valid per `validateHeadersCommissionRecipients`).
2. Suppose the winning parent unit's `headers_commission` for this round is an amount such that `headers_commission * 34/100`, `* 33/100`, `* 33/100` each round up (e.g., `headers_commission = 3` gives `1.02→1`, `0.99→1`, `0.99→1`, sum = 3, no gain; but choosing `headers_commission = 5` with shares `34/33/33` gives `1.7→2`, `1.65→2`, `1.65→2`, sum = 6 > 5 — a 1-unit inflation per stabilization round).
3. Repeat this pattern across many self-controlled units over time (each unit only needs to declare a 3-way, or n-way, split maximizing rounding gain) to accumulate excess `headers_commission_outputs` balance.
4. Spend the resulting `headers_commission_outputs` via a `type: "headers_commission"` input in a payment message — this is accepted uncritically by `inputs.js`/`writer.js` as legitimate spendable bytes, realizing the inflated supply as real value.

### Citations

**File:** validation.js (L1101-1126)
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
	cb();
}
```

**File:** headers_commission.js (L49-51)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
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

**File:** headers_commission.js (L199-205)
```javascript
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

**File:** inputs.js (L173-176)
```javascript
	function addHeadersCommissionInputs(){
		addMcInputs("headers_commission", HEADERS_COMMISSION_INPUT_SIZE + (bWithKeys ? HEADERS_COMMISSION_INPUT_KEYS_SIZE : 0),
			headers_commission.getMaxSpendableMciForLastBallMci(last_ball_mci), addWitnessingInputs);
	}
```

**File:** balances.js (L162-201)
```javascript
function readAllUnspentOutputs(exclude_from_circulation, handleSupply) {
	if (!exclude_from_circulation)
		exclude_from_circulation = [];
	var supply = {
		addresses: 0,
		txouts: 0,
		total_amount: 0,
		circulating_txouts: 0,
		circulating_amount: 0,
		headers_commission_amount: 0,
		payload_commission_amount: 0,
	};
	db.query(`SELECT address, COUNT(*) AS count, SUM(amount) AS amount
		FROM outputs
		CROSS JOIN units USING(unit)
		WHERE is_spent=0 AND asset IS NULL AND units.sequence='good'
		GROUP BY address`,
		function (rows) {
		if (rows.length) {
			supply.addresses += rows.length;
			rows.forEach(function(row) {
				supply.txouts += row.count;
				supply.total_amount += row.amount;
				if (!exclude_from_circulation.includes(row.address)) {
					supply.circulating_txouts += row.count;
					supply.circulating_amount += row.amount;
				}
			});
		}
		db.query('SELECT "headers_commission_amount" AS amount_name, SUM(amount) AS amount FROM headers_commission_outputs WHERE is_spent=0 UNION SELECT "payload_commission_amount" AS amount_name, SUM(amount) AS amount FROM witnessing_outputs WHERE is_spent=0;', function(rows) {
			if (rows.length) {
				rows.forEach(function(row) {
					supply.total_amount += row.amount;
					supply.circulating_amount += row.amount;
					supply[row.amount_name] += row.amount;
				});
			}
			handleSupply(supply);
		});
	});
```
