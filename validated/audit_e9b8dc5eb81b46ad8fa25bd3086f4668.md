## Title
Independent Per-Recipient Rounding in Headers-Commission Distribution Can Mint or Burn Bytes - (File: headers_commission.js)

### Summary
`ocore`'s headers-commission distribution logic splits a parent unit's `headers_commission` among multiple recipients declared via `earned_headers_commission_recipients` (a field an ordinary unit author fully controls when composing/posting a unit). Each recipient's share of the commission is computed **independently** with `Math.round(full_amount * share / 100.0)`. Because rounding is applied per-recipient rather than once with a remainder carried to the last recipient, the sum of the rounded per-recipient amounts is not guaranteed to equal the original `full_amount`. This is the same rounding-error bug class as in the external report's `estimateClaim`, where independent divisions of a shared pool cause the sum of parts to diverge from the whole.

### Finding Description
In `headers_commission.js`, when a child unit's author designates several `earned_headers_commission_recipients` (each with an integer `%` share, typically expected to sum to 100), the amount paid to each recipient is computed independently: [1](#0-0) [2](#0-1) 

For the SQL ("faster") code path the same independent-rounding pattern is used directly in the query: [3](#0-2) 

Each recipient amount is `Math.round(full_amount * share / 100.0)`. Because `Math.round` is applied separately to each recipient's fractional share, the **sum of all recipients' rounded amounts is not mathematically guaranteed to equal `full_amount`**. For example, with `full_amount = 100` and three recipients each holding a `33%`/`33%`/`34%` share:
- `Math.round(100*33/100) = 33`
- `Math.round(100*33/100) = 33`
- `Math.round(100*34/100) = 34`
Sum = 100 (fine in this case), but with less friendly numbers (e.g. `full_amount = 7`, shares `50/50`): `Math.round(7*50/100) = 4` and `Math.round(7*50/100) = 4`, giving a total of `8` — one byte more than `full_amount`. Conversely other share/amount combinations can produce a total less than `full_amount`.

These resulting amounts are inserted into `headers_commission_contributions` and later aggregated (via `SUM(amount)`) into `headers_commission_outputs`, which become directly spendable byte outputs: [4](#0-3) [5](#0-4) 

The `earned_headers_commission_recipients` field and its per-address shares are set by the unit's author at composition time and are validated only for structural correctness (address validity, share format) — there is no evidence in `validation.js` of a consensus check that individually-rounded recipient amounts must sum exactly back to the parent's `headers_commission`. This mirrors the Solidity `estimateClaim` bug: a value is split proportionally among stakeholders via independent divisions/roundings, with no correction to guarantee the total matches the source amount.

### Impact Explanation
Because `headers_commission_outputs` amounts feed directly into the base-currency (`bytes`) UTXO set that is spendable, any positive rounding drift constitutes minting of bytes that were never paid for by a corresponding fee/burn — a supply-inflation bug. Any negative drift constitutes silent loss of network-designated commission funds. Given the fixed, protocol-defined total byte supply, systematic upward drift (an attacker who authors many units with carefully chosen fractional `earned_headers_commission_recipients` splits, each of which nudges the rounding in their favor across a large number of headers-commission-winning units) could accumulate small amounts of unbacked byte creation over time. This affects consensus-relevant state (`headers_commission_outputs`), so if nodes computing this in "RAM"/"faster" mode versus the SQL-aggregate mode ever diverge in rounding behavior, it could also cause different nodes to disagree on account balances/spendable amounts.

### Likelihood Explanation
Any unpriviledged unit author can set `earned_headers_commission_recipients` with arbitrary integer share percentages across multiple addresses for their own unit when composing it. Whether that unit wins the headers-commission per-parent lottery depends on the deterministic SHA1-based selection among sibling child units, so an attacker does not have full control over *which* unit wins, but they do control the share split of any of *their own* candidate units, and posting many candidate units over time increases the chance that a "self-favoring" split occurs on a winning unit. The dust magnitude is small per occurrence (typically ≤1 unit per additional recipient), making this a low/medium-severity issue in isolation, though it is a legitimate rounding-error class defect consistent with the reported bug.

### Recommendation
When distributing `full_amount` (or `punits.headers_commission`) among multiple `earned_headers_commission_recipients`, compute all recipients' shares except the last with `Math.round`/`Math.floor`, then assign the **remainder** (`full_amount - sum_of_computed_shares`) to the last recipient (or to a designated "primary" recipient), guaranteeing the total distributed equals `full_amount` exactly. Apply the same fix consistently across the SQL query path (`headers_commission.js:49-56`) and the in-memory/RAM path (`headers_commission.js:180-204`) to avoid divergence between the two computation modes.

### Proof of Concept
1. A user composes a unit with `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]`.
2. This unit becomes the winning child of a parent unit whose `headers_commission` (i.e., `full_amount`) is `7` bytes (an odd number achievable via the deterministic headers-size-based commission).
3. `calcHeadersCommissions` computes, per [2](#0-1) : `Math.round(7*50/100) = 4` for A and `Math.round(7*50/100) = 4` for B.
4. Total distributed = `8`, one byte more than the parent's `headers_commission` of `7`, which is inserted into `headers_commission_outputs` and becomes spendable — an unbacked byte has been minted.

### Citations

**File:** headers_commission.js (L49-56)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
					FROM units AS chunits \n\
					JOIN earned_headers_commission_recipients USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
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

**File:** headers_commission.js (L212-214)
```javascript
								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
```

**File:** headers_commission.js (L222-227)
```javascript
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
```
