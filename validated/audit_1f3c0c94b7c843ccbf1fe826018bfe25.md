### Title
`headers_commission`/`witnessing` input range validation lets a unit poster permanently strand their own accrued commission — (File: `validation.js`, `mc_outputs.js`)

### Summary
The `setReplenishingIndex` bug freezes unclaimed funds because the contract enforces that an admin-controlled index can only move forward, with no way to reclaim value that falls behind it once the index is advanced too far. `ocore` has the same one-directional-index freeze pattern in the `headers_commission`/`witnessing` input validation path, except the "operator" here is any ordinary unit-posting address spending its own header/witnessing commission earnings: once it commits an input whose `to_main_chain_index` skips ahead of its true next claimable index, all commission income in the skipped range becomes permanently unclaimable.

### Finding Description
When an address wants to spend accrued header-commission or witnessing income, it posts a payment unit with an input of `type: "headers_commission"` or `"witnessing"` specifying `from_main_chain_index` and `to_main_chain_index` [1](#0-0) . Validation computes the address's `next_spendable_mc_index` by looking at the maximum `to_main_chain_index` ever used in a non-`final-bad` input of that type for that address, and requires the new `from_main_chain_index` to be `>=` that value: [2](#0-1) [3](#0-2) 

The code comment explicitly acknowledges that gaps are possible ("gaps allowed, in case a unit becomes bad due to another address being nonserial") but provides no mechanism to go back and claim a skipped range once `next_spendable_mc_index` has moved past it — the index is monotonic and never decreases, exactly like `replenishingIndex` in the original report. There is no admin fix or protocol-level correction path for this: `readNextSpendableMcIndex` always takes `MAX(to_main_chain_index)+1` regardless of any gap left behind [2](#0-1) .

### Impact Explanation
Any address that (through a hand-crafted transaction, a buggy wallet/composer, or a misjudged manual claim) posts a `headers_commission` or `witnessing` input with a `to_main_chain_index` set too high — skipping mci ranges it had not yet actually claimed — permanently and irrecoverably loses access to the commission/witnessing income accrued in the skipped mci range. The `headers_commission_outputs`/`witnessing_outputs` for that range remain marked unspent in the DB, but no future input for that address can ever have a `from_main_chain_index` low enough to reach them, since `next_spendable_mc_index` only ratchets forward. This is a direct, protocol-enforced fund freeze with no recovery path, matching the "unclaimed tokens frozen forever" bug class.

### Likelihood Explanation
Any unprivileged unit poster can trigger this simply by composing a payment with a `headers_commission`/`witnessing` input whose `to_main_chain_index` is set beyond the truly-owed range (e.g., due to a bug in commission-claiming logic, a race in a wallet computing the range, or a manual/advanced transaction). Since the mistake is silent — the transaction validates successfully (`ranges must not overlap` is the only rejection, not "range starts too optimistically") — and the range check only protects against overlaps/double-spends, not gaps, this can realistically occur without any malicious intent.

### Recommendation
Add validation to reject claims whose `from_main_chain_index` leaves an unclaimed gap unless that gap is provably unclaimable (e.g., due to the documented nonserial exception), or provide an explicit mechanism/opcode allowing an address to still claim earlier skipped ranges even after a later range has been spent, rather than only enforcing forward-only progress based on the maximum `to_main_chain_index` ever used.

### Proof of Concept
1. Address `A` accrues header-commission outputs at `main_chain_index` 100–200.
2. `A` posts a unit with a `headers_commission` input `{from_main_chain_index: 190, to_main_chain_index: 200}`, intending to claim only the tail but mistakenly (or via a buggy composer) skipping 100–189.
3. `mc_outputs.readNextSpendableMcIndex` now returns `201` as the next spendable index for `A` for that type [2](#0-1) .
4. Any subsequent attempt by `A` to claim `main_chain_index` 100–189 fails validation because `input.from_main_chain_index < next_spendable_mc_index` [4](#0-3) .
5. The commission income for mci 100–189 is permanently unclaimable by `A`, with no protocol-level recovery.

### Citations

**File:** validation.js (L2542-2553)
```javascript
					if (hasFieldsExcept(input, ["type", "from_main_chain_index", "to_main_chain_index", "address"]))
						return cb("unknown fields in witnessing input");
					if (!isNonnegativeInteger(input.from_main_chain_index))
						return cb("from_main_chain_index must be nonnegative int");
					if (!isNonnegativeInteger(input.to_main_chain_index))
						return cb("to_main_chain_index must be nonnegative int");
					if (input.from_main_chain_index > input.to_main_chain_index)
						return cb("from_main_chain_index > input.to_main_chain_index");
					if (input.to_main_chain_index > objValidationState.last_ball_mci)
						return cb("to_main_chain_index > last_ball_mci");
					if (input.from_main_chain_index > objValidationState.last_ball_mci)
						return cb("from_main_chain_index > last_ball_mci");
```

**File:** validation.js (L2579-2586)
```javascript
					mc_outputs.readNextSpendableMcIndex(conn, type, address, objValidationState.arrConflictingUnits, function(next_spendable_mc_index){
						if (input.from_main_chain_index < next_spendable_mc_index)
							return cb(type + " ranges must not overlap"); // gaps allowed, in case a unit becomes bad due to another address being nonserial
						var max_mci = (type === "headers_commission") 
							? headers_commission.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci)
							: paid_witnessing.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci);
						if (input.to_main_chain_index > max_mci)
							return cb(type+" to_main_chain_index is too large");
```

**File:** mc_outputs.js (L13-32)
```javascript
function readNextSpendableMcIndex(conn, type, address, arrConflictingUnits, handleNextSpendableMcIndex){
	conn.query(
		"SELECT to_main_chain_index FROM inputs CROSS JOIN units USING(unit) \n\
		WHERE type=? AND address=? AND sequence!='final-bad' "+(
			(arrConflictingUnits && arrConflictingUnits.length > 0) 
			? " AND unit NOT IN("+arrConflictingUnits.map(function(unit){ return db.escape(unit); }).join(", ")+") " 
			: ""
		)+" \n\
		ORDER BY to_main_chain_index DESC LIMIT 1", 
		[type, address],
		function(rows){
			var mci = (rows.length > 0) ? (rows[0].to_main_chain_index+1) : 0;
		//	readNextUnspentMcIndex(conn, type, address, function(next_unspent_mci){
		//		if (next_unspent_mci !== mci)
		//			throw Error("next unspent mci !== next spendable mci: "+next_unspent_mci+" !== "+mci+", address "+address);
				handleNextSpendableMcIndex(mci);
		//	});
		}
	);
}
```
