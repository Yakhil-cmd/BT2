Based on my research, I found a legitimate analog to the Buck rounding-down bug class in `ocore`'s TPS-fee credit accounting.

### Title
`updateTpsFees()` floors TPS-fee credit distribution, causing permanent under-crediting of prepaid TPS fees - (File: storage.js)

### Summary
`storage.js`'s `updateTpsFees()` reconciles the TPS fee a unit's author actually paid against the final (lower) fee determined once the unit is stable, and credits the difference back to the paying address(es) via `tps_fees_balances`. When a unit has multiple fee-share recipients (via `earned_headers_commission_recipients`), the per-recipient credit is computed with `Math.floor(total_tps_fees_delta * share / 100)`, which — like `BuckV2.updateYieldRate()`'s `(unvestedYieldBps * elapsed) / currentVestDuration`, always rounds toward zero and never compensates the truncated remainder. [1](#0-0) 

### Finding Description
`getFinalTpsFee()` recomputes the true TPS fee owed for a unit once it stabilizes, which is normally lower than the fee the author paid up-front (since up-front payment must conservatively account for possible competing parallel branches that get pruned once finality narrows the DAG). The difference (`total_tps_fees_delta`, usually positive — a refund) is split among fee-paying recipients determined by `getTpsFeeRecipients()`/`earned_headers_commission_recipients` and each recipient's credit is truncated with `Math.floor`: [2](#0-1) 

Every truncated remainder (up to `share/100` of a byte per recipient per unit, and up to 99 out of 100 shares' worth when several recipients split unevenly) is silently discarded — it is added to nobody's `tps_fees_balances` and never carried forward, exactly analogous to the reported Buck issue where `vestedFromStream = (unvestedYieldBps * elapsed) / currentVestDuration` truncates and the remainder is lost rather than deferred. Because every stable unit that pays a TPS fee and every multi-recipient split goes through this same floor operation, the loss compounds continuously over the life of the network for any address that regularly co-authors units or shares header-commission/tps-fee credit with others.

This credit is directly consumed later in `validateTpsFee()` and `getPaidTpsFee()`, where `tps_fees_balance` is read back and divided by `share` to determine whether a new unit's TPS fee payment (combined with balance) satisfies the currently required minimum: [3](#0-2) [4](#0-3) 

A permanently under-credited balance means the address in question is forced to overpay on every subsequent unit relative to what it should owe given its actual TPS history, i.e., a real, measurable and irreversible loss of prepaid bytes for the affected address(es), with no path to reclaim the truncated remainder.

### Impact Explanation
Unlike the `Math.round()` used elsewhere for headers/witnessing commission distribution (which is unbiased), `Math.floor()` here is systematically one-directional: it always reduces the credit given back to fee payers, never increases it. Every stable unit created after `constants.v4UpgradeMci` that has `earned_headers_commission_recipients` (a normal, unprivileged, user-controlled unit field) triggers this code path, so any ordinary unit author or AA-address whose fee credit is split across several addresses will have their genuine, correctly-computed refund silently truncated on every single unit, forever. This is a sustained economic loss to ordinary network participants analogous in structure and severity to the reported Buck issue (loss of legitimately owed value due to floor-rounding in a repeatedly-invoked accounting update).

### Likelihood Explanation
This triggers automatically and deterministically on every stabilized unit with TPS-fee accounting and multiple fee-share recipients — no attacker action or malicious input is required beyond normal, legitimate use of the `earned_headers_commission_recipients` feature (which any unpriviledged unit poster can set). The loss is guaranteed to occur every time and accumulates continuously as the network processes units.

### Recommendation
Track and carry forward the fractional remainder from `Math.floor(total_tps_fees_delta * share / 100)` (e.g., accumulate a per-address remainder and add it back once it reaches a whole byte), or switch to an unbiased/rounded distribution (as is already done in `headers_commission.js`/`paid_witnessing.js` via `Math.round`) so truncation doesn't systematically favor the network over fee payers.

### Proof of Concept
1. Author a unit whose `earned_headers_commission_recipients` splits fee credit across, e.g., 3 addresses with shares 34/33/33.
2. Let the unit stabilize such that `getFinalTpsFee()` yields a `total_tps_fees_delta` of, say, 10 (a legitimate 10-byte refund).
3. `updateTpsFees()` computes `Math.floor(10*34/100)=3`, `Math.floor(10*33/100)=3`, `Math.floor(10*33/100)=3` — total credited = 9, one byte permanently lost instead of credited to any address.
4. Repeat across the many units such an address co-authors/receives shares from over time; the cumulative uncredited amount grows without bound and is never recoverable via any protocol mechanism.

### Citations

**File:** storage.js (L1257-1272)
```javascript
			const tps_fee = getFinalTpsFee(objUnitProps) * (1 + (objUnitProps.count_aa_responses || 0));
			await conn.query("UPDATE units SET actual_tps_fee=? WHERE unit=?", [tps_fee, objUnitProps.unit]);
			const total_tps_fees_delta = (objUnitProps.tps_fee || 0) - tps_fee; // can be negative
			//	if (total_tps_fees_delta === 0)
			//		continue;
			/*	const recipients = (objUnitProps.assocEarnedHeadersCommissionRecipients && total_tps_fees_delta < 0)
					? storage.getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses)
					: (objUnitProps.assocEarnedHeadersCommissionRecipients || { [objUnitProps.author_addresses[0]]: 100 });*/
			const recipients = getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses);
			for (let address in recipients) {
				const share = recipients[address];
				const tps_fees_delta = Math.floor(total_tps_fees_delta * share / 100);
				const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, mci]);
				const tps_fees_balance = row ? row.tps_fees_balance : 0;
				await conn.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", [address, mci, tps_fees_balance + tps_fees_delta]);
			}
```

**File:** storage.js (L1430-1440)
```javascript
	const recipients = getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses);
	let min_tps_fee = Infinity;
	for (let address in recipients) {
		const share = recipients[address] / 100;
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		const tps_fee = tps_fees_balance / share + objUnitProps.tps_fee;
		if (tps_fee < min_tps_fee)
			min_tps_fee = tps_fee;
	}
	return min_tps_fee;
```

**File:** validation.js (L1082-1090)
```javascript
	for (let address in recipients) {
		const share = recipients[address] / 100;
		if (!share)
			throw Error(`invalid share for address ${address}: ${share}`);
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
		const tps_fee = tps_fees_balance / share + objUnit.tps_fee;
```
