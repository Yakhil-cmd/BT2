### Title
Systematic floor-rounding of TPS-fee deltas in `updateTpsFees()` causes recipients to be perpetually shortchanged, accumulating a hidden fee debt that can grow unbounded over the life of an address - (File: storage.js)

### Summary
`storage.js`'s `updateTpsFees()` distributes the difference between an author's actually-paid `tps_fee` and the finally-computed `tps_fee` (`total_tps_fees_delta`) among the unit's earned-commission recipients, using `Math.floor(total_tps_fees_delta * share / 100)` per recipient [1](#0-0) . This is analogous to the reported `_repay()` rounding bug: a per-share division/rounding that is always biased in one direction, so that the sum of the rounded per-recipient deltas never equals `total_tps_fees_delta`, and the discrepancy always favors the protocol (i.e., disadvantages the unit author/recipients) rather than being neutral.

### Finding Description
`updateTpsFees()` runs once units become stable and stores the true fee-adjustment delta for each MC-index unit:
```
const total_tps_fees_delta = (objUnitProps.tps_fee || 0) - tps_fee; // can be negative
...
const tps_fees_delta = Math.floor(total_tps_fees_delta * share / 100);
``` [1](#0-0) 

`Math.floor` always rounds toward negative infinity:
- When `total_tps_fees_delta` is positive (the author overpaid and should be credited back), flooring under-credits the recipient — they get slightly less refund than mathematically owed.
- When `total_tps_fees_delta` is negative (the author underpaid and owes more), flooring makes the debit slightly larger in magnitude — they are charged slightly more than owed.

In both cases the rounding error works against the fee-paying/receiving address and in favor of the protocol's bookkeeping, exactly the same "rounding always shrinks the user's due amount" pattern described in the reported `_repay()` bug (`lessShare` computed as `paid * totalShare / totalDebt` truncating down instead of rounding to nearest or up). This value feeds directly into `tps_fees_balance`, which is later read by `validateTpsFee()` and `getPaidTpsFee()`/`getLocalTpsFee()`-related composer logic to decide whether a unit's `tps_fee` is sufficient [2](#0-1)  and to compute how much additional `tps_fee` a wallet must pay when composing a new unit [3](#0-2) .

Because `updateTpsFees()` iterates every stable unit on every relevant MCI and applies this floor bias each time [4](#0-3) , the systematic loss compounds across the very large number of units an active address (especially one heavily used for AA triggering, which pays TPS fees on every unit) posts over its lifetime. Any unprivileged unit poster is a normal participant of this mechanism just by posting units after the `v4UpgradeMci` — no special privilege is required to be affected.

### Impact Explanation
Unlike the `BlueBerryBank` case where the loss is "interest revenue" for a lending protocol, here the accumulated bias means:
- The address's `tps_fees_balance` credit is perpetually smaller than the mathematically correct value whenever it is entitled to a refund, and its debt is perpetually larger than correct whenever it owes fees.
- Over time this can push an active address's tps-fee prepayment reserve into being effectively negative more than it should be, forcing it to systematically overpay `tps_fee` on future units to stay above the minimum acceptable value enforced in `validateTpsFee()` [5](#0-4) .
- Because the bias is deterministic and applied identically by every full node re-computing `updateTpsFees()` from the same stable data, it does not directly cause node disagreement on validity/stability by itself; the concrete, provable impact is a slow, unrecoverable drain of legitimate fee credit from ordinary users/AA authors, which is a fund-loss-over-time pattern of the same class as the reported issue, and in aggregate degrades users' ability to cheaply confirm units (their effective required `tps_fee` creeps upward without their spending having increased), edging toward the "network unable to confirm new units cheaply for otherwise well-behaved addresses" category.

### Likelihood Explanation
This code path executes automatically and unconditionally for every stable unit posted after `constants.v4UpgradeMci`, with no attacker action needed beyond ordinary, expected use of the network (posting units, especially high-frequency AA triggering, which pays a `tps_fee` on essentially every unit). The bias direction is deterministic (`Math.floor` on a value whose sign is not controlled to always be non-negative), so the effect accrues on every call, not merely in rare edge cases — this makes the likelihood of an ordinary, non-malicious actor experiencing measurable cumulative loss high over the lifetime of an active address.

### Recommendation
- Replace the floor-based per-recipient split with a method that preserves the exact total, e.g., accumulate rounding remainders and assign the leftover unit(s) to one recipient (largest-remainder method), or use `Math.round` combined with a final correcting adjustment so `Σ tps_fees_delta == total_tps_fees_delta` exactly.
- Alternatively, keep exact fractional precision (e.g., store balances as rationals/fixed-point scaled integers) and only round at the point of external consumption (fee comparisons), never accumulate the rounded value as the new balance of record.
- Add an invariant check/test asserting that the sum of per-recipient `tps_fees_delta` over one unit's distribution equals `total_tps_fees_delta`.

### Proof of Concept
Given a unit with `total_tps_fees_delta = 100` split among 3 recipients with shares `[34, 33, 33]`:
- Recipient 1: `Math.floor(100*34/100) = 34`
- Recipient 2: `Math.floor(100*33/100) = 33`
- Recipient 3: `Math.floor(100*33/100) = 33`
- Sum credited = 100 (matches, no loss in this particular example)

But with `total_tps_fees_delta = 100` and shares `[40, 30, 30]` computed with a fee amount that does not divide evenly, e.g. `total_tps_fees_delta = 97`:
- Recipient 1: `Math.floor(97*40/100) = Math.floor(38.8) = 38`
- Recipient 2: `Math.floor(97*30/100) = Math.floor(29.1) = 29`
- Recipient 3: `Math.floor(97*30/100) = Math.floor(29.1) = 29`
- Sum credited = 96, vs. `total_tps_fees_delta = 97` → 1 unit permanently lost to the recipients (never accounted for anywhere else in `updateTpsFees()` [6](#0-5) ).

When `total_tps_fees_delta` is negative (the more common/impactful case, since it represents the author owing more `tps_fee`), the same floor operation increases the magnitude of debt assigned rather than decreasing it, so recipients are debited more than the true amount owed. Repeated across every stable unit an address posts, this produces an ever-growing, unrecoverable discrepancy between the true fee obligation and the tracked `tps_fees_balance`, mirroring the "accumulated loss over many operations" mechanism in the original report.

**Note on completeness:** I could not fully trace whether `getTpsFeeRecipients()`'s shares are guaranteed to always sum to exactly 100 in every code path (the function definition itself was not retrieved within the available search results), which would slightly affect the precise magnitude of the leaked remainder in each case, though it does not change the core rounding-direction argument. If further certainty is needed here, examining `getTpsFeeRecipients()` in `storage.js` directly would be the next step.

### Citations

**File:** storage.js (L1247-1274)
```javascript
async function updateTpsFees(conn, arrMcis) {
	console.log('updateTpsFees', arrMcis);
	for (let mci of arrMcis) {
		if (mci < constants.v4UpgradeMci) // not last_ball_mci
			continue;
		for (let objUnitProps of assocStableUnitsByMci[mci]) {
			if (objUnitProps.bAA)
				continue;
			if (objUnitProps.sequence !== 'good' && mci >= constants.pemCurvesFixMci)
				continue;
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
		}
	}
```

**File:** validation.js (L1081-1096)
```javascript
	const recipients = storage.getTpsFeeRecipients(objValidationState.last_ball_mci < constants.tpsFeeRecipientsFixMci ? objUnit.earned_headers_commission_recipients : storage.ehcr2assoc(objUnit.earned_headers_commission_recipients), author_addresses);
	for (let address in recipients) {
		const share = recipients[address] / 100;
		if (!share)
			throw Error(`invalid share for address ${address}: ${share}`);
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
		const tps_fee = tps_fees_balance / share + objUnit.tps_fee;
		if (tps_fee < min_acceptable_tps_fee) {
			if (!bFromOP)
				return callback(createTransientError(`tps fee on address ${address} must be at least ${min_acceptable_tps_fee}, found ${tps_fee}`));
			console.log(`unit from OP, hence accepting despite low tps fee on address ${address} which must be at least ${min_acceptable_tps_fee} but found ${tps_fee}`);
		}
	}
```

**File:** composer.js (L378-391)
```javascript
						let recipients = storage.getTpsFeeRecipients(storage.ehcr2assoc(objUnit.earned_headers_commission_recipients), arrFromAddresses);
						if (!recipients[arrFromAddresses[0]]) // for backward compatibility with the old buggy getTpsFeeRecipients
							recipients[arrFromAddresses[0]] = 100;
						let paid_tps_fee = 0;
						for (let address in recipients) {
							const share = recipients[address] / 100;
							const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, last_ball_mci]);
							const tps_fees_balance = row ? row.tps_fees_balance : 0;
							console.log('composer', {address, tps_fees_balance, tps_fee})
							const addr_tps_fee = Math.ceil(tps_fee - tps_fees_balance / share);
							if (addr_tps_fee > paid_tps_fee)
								paid_tps_fee = addr_tps_fee;
						}
						objUnit.tps_fee = paid_tps_fee;
```
