### Title
Retroactive/"ticking" TPS-fee settlement lets an attacker post-hoc spike congestion to drive a victim's `tps_fees_balance` negative and freeze the victim's ability to post further units - ([File: storage.js])

### Summary
Obyte's v4.0 congestion-fee model prices each unit at composition time using a *locally observable* estimate of throughput (`getLocalTpsFee`), but the fee that is actually owed is only settled after the unit's MCI stabilizes, using the *network-wide, final* throughput measured over that MCI window (`getFinalTpsFee`). The difference between what was paid and what is finally owed is applied to a running per-address balance (`tps_fees_balance`) that can go arbitrarily negative and must be repaid by future units from that address before they are accepted. This is structurally the same bug class as the reported "ticking interest rate": a state variable (owed fee / effective collateral margin) is recomputed deterministically as chain-time advances, and anyone can cheaply manipulate the metric that will apply retroactively to someone else's already-broadcast, unconfirmed transaction, damaging that victim's position at the very next confirmation.

### Finding Description
When a unit is composed, the wallet computes and pays `tps_fee` based on `getLocalTpsFee`, which measures tps deterministically from the unstable DAG up to that point plus `count_units`: [1](#0-0) 

Later, once the unit's MCI stabilizes, `updateTpsFees` recomputes the fee that should actually have been paid using `getFinalTpsFee`, which uses the *final* measured tps for that MCI (a quantity that depends on everything else that got confirmed in the same window, not just the unit's own local view): [2](#0-1) 

The delta between what was paid (`objUnitProps.tps_fee`) and what was finally owed (`tps_fee`) is applied to `tps_fees_balance`, which "can be negative": [3](#0-2) [4](#0-3) 

This negative balance is not merely informational — it is enforced as a hard validation gate on the address's *next* unit. `validateTpsFee` requires `tps_fees_balance + objUnit.tps_fee*share >= min_tps_fee*share`, i.e. any accumulated deficit must be paid off (with a permanent rejection, not a soft/transient one) before a new unit from the same author is accepted: [5](#0-4) 

Because the "final" congestion figure that determines the retroactive fee is a function of *everyone's* activity within the same MCI window (not just the fee-payer's own unit), any unprivileged unit poster can flood the DAG with many low-value units immediately after a victim's transaction has picked its parents/tps estimate but before that MCI stabilizes. This inflates `getFinalTps`/`getFinalTpsFee` for the window that ends up containing the victim's unit, which was priced against a much lower tps estimate. The victim's `tps_fees_balance` is pushed deeply negative by `updateTpsFees` once the MCI actually stabilizes — a state change that occurs one MC-stabilization "tick" after the victim posted their unit, exactly mirroring the interest-rate tick in the original report that predictably degrades a position the very next block.

### Impact Explanation
The victim's subsequent unit(s) will fail the hard check in `validateTpsFee` (line 1088-1089) until the deficit is repaid, i.e. the address is effectively locked out of confirming new units on the network until it pays extra tps fee to cover a deficit it did not itself cause. This is a concrete "network unable to confirm new units" / fund-freezing condition for the targeted address, imposed purely by an attacker's ability to retroactively inflate a chain-wide metric that a third party's already-broadcast, unconfirmed unit is graded against. An attacker can perform this cheaply and repeatedly against any address whose pending unit they can observe (all pending units are gossiped pre-stabilization), and because OPs are exempted from the soft multiplier check (`bFromOP`) while ordinary users are not, the attack is asymmetric and can be used to grief specific competitors/AA counterparties.

### Likelihood Explanation
The primary ingredients — observing another address's pending unit, and flooding cheap units before the enclosing MCI stabilizes — are both actions available to any unprivileged node/wallet; no special privilege, witness/OP status, or protocol upgrade is required beyond mci ≥ `v4UpgradeMci` (TPS-fee model already active). The attack only needs to win a timing race against MC stabilization, which is a normal, repeatable operation, making this a medium-likelihood, low-cost griefing vector rather than a one-off exploit.

### Recommendation
- Do not let a unit's fee obligation depend on activity that occurs *after* the unit was created/broadcast; settle `tps_fee` using only information knowable and fixed at the unit's own last_ball/parent-selection time (i.e., make `getFinalTpsFee` a function of data available no later than the unit's own composition, not of the full stabilized MCI window that can include units the payer never anticipated).
- Alternatively, cap the magnitude of `total_tps_fees_delta` per unit/per MCI so that a single burst of third-party traffic cannot drive an unrelated address's `tps_fees_balance` deeply negative in one settlement.
- Make the deficit-repayment check in `validateTpsFee` transient/soft (as is already done for `min_acceptable_tps_fee`) rather than a hard, permanent rejection, so a temporary spike cannot indefinitely freeze an address's ability to transact.

### Proof of Concept
1. Address V composes and broadcasts unit U, paying `tps_fee` computed by `getLocalTpsFee` based on the tps observed in the DAG at that moment (composer.js `estimateTpsFee`/`getTpsFee` path).
2. Before U's MCI stabilizes, attacker A rapidly broadcasts many cheap units (paying only their own local, still-low, tps fee) that land in the same MCI window as U.
3. When the MCI stabilizes, `updateTpsFees` (storage.js:1247-1275) computes `getFinalTpsFee` for U using the now much higher final tps for that MCI (inflated by A's flood), producing a large negative `total_tps_fees_delta` and driving V's `tps_fees_balance` negative (storage.js:1259-1271).
4. V's next unit is checked in `validateTpsFee` (validation.js:1082-1090); because `tps_fees_balance` is very negative, the hard condition `tps_fees_balance + objUnit.tps_fee*share < min_tps_fee*share` triggers, and V's unit is permanently rejected until V pays off the attacker-induced deficit — a "recovery-mode"-style, next-block imposed penalty triggered by a third party's cheap action.

### Citations

**File:** storage.js (L1238-1275)
```javascript
function getFinalTpsFee(objUnitProps) {
	const mci = objUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', mci); // not at last_ball_mci
	const tps_interval = getSystemVar('tps_interval', mci);
	const tps = getFinalTps(objUnitProps);
	console.log(`final tps at ${objUnitProps.unit} ${tps}`);
	return Math.round(base_tps_fee * (exp(tps / tps_interval) - 1));
}

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
}
```

**File:** storage.js (L1339-1349)
```javascript
async function getLocalTpsFee(conn, objUnitProps, count_units = 1) {
	const objLastBallUnitProps = await readUnitProps(conn, objUnitProps.last_ball_unit);
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', last_ball_mci); // unit's mci is not known yet
	const tps_interval = getSystemVar('tps_interval', last_ball_mci);
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_ball_mci);
	const tps = await getLocalTps(conn, objUnitProps, count_units);
	console.log(`local tps at ${objUnitProps.unit} ${tps}`);
	const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (exp(tps / tps_interval) - 1));
	return count_units * tps_fee_per_unit;
}
```

**File:** initial-db/byteball-sqlite.sql (L1001-1007)
```sql
CREATE TABLE tps_fees_balances (
	address CHAR(32) NOT NULL,
	mci INT NOT NULL,
	tps_fees_balance INT NOT NULL DEFAULT 0, -- can be negative
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (address, mci DESC)
);
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
