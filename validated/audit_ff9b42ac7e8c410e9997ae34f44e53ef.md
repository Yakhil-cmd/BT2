### Title
Unbounded retroactive TPS-fee debt from delayed unit stabilization forces senders to overpay unknown future fees - (File: storage.js)

### Summary
In ocore's v4.0 TPS-fee mechanism, the fee a sender actually commits to when composing a unit (`objUnit.tps_fee`) is estimated from network conditions *at composition time*, while the fee that is ultimately charged (`actual_tps_fee`) is computed later, only after the unit's main-chain index becomes stable, based on the *final* network throughput observed over that period. Because stabilization can happen an unpredictable amount of time after broadcast (analogous to `Flip.sol`'s `gameStartTime` vs. actual mining time), the sender has no way to bound or cap the fee they will ultimately be charged — the shortfall is silently added as debt against their address and collected from *future* transactions.

### Finding Description
When composing a unit, the paid `tps_fee` is derived from `parentComposer.getTpsFee`/`storage.getLocalTpsFee`, which estimates throughput using the state at the chosen `last_ball_mci` [1](#0-0) . Validators then apply a live, congestion-sensitive check in `validateTpsFee`, comparing the paid fee against `current_tps_fee`/`min_acceptable_tps_fee` [2](#0-1) .

However, the fee that is truly deducted from the address's `tps_fees_balance` is only computed once the unit's MCI is finally stabilized, via `getFinalTpsFee`/`getFinalTps` in `updateTpsFees`, which counts *all* units that ended up sharing that MCI window — a number that cannot be known at composition time and can only grow while the unit sits unconfirmed: [3](#0-2) 

`updateTpsFees` then computes the delta between what was paid and what is finally owed, and applies it — even when negative — to the address's persistent `tps_fees_balance`: [4](#0-3) 

This negative delta (unpaid debt) is not bounded or capped, and there is no "deadline" parameter or user-controlled ceiling on how much this deficit can grow while the unit is delayed on its way to stabilization (e.g., due to a temporary throughput spike from other traffic). The debt is silently carried forward and enforced against the same address's *future* units in `validateTpsFee`, which rejects a new unit unless the account's cumulative deficit plus the newly offered fee clears the then-current minimum: [5](#0-4) 

The root cause mirrors the reported bug class exactly: a monetary parameter (`fee`) is fixed based on state observed when the transaction is initiated, but the transaction is not guaranteed to execute (stabilize) at that state — it can be delayed by network conditions outside the sender's control — and there is no deadline/cap mechanism to protect the sender from being charged for conditions that arose only after they committed funds.

### Impact Explanation
An honest, unprivileged unit poster can be charged materially more than the fee they explicitly paid and had no way to predict, purely because of delay before their unit's MCI stabilizes (e.g., a burst of other units/AA responses sharing that window). This deficit is not user-approved and is collected coercively from that address's subsequent transactions via the `tps_fees_balance`/`validateTpsFee` gate, which can also block confirmation of future units from that address until the deficit is paid down. This is a fund-loss / fee-manipulation impact directly analogous to the referenced report's "higher fees than the player initially anticipated," scoped entirely within core consensus/validation code rather than any application layer.

### Likelihood Explanation
This requires no attacker action — it can occur under normal network congestion whenever the interval between a unit's broadcast (its `last_ball_mci` snapshot) and its stabilization sees increased throughput from unrelated traffic. Since MCI stabilization timing is inherently variable and outside any single sender's control, this condition is readily reachable by any unit poster during periods of load, making the likelihood moderate to high, though the resulting cost is speculative/statistical rather than deterministic.

### Recommendation
Cap the retroactive `actual_tps_fee` a sender can be charged relative to what they explicitly declared as acceptable at composition, and/or eliminate open-ended retroactive debt collection. Concretely: 
- Allow the composed unit to declare a maximum acceptable `tps_fee` (a "fee ceiling"), similar to the recommended `deadline` parameter, and refuse to charge (or bounce/void) beyond that ceiling rather than silently carrying the shortfall as debt against the address's future transactions in `storage.js`'s `updateTpsFees`.
- Alternatively, bound how negative `tps_fees_balance` can go per address/per unit, and communicate the risk explicitly instead of enforcing it transparently through `validateTpsFee`'s future-unit checks.

### Proof of Concept
1. Address A composes and broadcasts a unit U at time T0, referencing `last_ball_mci = M`. At this point `storage.getLocalTpsFee` estimates a low tps and A pays `tps_fee = F1` [1](#0-0) .
2. Before U's MCI stabilizes, a burst of unrelated units/AA responses is posted, raising the final observed tps for that MCI window.
3. Once U's MCI stabilizes, `updateTpsFees` computes `actual_tps_fee = getFinalTpsFee(...)`, which is now `F2 > F1` due to the higher final tps [6](#0-5) .
4. `total_tps_fees_delta = F1 - F2 < 0` is added to A's `tps_fees_balance`, going negative [7](#0-6) .
5. A's next unit V is validated: `validateTpsFee` checks `tps_fees_balance + objUnit.tps_fee*share < min_tps_fee*share`; because of the negative balance carried from step 4, A must now pay significantly more tps_fee than otherwise required, or V is rejected as underpaying [5](#0-4) , all without A ever having agreed to or been able to cap this outcome when U was originally composed.

### Citations

**File:** composer.js (L374-391)
```javascript
					if (last_ball_mci >= constants.v4UpgradeMci) {
						const rows = await conn.query("SELECT 1 FROM aa_addresses WHERE address IN (?)", [arrOutputAddresses]);
						const count_primary_aa_triggers = rows.length;
						const tps_fee = await parentComposer.getTpsFee(conn, arrParentUnits, last_stable_mc_ball_unit, objUnit.timestamp, 1 + count_primary_aa_triggers * max_aa_responses);
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

**File:** validation.js (L1050-1096)
```javascript
async function validateTpsFee(conn, objJoint, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || !objValidationState.last_ball_mci)
		return callback();
	const objUnit = objJoint.unit;
	if (objValidationState.bAA) {
		if ("tps_fee" in objUnit)
			return callback("tps_fee in AA response");
		return callback();
	}
	if ("content_hash" in objUnit) // tps_fee and other unit fields have been already stripped
		return callback();
	const objUnitProps = {
		unit: objUnit.unit,
		parent_units: objUnit.parent_units,
		best_parent_unit: objValidationState.best_parent_unit,
		last_ball_unit: objUnit.last_ball_unit,
		timestamp: objUnit.timestamp,
		count_primary_aa_triggers: objValidationState.count_primary_aa_triggers,
		max_aa_responses: objUnit.max_aa_responses,
	};
	const count_units = storage.getCountUnitsPayingTpsFee(objUnitProps);
	const min_tps_fee = await storage.getLocalTpsFee(conn, objUnitProps, count_units);
	console.log('validation', {min_tps_fee}, objUnitProps)
	
	// compare against the current tps fee or soft-reject
	const current_tps_fee = objJoint.ball ? 0 : storage.getCurrentTpsFee(0, count_units); // very low while catching up
	const min_acceptable_tps_fee_multiplier = objJoint.ball ? 0 : storage.getMinAcceptableTpsFeeMultiplier();
	const min_acceptable_tps_fee = current_tps_fee * min_acceptable_tps_fee_multiplier * count_units;

	const author_addresses = objUnit.authors.map(a => a.address);
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
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

**File:** storage.js (L1238-1272)
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
```
