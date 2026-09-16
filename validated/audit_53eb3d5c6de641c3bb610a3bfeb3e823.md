### Title
Unit poster can pick a stale `last_ball_unit` to apply an outdated (lower) system-var fee schedule and underpay `oversize_fee`/`tps_fee` - ([File: validation.js], [File: storage.js])

### Summary
The Footium report describes a club choosing a favorable "state" (division tier) to pay a lower minting fee even though the fee should track the club's actual state at the relevant time. The structurally analogous pattern in ocore is that a unit's anti-spam fees (`oversize_fee`, `tps_fee`) are computed purely from system variables (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) looked up **at the unit's own `last_ball_mci`**, a value the unit author itself selects when composing the unit, rather than a value tied unambiguously to the network's real, current state.

### Finding Description
`storage.getOversizeFee(objUnitOrSize, mci, bAA)` derives the `threshold_size` via `getSystemVar('threshold_size', mci)` [1](#0-0)  and `storage.getLocalTpsFee`/`getFinalTpsFee` similarly pull `base_tps_fee`, `tps_interval`, `tps_fee_multiplier` via `getSystemVar(subject, mci)` [2](#0-1) . `getSystemVar` walks a list of `{vote_count_mci, value}` entries and returns the value whose `vote_count_mci` is below the supplied `mci` [3](#0-2) , meaning these parameters change over time via voting.

Validation of both fees is keyed off `objValidationState.last_ball_mci`, which is simply the `main_chain_index` of whatever `last_ball_unit` the unit author put in their own unit (checked only for internal consistency, not "freshness"): the oversize-fee check recomputes `storage.getOversizeFee(objUnit, objValidationState.last_ball_mci, objValidationState.bAA)` [4](#0-3) , and `validateTpsFee` computes `min_tps_fee` from `storage.getLocalTpsFee(conn, objUnitProps, count_units)` where `objUnitProps.last_ball_unit` is again taken directly from the submitted unit [5](#0-4) . The only bound enforced on `last_ball_mci` is an upper bound (`max_parent_limci < last_ball_mci` is rejected) [6](#0-5) ; there is no lower bound forcing the author to reference a recent stable ball. So an author is free to reference any older, still-stable `last_ball_unit` that satisfies the unrelated "unstable predecessors"/double-spend constraints, and thereby lock in whatever `threshold_size`/`base_tps_fee`/`tps_fee_multiplier` were in effect at that older mci instead of the values that should apply to the unit's actual (current) position in the DAG — mirroring the Footium bug where the fee is tied to a caller-chosen historical marker (`seasonId`) rather than the club's true current division.

### Impact Explanation
`tps_fee` has an additional real-time backstop: `validateTpsFee` also compares against `current_tps_fee`/`min_acceptable_tps_fee` derived from the validating node's live view (`storage.getCurrentTpsFee`), which limits how much a stale-mci choice can reduce the fee [7](#0-6) . `oversize_fee`, however, has no equivalent live-state cross-check in the code inspected — it is validated purely against the `threshold_size` at the author-chosen `last_ball_mci` [4](#0-3) . Because both fees are the network's anti-spam/congestion-pricing mechanism, systematically underpaying them by referencing favorable historical system-var snapshots would blunt the anti-spam pricing and could contribute to unit-confirmation congestion under load — the kind of "network unable to confirm new units in a timely fashion" impact category.

### Likelihood Explanation
I could not fully confirm within the available tool budget (a) whether `threshold_size`/`base_tps_fee`/etc. actually change materially/frequently enough in practice via the voting mechanism (`initial_votes.js`, `main_chain.js`) to make this exploitable, and (b) whether some other constraint elsewhere in unit composition/validation (e.g., input-selection "must be before last_ball" rules, or a maximum age check I did not locate) effectively forces `last_ball_unit` to be recent. Given the uncertainty on both the actual magnitude of system-var drift and on whether a hidden freshness constraint exists, I cannot assert this rises above a low-likelihood theoretical fee-optimization issue rather than a concretely exploitable Medium-severity vulnerability matching the required impact categories.

### Recommendation
If confirmed exploitable: (1) require `last_ball_unit`/`last_ball_mci` used for oversize-fee and tps-fee purposes to be within a bounded recency window of the unit's actual position (e.g., compare against `max_parent_limci` directly rather than an arbitrarily older stable ball chosen by the author), or (2) add a live-state floor check for `oversize_fee` analogous to the `current_tps_fee`/`min_acceptable_tps_fee` backstop already present for `tps_fee`.

### Proof of Concept
Not constructed — this requires confirming empirically (via `initial_votes.js`/`main_chain.js` vote history) that `threshold_size` or `base_tps_fee` actually decreases at some point in the vote history, then composing a unit that intentionally selects an older, still-stable `last_ball_unit` corresponding to that lower value while otherwise satisfying `validateParents`'s "no unstable predecessors" and double-spend constraints, and confirming the unit passes `validation.js`'s oversize-fee check while paying less than what the fee would be at the true current `last_ball_mci`. Given the unresolved uncertainty above, I present this as a candidate analog rather than a fully proven vulnerability.

### Citations

**File:** storage.js (L1132-1137)
```javascript
function getSystemVar(subject, mci) {
	for (let { vote_count_mci, value } of systemVars[subject])
		if (mci > vote_count_mci)
			return value;
	throw Error(subject + ` not found for mci ` + mci);
}
```

**File:** storage.js (L1147-1166)
```javascript
function getOversizeFee(objUnitOrSize, mci, bAA) {
	let size;
	if (typeof objUnitOrSize === "number")
		size = objUnitOrSize; // must be already without temp data fee
	else if (typeof objUnitOrSize === "object") {
		if (!objUnitOrSize.headers_commission || !objUnitOrSize.payload_commission)
			throw Error("no headers or payload commission in unit");
		// AA-generated units pay the oversize fee based on the unit size excluding its payment messages to avoid swelling the fee while spending dust outputs
		const payload_commission = (bAA && mci >= constants.pemCurvesFixMci)
			? objectLength.getTotalPayloadSize({ ...objUnitOrSize, messages: objUnitOrSize.messages.filter(message => message.app !== 'payment') })
			: objUnitOrSize.payload_commission;
		size = objUnitOrSize.headers_commission + payload_commission - objectLength.getPaidTempDataFee(objUnitOrSize);
	}
	else
		throw Error("unrecognized 1st arg in getOversizeFee");
	const threshold_size = getSystemVar('threshold_size', mci);
	if (size <= threshold_size)
		return 0;
	return Math.ceil(size * (exp(size / threshold_size - 1) - 1));
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

**File:** validation.js (L740-741)
```javascript
					if (objValidationState.max_parent_limci < objValidationState.last_ball_mci)
						return callback("last ball unit "+last_ball_unit+" is not included in parents, unit "+objUnit.unit);
```

**File:** validation.js (L767-778)
```javascript
						if (!("content_hash" in objUnit)) { // serial unit
							const oversize_fee = storage.getOversizeFee(objUnit, objValidationState.last_ball_mci, objValidationState.bAA);
							if (oversize_fee) {
								if (objUnit.oversize_fee !== oversize_fee)
									return callback(createJointError(`oversize_fee mismatch: expected ${oversize_fee}, found ${objUnit.oversize_fee}`));
							}
							else {
								if ("oversize_fee" in objUnit)
									return callback(createJointError("zero oversize fee should be omitted"));
							}
							if (!("tps_fee" in objUnit) && !objValidationState.bAA)
								return callback("no tps_fee field");
```

**File:** validation.js (L1061-1071)
```javascript
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
```

**File:** validation.js (L1074-1096)
```javascript
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
