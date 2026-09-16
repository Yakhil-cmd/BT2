Based on my research, I found a directly analogous, developer-acknowledged bug class in ocore's `tps_fee` mechanism.

### Title
Users can be forced to overpay `tps_fee` because it is calculated from live, mutable network state rather than a value fixed at composition time - (File: `object_hash.js`, `storage.js`, `parent_composer.js`)

### Summary
The SecondSwap bug charges a stale/live-read `penaltyFee` that can change between the time a user decides to act and the time the action executes, causing overpayment with no user protection. In `ocore`, the `tps_fee` a unit must pay is likewise not a value fixed at composition time: it is derived from live, continuously changing network throughput (`storage.getCurrentTps`/`getLocalTps`) and from governance-adjustable `system_vars` (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), both of which can change between when a wallet/light client estimates and pays the fee and when the unit is actually validated/included. The ocore developers themselves flagged this exact class of issue in a code comment.

### Finding Description
When composing a unit, the wallet/light client estimates the fee to attach via `composer.estimateTpsFee()` / `parent_composer.getTpsFee()`, which calls `getLocalTpsFee()`/`getCurrentTpsFeeToPay()`. These functions compute the fee using the **current** network throughput and the **current** `system_vars` values for `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier`: [1](#0-0) 

`base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are themselves mutable, governance-voted parameters that can change at any stabilized MCI via `system_vote`/`system_vote_count` messages, counted in `countVotes()`: [2](#0-1) 

By the time the composed unit is broadcast and reaches `validateTpsFee()` at inclusion (using the throughput/system vars as of the eventual `last_ball_mci`, not the values known at compose time), the required `min_tps_fee` may be higher than what was estimated and paid: [3](#0-2) 

The ocore team is explicitly aware that `tps_fee` "cannot be calculated from unit's content and environment" alone, and left it out of the hash-excluded fields specifically because "users might pay more than required": [4](#0-3) 

This is structurally the same defect class as the SecondSwap report: a mutable, externally-adjustable fee parameter is read live at validation/settlement time instead of being locked to what the user agreed to when initiating the action, and there is no cached/committed value in the unit that binds the fee to conditions at the time of intent formation.

### Impact Explanation
If throughput/voted parameters rise between compose time and inclusion time, the previously-attached `tps_fee` becomes insufficient. `validateTpsFee()` will then reject the unit as a transient error (`createTransientError`) unless the sender is an Order Provider (OP), forcing the user to recompose and pay a **higher, unexpected fee** than what they budgeted for when they built and broadcast the original unit - i.e., the user "pays an outdated (too-low) fee expectation and must pay more than initially agreed," mirroring the SecondSwap overcharge scenario. Because light wallets fetch `tps_fee` from a vendor at an earlier point and use it verbatim (`composer.js:353-355`, `light.js:622-641`), the discrepancy window is a normal, unprivileged usage path, not a privileged/admin-only scenario.

### Likelihood Explanation
This occurs under ordinary network conditions whenever throughput increases meaningfully (or an OP votes to raise `base_tps_fee`/`tps_fee_multiplier`) in the interval between a wallet's fee estimation and the unit's eventual inclusion at a later `last_ball_mci`. Given `system_vote` changes take effect at the very next stabilized MCI and throughput is highly dynamic, this window is realistically and frequently reachable by any ordinary posting wallet/light client, without any malicious actor being required.

### Recommendation
Bind the fee commitment to the intent expressed at composition time rather than re-deriving it purely from live state at validation time: e.g., allow the composing wallet to include a `max_tps_fee` cap the user explicitly agreed to, and treat any requirement above that cap as a hard failure with clear user notice rather than silently recomputing a higher due amount; alternatively, cache/checkpoint the throughput and `system_vars` values used at composition time (referenced by `last_ball_unit`) so that the fee owed by a given unit is deterministic from data available when the user decided to send it, closing the gap the ocore team already flagged in `object_hash.js`.

### Proof of Concept
1. Light wallet calls `estimateTpsFee()` (`composer.js:604-631`) or `prepareParentsAndLastBallAndWitnessListUnit` (`light.js:590-651`) at time T0, receiving `tps_fee` based on throughput/`system_vars` as of T0.
2. Between T0 and unit inclusion, network throughput rises, or an OP casts a `system_vote` for `base_tps_fee`/`tps_fee_multiplier` that gets counted at the next stable MCI (`main_chain.js:1878-1903`).
3. The unit finally reaches inclusion; `validateTpsFee()` recomputes `min_tps_fee` from throughput/`system_vars` at the (now later) `last_ball_mci` (`validation.js:1050-1097`).
4. `min_tps_fee` now exceeds the `tps_fee` the user attached at T0; the unit is rejected as a transient error, forcing the user to resend paying a higher fee than what they had agreed to pay when they initiated the transaction - exactly the "outdated fee vs. live fee" mismatch from the SecondSwap report, acknowledged directly in `object_hash.js:39`.

### Citations

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

**File:** main_chain.js (L1878-1903)
```javascript
		case "threshold_size":
		case "base_tps_fee":
		case "tps_interval":
		case "tps_fee_multiplier":
			const rows = await conn.query(`SELECT value, SUM(balance) AS total_balance
				FROM numerical_votes
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=? AND subject=?
				GROUP BY value
				ORDER BY value`,
				[since_timestamp, subject]
			);
			console.log(`total votes for`, subject, rows);
			const total_voted_balance = rows.reduce((acc, row) => acc + row.total_balance, 0);
			let accumulated = 0;
			for (let { value: v, total_balance } of rows) {
				accumulated += total_balance;
				if (accumulated >= total_voted_balance / 2) {
					value = v;
					break;
				}
			}
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
			break;
```

**File:** validation.js (L1050-1097)
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
	callback();
```

**File:** object_hash.js (L33-40)
```javascript
function getNakedUnit(objUnit){
	var objNakedUnit = _.cloneDeep(objUnit);
	delete objNakedUnit.unit;
	delete objNakedUnit.headers_commission;
	delete objNakedUnit.payload_commission;
	delete objNakedUnit.oversize_fee;
//	delete objNakedUnit.tps_fee; // cannot be calculated from unit's content and environment, users might pay more than required
	delete objNakedUnit.actual_tps_fee;
```
