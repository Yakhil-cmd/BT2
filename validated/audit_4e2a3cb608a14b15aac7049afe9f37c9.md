### Title
Fixed `bounce_fees` in an AA definition can become insufficient to cover the actual, governance-adjustable cost of sending a response/bounce, freezing AA responses and trigger funds - (File: aa_composer.js, aa_validation.js)

### Summary
The Synthetix report describes a liquidity pool that hardcodes a margin ratio (`futuresLeverage`) that is checked against a *fixed* local assumption, while the real minimum-margin requirement is set by an external, governance-mutable parameter (`liquidationBufferRatio`) that can be raised over time, eventually making the hardcoded margin insufficient and causing execution/liquidation failures. The closest reachable analog in ocore is the `bounce_fees` field of an Autonomous Agent (AA) definition, which is a value fixed forever at AA-creation time and only validated once (`>= constants.MIN_BYTES_BOUNCE_FEE`), while the *actual* cost that an AA must pay to send a response or bounce message (`headers_commission + payload_commission + oversize_fee + tps_fee`) is driven by system parameters (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) that are explicitly designed to be changed over time through `system_vote`/`system_vote_count` governance. Because an AA's `bounce_fees` can never be updated after deployment, once these mutable network fee parameters grow enough, an AA's built-in "minimum funds to guarantee a response" assumption silently becomes inadequate.

### Finding Description
`aa_validation.js` validates `bounce_fees` only at AA-definition time, checking that `bounce_fees.base >= constants.MIN_BYTES_BOUNCE_FEE`: [1](#0-0) 

This is a one-time, static sanity check based on the `MIN_BYTES_BOUNCE_FEE` constant, similar in spirit to how the Synthetix LP's `futuresLeverage` was fixed against a `liquidationBufferRatio` that was 1e16 "now" but could grow.

At trigger-handling time, `aa_composer.js` uses this same fixed `bounce_fees` object (read once from the immutable AA definition) both to decide whether the AA should even try to respond and to size the bounce transaction: [2](#0-1) [3](#0-2) 

However, the *actual* bytes required to successfully post the AA's response/bounce unit are not fixed - they include `oversize_fee` and `tps_fee`, both of which are computed from mutable, vote-controlled system variables: [4](#0-3) [5](#0-4) 

These system variables (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) are explicitly designed to be changed by the community through `system_vote`, counted at stabilization, and looked up per-mci via `getSystemVar`: [6](#0-5) [7](#0-6) 

Both parameters can, over time, be voted arbitrarily higher within their validated bounds (e.g., `base_tps_fee` up to `1e8`, `tps_fee_multiplier` up to `1000`), as enforced in `validation.js`: [8](#0-7) 

When `sendUnit()`/`completePaymentPayload()` build the AA's response, they compute `target_amount` including `getOversizeFee()`, i.e., using the *current* mutable fee schedule, not the fee schedule that existed when the AA was created and its `bounce_fees` were fixed: [9](#0-8) 

If network fee parameters rise enough (via legitimate governance votes, which any unprivileged holder can influence and any AA author cannot control or predict), a previously-adequate `bounce_fees.base` (which only had to satisfy `MIN_BYTES_BOUNCE_FEE` at creation time) can become insufficient to cover `headers_commission + payload_commission + oversize_fee + tps_fee` for the response/bounce unit. Because `bounce()` guards against re-entrant bouncing (`bBouncing` flag) and simply calls `finish(null)` if the second `sendUnit()` attempt from within `bounce()` itself fails, the AA silently swallows the trigger's payment with no response and no state change, exactly analogous to the reported bug where the LP's under-collateralized position could no longer be maintained once the external ratio moved: [10](#0-9) 

### Impact Explanation
This is an "AA fund loss or freezing" scenario as accepted by the validation rules: funds sent by an unprivileged trigger sender to an AA can be silently absorbed by the AA with no response and no refund/bounce if the current governance-driven `tps_fee`/`oversize_fee` schedule exceeds the AA's immutable `bounce_fees.base` (which was only checked against the historical `MIN_BYTES_BOUNCE_FEE` constant at definition time). Since AA definitions in ocore are immutable once deployed, the AA author has no way to raise `bounce_fees` later to keep pace with governance-voted fee increases, unlike a mutable admin-controlled `futuresLeverage` in the Synthetix analog (which at least *can* be adjusted by an admin). This makes the ocore case arguably harder to remediate once deployed.

### Likelihood Explanation
Low-to-medium likelihood: it requires network-wide governance votes (`system_vote` for `base_tps_fee`, `tps_fee_multiplier`, `tps_interval`, or `threshold_size`) to push the effective fee well above the small `MIN_BYTES_BOUNCE_FEE` floor used at AA-creation validation time, similar to how the original report required Synthetix governance to raise `liquidationBufferRatio` well above its "current" 1e16 value. As in the original C4 finding (which was accepted despite requiring "many what-ifs"), this is a plausible but not immediate risk that depends on future parameter changes outside the AA author's control.

### Recommendation
- Do not rely solely on a fixed `bounce_fees.base` validated once against `MIN_BYTES_BOUNCE_FEE`; either periodically re-validate/warn AA authors that `bounce_fees` must track the current fee schedule, or provide an oscript primitive/getter that lets an AA query current `oversize_fee`/`tps_fee` parameters so authors can size `bounce_fees` dynamically, or design AAs defensively (e.g., accept larger safety margins).
- Consider making the bounce-fee sufficiency check at trigger time account for the *current* `oversize_fee`/`tps_fee` cost of the actual bounce/response unit rather than only comparing against the AA's static `bounce_fees` object, so that borderline cases fail predictably (bounce) rather than being silently absorbed.

### Proof of Concept
1. Deploy an AA with `bounce_fees: { base: constants.MIN_BYTES_BOUNCE_FEE }` (the validator only requires this minimum, per `aa_validation.js:758`).
2. Over time, network governance votes progressively raise `base_tps_fee` and/or `tps_fee_multiplier` (bounded by `validation.js:1893-1905`) and/or lowers `threshold_size` implications for oversize fee growth (`storage.js:1147-1166`), which raises the effective `oversize_fee`/`tps_fee` cost of any response unit the AA must send (`storage.js:1339-1349`).
3. A user triggers the AA with payment just above the AA's static `bounce_fees.base` but now below the *actual* required `headers_commission + payload_commission + oversize_fee + tps_fee` for a bounce/response unit at the current mci.
4. Inside `handleTrigger`, the trigger passes the static bounce-fee check (`aa_composer.js:1851-1859`), but `sendUnit()`/`completePaymentPayload()` (using the current, higher fee schedule via `getOversizeFee` at `aa_composer.js:1083-1101`) fails to find enough funds, causing `bounce(err)` to be invoked from inside `sendUnit`'s error path.
5. Since `bBouncing` is already true from the initial attempt, the second `bounce()` call short-circuits to `finish(null)` (`aa_composer.js:923-925`), and the trigger's coins are consumed by the AA without any response, state update, or refund.

### Citations

**File:** aa_validation.js (L748-759)
```javascript
	if ('bounce_fees' in template){
		if (!isNonemptyObject(template.bounce_fees))
			return callback("empty bounce_fees");
		for (var asset in template.bounce_fees){
			if (asset !== 'base' && !isValidBase64(asset, constants.HASH_LENGTH))
				return callback("bad asset in bounce_fees: " + asset);
			var fee = template.bounce_fees[asset];
			if (!isNonnegativeInteger(fee) || fee > constants.MAX_CAP)
				return callback("bad bounce fee: "+JSON.stringify(fee));
		}
		if ('base' in template.bounce_fees && template.bounce_fees.base < constants.MIN_BYTES_BOUNCE_FEE)
			return callback("too small base bounce fee: "+template.bounce_fees.base);
```

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```

**File:** aa_composer.js (L1083-1101)
```javascript
			const paid_temp_data_fee = objectLength.getPaidTempDataFee({ messages });
			const bChargeOversizeFee = (mci >= constants.v4UpgradeMci && is_base);
			// AA-generated units pay the oversize fee based on the unit size excluding its payment messages;
			// this doesn't change as we add more inputs to the payment message, so calculate it only once
			const oversize_fee_excluding_payments = (bChargeOversizeFee && mci >= constants.pemCurvesFixMci)
				? storage.getOversizeFee(objUnit.headers_commission + objectLength.getTotalPayloadSize({ ...objUnit, messages: messages.filter(message => message.app !== 'payment') }) - paid_temp_data_fee, last_ball_mci)
				: null;
			var net_target_amount = payload.outputs.reduce(function (acc, output) { return acc + (output.amount || 0); }, size);
			let target_amount = net_target_amount + getOversizeFee(size);
			var bFound = false;

			function getOversizeFee(s) {
				if (!bChargeOversizeFee)
					return 0;
				if (mci < constants.pemCurvesFixMci)
					return storage.getOversizeFee(s - paid_temp_data_fee, last_ball_mci);
				return oversize_fee_excluding_payments;
			}

```

**File:** aa_composer.js (L1851-1859)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

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

**File:** validation.js (L1893-1905)
```javascript
				case "base_tps_fee":
				case "tps_interval":
				case "tps_fee_multiplier":
					if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
						return callback(payload.subject + " must be a positive number");
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) {
						if (payload.subject === "tps_interval" && payload.value < 0.1)
							return callback(payload.subject + " must be at least 0.1");
						if (payload.subject === "base_tps_fee" && payload.value > 1e8)
							return callback(payload.subject + " must be at most 1e8");
						if (payload.subject === "tps_fee_multiplier" && (payload.value < 1 || payload.value > 1000))
							return callback(payload.subject + " must be between 1 and 1000");
					}
```
