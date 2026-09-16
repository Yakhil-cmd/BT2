### Title
Division by zero / `Infinity` in `storage.js::getPaidTpsFee` when `earned_headers_commission_share` is 0 - (File: storage.js)

### Summary
`storage.js::getPaidTpsFee` divides `tps_fees_balance` by a `share` value derived from an untrusted, unit-author-controlled field (`earned_headers_commission_share`) without guarding against `share === 0`, unlike the equivalent code path in `validation.js::validateTpsFee`, which explicitly checks for this condition. This mirrors the reported `BlockSpecimenProofChain::finalizeSpecimenSession` pattern: a divisor sourced from externally-influenced data is used in a division without a zero-check.

### Finding Description
Any unit author can attach an `earned_headers_commission_recipients` message to their own unit, listing recipient addresses with an `earned_headers_commission_share` (a percentage). This value is written to the DB as-is in `writer.js` with no floor enforcement visible at that layer: [1](#0-0) 

`storage.js::getTpsFeeRecipients` returns these shares straight from the stored/posted recipients map: [2](#0-1) 

`storage.js::getPaidTpsFee` then computes, for each recipient:
```js
const share = recipients[address] / 100;
...
const tps_fee = tps_fees_balance / share + objUnitProps.tps_fee;
```
with no check that `share` is non-zero before dividing: [3](#0-2) 

Notably, the sibling function `validation.js::validateTpsFee`, which performs the *same* division (`tps_fees_balance / share`) over the *same* `recipients` structure, explicitly guards against this: [4](#0-3) 

The presence of `if (!share) throw Error(...)` in `validateTpsFee` demonstrates that the codebase authors recognized `share` could be `0` for a value taken from `earned_headers_commission_share`, yet the equivalent division in `getPaidTpsFee` (and also in `composer.js`'s TPS-fee computation, which divides `tps_fees_balance / share` without a zero-check) lacks the same protection: [5](#0-4) 

This is the same bug class as the reported issue: a division whose divisor is derived from data that should be positive but is not validated to be `> 0` before being used as a divisor, letting an unprivileged poster (unit author) trigger a division-by-zero/`Infinity` computation.

### Impact Explanation
When `share` is `0`, `tps_fees_balance / share` evaluates to `Infinity` (or `NaN` if `tps_fees_balance` is also `0`) in JavaScript, silently corrupting `min_tps_fee`/`tps_fee` calculations rather than throwing. Since `getPaidTpsFee` is used to determine the minimum acceptable TPS fee for a unit, a corrupted `Infinity` value could make legitimate light-client fee estimation impossible or incorrect, potentially causing units to be rejected as underpaying fees or causing downstream logic that consumes this value to misbehave. This is a Medium-severity node-disagreement/availability-adjacent issue, not a fund-theft primitive.

### Likelihood Explanation
Reaching this requires only that an unprivileged unit author includes an `earned_headers_commission_recipients` entry with `earned_headers_commission_share = 0` in their own unit — no special privilege is required to post such a message. Whether the base unit-syntax validator (in `validation.js`, not fully inspected here) enforces `earned_headers_commission_share > 0` at the JSON-schema/structural-validation stage is not fully confirmed from the retrieved code; the existence of the explicit runtime guard in `validateTpsFee` (`if (!share) throw Error(...)`) strongly suggests such a value can reach that point without being rejected earlier, since otherwise the guard would be dead code.

### Recommendation
Add an explicit guard in `storage.js::getPaidTpsFee` (and in the analogous computation in `composer.js`) to reject or safely skip any recipient whose `share` resolves to `0`, mirroring the check already present in `validation.js::validateTpsFee`. Additionally, confirm that unit-level structural validation of `earned_headers_commission_share` enforces a strictly positive integer percentage so that a `0` value can never be persisted in the first place.

### Proof of Concept
1. Attacker composes and posts a unit with two authors (or one author plus an `earned_headers_commission_recipients` message) where one recipient's `earned_headers_commission_share` is set to `0`.
2. This value is stored verbatim via `writer.js` (lines 290-296) with no floor check.
3. Later, when `storage.getPaidTpsFee(conn, unit)` is called for this unit (e.g., by a light client estimating the TPS fee to pay for a dependent unit), `getTpsFeeRecipients` returns `{ address: 0 }` for that recipient.
4. In the loop, `const share = recipients[address] / 100;` evaluates to `0`, and `const tps_fee = tps_fees_balance / share + objUnitProps.tps_fee;` evaluates to `Infinity`, propagating a corrupted fee value from `getPaidTpsFee`.

### Citations

**File:** writer.js (L290-296)
```javascript
		if ("earned_headers_commission_recipients" in objUnit){
			for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
				var recipient = objUnit.earned_headers_commission_recipients[i];
				conn.addQuery(arrQueries, 
					"INSERT INTO earned_headers_commission_recipients (unit, address, earned_headers_commission_share) VALUES(?,?,?)", 
					[objUnit.unit, recipient.address, recipient.earned_headers_commission_share]);
			}
```

**File:** storage.js (L1430-1439)
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
```

**File:** storage.js (L1470-1482)
```javascript
function getTpsFeeRecipients(assocEarnedHeadersCommissionRecipients, author_addresses) {
	let recipients = assocEarnedHeadersCommissionRecipients || { [author_addresses[0]]: 100 };
	if (assocEarnedHeadersCommissionRecipients) {
		let bHasExternalRecipients = false;
		for (let address in recipients) {
			if (!author_addresses.includes(address))
				bHasExternalRecipients = true;
		}
		if (bHasExternalRecipients) // override, non-authors won't pay for our tps fee
			recipients = { [author_addresses[0]]: 100 };
	}
	return recipients;
}
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

**File:** composer.js (L382-390)
```javascript
						for (let address in recipients) {
							const share = recipients[address] / 100;
							const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, last_ball_mci]);
							const tps_fees_balance = row ? row.tps_fees_balance : 0;
							console.log('composer', {address, tps_fees_balance, tps_fee})
							const addr_tps_fee = Math.ceil(tps_fee - tps_fees_balance / share);
							if (addr_tps_fee > paid_tps_fee)
								paid_tps_fee = addr_tps_fee;
						}
```
