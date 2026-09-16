### Title
Unbounded `earned_headers_commission_recipients` array is not capped like `authors`, enabling gas/DB-query explosion in headers-commission distribution and TPS-fee validation - ([File: validation.js])

### Summary
The Union Finance bug (`updateTrust()` not bounding `vouchers` the way it bounds `vouchees`) is a case where one side of a paired data structure is length-capped (`MAX_VOUCHERS`) while the logically-coupled side is left uncapped, letting an attacker grow the uncapped array until downstream iteration over it becomes prohibitively expensive. The same asymmetry exists in ocore between `objUnit.authors` (capped at `constants.MAX_AUTHORS_PER_UNIT = 16`) and the paired field `earned_headers_commission_recipients`, which has no equivalent maximum-length check.

### Finding Description
`validateHeadersCommissionRecipients()` only checks that the array is non-empty, that each `earned_headers_commission_share` is a positive integer, that addresses are sorted/valid, and that the shares sum to 100 — it never bounds the number of entries: [1](#0-0) 

Compare this with `validateAuthors()`, which explicitly rejects a unit whose `authors` array exceeds `MAX_AUTHORS_PER_UNIT` specifically as an anti-spam/anti-gas-explosion measure: [2](#0-1) 

`constants.js` defines hard caps for essentially every other repeated structure in a unit (authors, parents, messages, inputs/outputs, poll choices, attestors, denominations, data feeds) but no cap for commission recipients: [3](#0-2) 

Nothing in `validateHeadersCommissionRecipients` requires that the recipient addresses be a subset of, or bounded by, the number of unit authors — a unit with a single author can still declare an arbitrarily long recipient list (bounded only by `MAX_UNIT_LENGTH`, ~5MB, and `MAX_MESSAGES_PER_UNIT`), because the check is purely on share-sum and address ordering, not array length.

This unbounded array is later consumed twice in ways whose cost scales linearly (or worse) with its length:
1. In `validateTpsFee()`, the code iterates `for (let address in recipients)` and issues a DB query (`SELECT tps_fees_balance FROM tps_fees_balances ...`) per recipient during validation of every incoming unit that references this author set: [4](#0-3) 
2. In `headers_commission.js`, when the unit wins headers commission, the code iterates over `objUnit.assocEarnedHeadersCommissionRecipients` for every winning child unit and builds SQL `INSERT` value lists (`arrValues.push(...)`), with no bound on how many rows can be generated: [5](#0-4) 

### Impact Explanation
An attacker can post a legitimate-looking unit whose `earned_headers_commission_recipients` array contains thousands of entries (still summing shares to 100, still sorted and unique, thus passing validation). Once that unit is included and becomes stable/winning for headers commission:
- `calcHeadersCommissions()` — a function run by every full node during stabilization to compute spendable balances — must iterate over and insert one DB row per recipient for that unit, repeated for every subsequent stable unit that references it as ancestor, multiplying node-side compute/DB load.
- `validateTpsFee()` performs one DB round-trip per recipient for every unit later validated whose author set overlaps, which can be triggered repeatedly as new units continue to be produced/validated by every node in the network.

Because `calcHeadersCommissions` is part of the deterministic post-stabilization processing pipeline (needed before further units can spend headers-commission outputs), a sufficiently bloated recipient list can significantly slow down or stall this critical path on every full node in the network, degrading the network's ability to promptly confirm/process new units that depend on the affected commission outputs — i.e., a shared computational bottleneck rather than a localized, per-peer resource issue.

### Likelihood Explanation
Any unprivileged unit poster with more than one author (or even a contrived single/multi-author unit, since nothing forces `earned_headers_commission_recipients` to correspond 1:1 to `authors`) can construct and broadcast such a unit. The only limits are the generic unit-size ceiling (`MAX_UNIT_LENGTH`) and message-count ceiling, both of which still permit thousands of small recipient entries (each just an address + integer share) in a single message. No special privileges, hub cooperation, or timing conditions are required — a normal validated unit triggers the expensive downstream processing automatically once it stabilizes and wins headers commission.

### Recommendation
Add an explicit maximum-length check on `earned_headers_commission_recipients` in `validateHeadersCommissionRecipients()`, analogous to the `MAX_AUTHORS_PER_UNIT` check on `authors` (e.g., cap it at `constants.MAX_AUTHORS_PER_UNIT` or another small constant, since logically the commission should only be split among the unit's own authors):

```js
if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
    return cb("empty earned_headers_commission_recipients array");
if (objUnit.earned_headers_commission_recipients.length > constants.MAX_AUTHORS_PER_UNIT)
    return cb("too many earned_headers_commission_recipients");
```

Additionally consider requiring that every recipient address in the list correspond to an actual author of the unit (or another already-legitimate constraint), removing the ability to declare arbitrary unrelated recipients.

### Proof of Concept
1. Craft a unit with 2 authors (satisfying the "more than 1 author" requirement) and an `earned_headers_commission_recipients` array containing e.g. 5,000 unique valid addresses with shares that sum to 100 (e.g., many entries with share `1` won't sum correctly, so use decreasing fractional integer shares summing exactly to 100 — feasible by using shares of `0` disallowed; use enough entries with minimal shares like `1` for 100 entries, then pad remaining bytes with additional messages/large payload_hash-consistent content to maximize entries while staying within `MAX_UNIT_LENGTH`).
2. Because `validateHeadersCommissionRecipients` (validation.js:1101-1126) does not check array length, the unit passes validation and is accepted/broadcast.
3. When the unit stabilizes and becomes a headers-commission "winner" (`getWinnerInfo` in headers_commission.js), `calcHeadersCommissions` iterates over all entries in `assocEarnedHeadersCommissionRecipients` (headers_commission.js:176-188) generating one `INSERT` row per recipient per payer unit; repeating over many payer units multiplies node-side work.
4. Independently, any subsequent unit validation calling `validateTpsFee` for units whose author overlaps the recipients triggers one DB query per recipient (validation.js:1079-1096), compounding load on every validating node.

### Citations

**File:** validation.js (L1079-1096)
```javascript
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

**File:** validation.js (L1101-1126)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
	cb();
}
```

**File:** validation.js (L1128-1132)
```javascript
function validateAuthors(conn, arrAuthors, objUnit, objValidationState, callback) {
	if (objValidationState.bAA && arrAuthors.length !== 1)
		throw Error("AA unit with multiple authors");
	if (arrAuthors.length > constants.MAX_AUTHORS_PER_UNIT) // this is anti-spam. Otherwise an attacker would send nonserial balls signed by zillions of authors.
		return callback("too many authors");
```

**File:** constants.js (L42-59)
```javascript
// anti-spam limits
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_CHOICES_PER_POLL = 128;
exports.MAX_CHOICE_LENGTH = 64;
exports.MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64;
exports.MAX_ATTESTORS_PER_ASSET = 64;
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
exports.MAX_DATA_FEEDS_PER_MESSAGE = 1024;
exports.MAX_AUTHENTIFIER_LENGTH = 4096;
exports.MAX_CAP = 9e15;
exports.MAX_COMPLEXITY = process.env.MAX_COMPLEXITY || 100;
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```

**File:** headers_commission.js (L176-214)
```javascript
								for (var child_unit in assocWonAmounts){
									var objUnit = storage.assocStableUnits[child_unit];
									for (var payer_unit in assocWonAmounts[child_unit]){
										var full_amount = assocWonAmounts[child_unit][payer_unit];
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
									}
								}
								// sql result
								var arrValues = conf.bFaster ? arrValuesRAM : [];
								if (!conf.bFaster){
									profit_distribution_rows.forEach(function(row){
										var child_unit = row.unit;
										for (var payer_unit in assocWonAmounts[child_unit]){
											var full_amount = assocWonAmounts[child_unit][payer_unit];
											if (!full_amount)
												throw Error("no amount for child unit "+child_unit+", payer unit "+payer_unit);
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
										}
									});
									if (!_.isEqual(arrValuesRAM.sort(), arrValues.sort())) {
										throwError("different arrValues, db: "+JSON.stringify(arrValues)+", ram: "+JSON.stringify(arrValuesRAM));
									}
								}

								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
```
