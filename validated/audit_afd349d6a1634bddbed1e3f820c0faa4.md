## Finding: Unauthenticated DoS via uncaught assertion-style `throw Error` in TPS-fee validation (`validation.js`)

### Title
Unit poster can crash every processing node via zero-share assertion throw in `validateTpsFee` - (File: validation.js)

### Summary
The FFmpeg CVE is a crash caused by an internal invariant ("assertion") being violated by attacker-supplied data inside rational/arithmetic code, rather than the code returning a graceful error. `ocore` has a structurally identical pattern in the TPS-fee validation path: a synchronous `throw Error(...)` guards against a "should never happen" arithmetic precondition (a zero commission-recipient share), but this branch is reachable from a value that an ordinary unit poster fully controls (`earned_headers_commission_recipients`), and it is not wrapped in any try/catch on the calling path. [1](#0-0) 

### Finding Description
`validateTpsFee()` is executed for every version-4+ unit as a mandatory step of `validate()`: [2](#0-1) 

Inside it, recipients and their `share` (percentage of headers-commission/TPS-fee split) are derived directly from unit-supplied `earned_headers_commission_recipients` (via `storage.ehcr2assoc`) and the author addresses: [1](#0-0) 

```
const share = recipients[address] / 100;
if (!share)
    throw Error(`invalid share for address ${address}: ${share}`);
```

This is the analog of the FFmpeg assertion failure: an arithmetic precondition ("share must never be 0/falsy") is enforced with an unconditional `throw` instead of routing the problem back through the normal `callback(err)` error path used everywhere else in this same function (e.g. lines 1088-1089, 1093). If a crafted unit produces a recipient whose computed share is `0` (or otherwise falsy, e.g. `NaN`/`undefined` due to malformed input), the `throw` executes synchronously inside `validateTpsFee`, an `async function` invoked from the `async.series` validation pipeline. This throw is not caught by any surrounding `try/catch`, so it propagates as an unhandled exception/rejection at the top of the validation call chain, which per Node.js semantics can terminate the process.

`storage.ehcr2assoc` (used to build `recipients`) merely copies whatever `earned_headers_commission_share` values exist in the unit's `earned_headers_commission_recipients` array: [3](#0-2) 

If the earlier structural check (`validateHeadersCommissionRecipients`, invoked at line 388 of `validation.js`) permits a recipient entry with `earned_headers_commission_share = 0` (a value that is a syntactically legitimate "explicit 0% share" and not obviously excluded by a simple range/sum check), that value flows unchanged into `getTpsFeeRecipients`/`ehcr2assoc` and then into the `share` computation above, hitting the `throw Error` in `validateTpsFee` — a crash triggerable purely by an unprivileged unit author. [4](#0-3) 

### Impact Explanation
An unhandled exception thrown mid-validation for every node that receives and validates the malicious unit constitutes a remote, unauthenticated denial-of-service: nodes across the network could crash simultaneously while trying to validate the same broadcast unit, preventing the network from confirming new units — matching the "network unable to confirm new units" bar required by this analysis. This mirrors the FFmpeg bug class exactly: a crafted, syntactically-valid input triggers an internal assertion-style crash rather than a controlled rejection.

### Likelihood Explanation
Likelihood depends entirely on whether `validateHeadersCommissionRecipients` (not fully inspected in this session) actually permits an `earned_headers_commission_share` value of `0` for one or more recipients while still passing overall unit structure checks. I was not able to retrieve the full body of `validateHeadersCommissionRecipients` before running out of search budget, so I cannot conclusively confirm that a `0` share value survives that earlier check. This is the key open question that determines whether this is directly exploitable or merely defense-in-depth code that is unreachable in practice.

### Recommendation
- Replace the `throw Error(...)` in `validateTpsFee` (validation.js:1084-1085) with a graceful `return callback(...)` rejecting the unit, consistent with the rest of the function.
- Explicitly verify/enforce in `validateHeadersCommissionRecipients` that every `earned_headers_commission_share` is a strictly positive integer (reject `0`), closing the root cause rather than only papering over the crash site.
- Audit other reachable `throw Error` sites in the mandatory unit-validation call graph (`validation.js`, `storage.js` TPS-fee functions, `main_chain.js` `finish()`/`updateTpsFees`) for the same pattern of "should never happen" assertions fed by attacker-controlled unit fields, since several similar unguarded `throw` statements exist in `storage.js` (`getFinalTps`, `getLocalTps`, `getCurrentTps`) that are reachable from unit processing without try/catch.

### Proof of Concept
Not independently verified end-to-end due to inability to confirm the exact bounds enforced by `validateHeadersCommissionRecipients` within the available tool budget. Conceptually: post a version-4+ unit whose `earned_headers_commission_recipients` array includes an address with `earned_headers_commission_share: 0` alongside other recipients summing the remainder to 100; when `validateTpsFee` computes `share = 0/100 = 0` for that address, the `if (!share) throw Error(...)` fires uncaught during standard peer validation.

**Uncertainty flagged:** I could not confirm whether `validateHeadersCommissionRecipients` already rejects zero-value shares upstream, which would neutralize this specific reachability path. A Devin session with full file access should read the complete `validateHeadersCommissionRecipients` function in `validation.js` to confirm or refute this before treating the PoC as concrete.

### Citations

**File:** validation.js (L381-389)
```javascript
				function(cb){
					profiler.start();
					checkDuplicate(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
```

**File:** validation.js (L429-434)
```javascript
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
```

**File:** validation.js (L1081-1090)
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
```

**File:** storage.js (L1123-1130)
```javascript
function ehcr2assoc(earned_headers_commission_recipients) {
	if (!earned_headers_commission_recipients)
		return earned_headers_commission_recipients; // null or undefined
	let assoc = {};
	for (let { address, earned_headers_commission_share } of earned_headers_commission_recipients)
		assoc[address] = earned_headers_commission_share;
	return assoc;
}
```
