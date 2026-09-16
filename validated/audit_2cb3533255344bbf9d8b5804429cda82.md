### Title
Missing Upper Bound on AA-Generated `oversize_fee` Relative to Response Size Enables Disproportionate AA Fund Drain - ([File: aa_composer.js], [File: storage.js])

### Summary
`storage.getOversizeFee()` computes an exponentially-growing fee once a unit's size exceeds the network `threshold_size`, and `aa_composer.js` charges this fee directly out of the triggered AA's own balance for every AA response unit it builds. Unlike the wallet-side `composer.js`/`divisible_asset.js`/`indivisible_asset.js` paths, which sanity-check that `oversize_fee` (+ `tps_fee`) does not exceed `max_ratio * size_fees` before signing, the AA response path has no equivalent bound. An unprivileged trigger sender who can influence the size of an AA's response unit (e.g., via trigger-controlled data reflected into response/state messages) can push the response unit size past `threshold_size`, causing the exponential fee formula to charge the AA balance an amount wildly disproportionate to the actual value being moved.

### Finding Description
`storage.getOversizeFee()` in [1](#0-0)  computes:
```
size = headers_commission + payload_commission - paid_temp_data_fee
if (size <= threshold_size) return 0;
return Math.ceil(size * (exp(size / threshold_size - 1) - 1));
```
This is unbounded exponential growth in `size`. For wallet-composed transactions, `composer.js` explicitly guards against this fee formula producing an unreasonable fee before signing and broadcasting: [2](#0-1) 
```
const size_fees = objUnit.headers_commission + objUnit.payload_commission;
const additional_fees = (objUnit.oversize_fee || 0) + objUnit.tps_fee;
const max_ratio = params.max_fee_ratio || conf.max_fee_ratio || 100;
if (additional_fees > max_ratio * size_fees)
    err = `additional fees ... would be more than ${max_ratio} times the regular fees ...`;
```
This same `max_fee_ratio` guard exists only in `wallet.js`, `divisible_asset.js`, and `indivisible_asset.js` — all of which are user-initiated wallet composition paths.

However, `aa_composer.js`, which autonomously builds and sends the AA's response unit(s) after a trigger, computes and applies `oversize_fee` with no equivalent bound: [3](#0-2) 
```
objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
const oversize_fee = (mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci, true) : 0;
if (oversize_fee)
    objUnit.oversize_fee = oversize_fee;
```
The fee is deducted from the AA's own balance (paid autonomously, not by the trigger sender), and `validation.js` only checks that the declared `oversize_fee` on the unit matches the formula's output — it never checks that the fee is proportionate to the value transferred or to the base commissions: [4](#0-3) 
```
const oversize_fee = storage.getOversizeFee(objUnit, objValidationState.last_ball_mci, objValidationState.bAA);
if (oversize_fee) {
    if (objUnit.oversize_fee !== oversize_fee)
        return callback(...);
}
```
Because AA authors typically do not (and cannot easily) predict every possible size of a triggered response unit — sizes can be influenced by trigger-controlled inputs echoed into `response[...]`/state messages/output counts — a trigger sender who crafts a trigger that forces an unusually large response unit can trigger the exponential fee curve. Since `threshold_size` is a small system-wide constant (initialized to `10000` bytes per [5](#0-4) ), pushing the response payload moderately past this threshold causes `exp(size/threshold_size - 1)` to blow up rapidly, extracting a very large fee from the AA's balance with no cap relative to `headers_commission + payload_commission` or to the amounts in play — mirroring the reported `pool::get_fee` bug class where a fee component (`base_fee`/exponential surcharge) is combined additively without any check that the total remains a reasonable fraction of the transacted value.

### Impact Explanation
Because the fee is silently deducted from the AA's own `base` balance (as part of normal AA response unit construction, before any user-level max-ratio protection is applied), an attacker who can trigger an AA in a way that inflates its response unit size can cause the AA to overpay an oversize fee disproportionate to the transaction, draining AA balance (an "AA fund loss" scenario) far beyond what the AA definition author ever accounted for. This is a fund-loss vector reachable purely by an unprivileged AA trigger sender crafting trigger data/messages that get reflected into the AA's response.

### Likelihood Explanation
Exploitability depends on whether a specific AA's `messages`/`state`/`response` templates echo trigger-controlled data of variable, attacker-influenced length into the response unit (a common pattern, e.g., logging trigger data or forwarding arbitrary strings). For AAs that do this, the attack is straightforward: send a trigger with as much sizeable data as the network allows, causing the response unit's payload to cross `threshold_size`, incurring the exponential fee. Likelihood is Medium: it requires a susceptible AA definition (one that reflects attacker-controlled length into its response), but the underlying missing bound in the fee-charging path (`aa_composer.js`) applies to all AAs uniformly, and the composer-side `max_fee_ratio` protection that exists for ordinary wallets was evidently deemed necessary by the codebase authors yet was never ported to the AA response path.

### Recommendation
Apply the same `max_fee_ratio`-style bound used in `composer.js` (and `divisible_asset.js`/`indivisible_asset.js`) to the AA response unit construction in `aa_composer.js`: before finalizing `objUnit.oversize_fee`, verify that `oversize_fee (+ tps_fee)` does not exceed some multiple of `headers_commission + payload_commission` (or of the actual value moved by the AA), and bounce the trigger (charging only the bounce fee) instead of silently draining AA balance when the computed fee is disproportionate.

### Proof of Concept
Conceptual PoC (not run, requires a live devnet/testnet):
1. Deploy an AA whose `messages`/`state` template echoes attacker-supplied `trigger.data` fields verbatim into a `response[...]` or `state` message (a common utility/logging pattern).
2. Send a trigger unit whose `data` payload is large enough to push the resulting response unit's `headers_commission + payload_commission` past the network `threshold_size` (10000 bytes by default).
3. Observe in `aa_composer.js`'s `sendUnit`/`completePaymentPayload` flow that `storage.getOversizeFee(objUnit, last_ball_mci, true)` returns a fee that grows exponentially with the excess size, and this fee is deducted from the AA's `base` balance without any check against `headers_commission + payload_commission` (unlike the `max_fee_ratio` check present in `composer.js:522-529`).
4. Repeat with progressively larger trigger data to demonstrate the AA balance being drained at a rate disproportionate to the size increase, verifying the exponential/unbounded nature of the charge.

### Citations

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

**File:** composer.js (L522-529)
```javascript
	], function(err){
		if (!err && last_ball_mci >= constants.v4UpgradeMci) {
			const size_fees = objUnit.headers_commission + objUnit.payload_commission;
			const additional_fees = (objUnit.oversize_fee || 0) + objUnit.tps_fee;
			const max_ratio = params.max_fee_ratio || conf.max_fee_ratio || 100;
			if (additional_fees > max_ratio * size_fees)
				err = `additional fees ${additional_fees} (oversize fee ${objUnit.oversize_fee || 0} + tps fee ${objUnit.tps_fee}) would be more than ${max_ratio} times the regular fees ${size_fees}`;
		}
```

**File:** aa_composer.js (L1399-1403)
```javascript
						objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
						const oversize_fee = (mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci, true) : 0;
						if (oversize_fee)
							objUnit.oversize_fee = oversize_fee;
						objUnit.unit = objectHash.getUnitHash(objUnit);
```

**File:** validation.js (L766-779)
```javascript
							return callback("should have no witness_list_unit since version 4.0");
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
						}
```

**File:** initial_votes.js (L34-36)
```javascript
	const timestamp = 1724716800; // 27 Aug 2024
	const threshold_size = 10000;
	const base_tps_fee = 10;
```
