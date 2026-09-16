### Title
Insufficient Contract Expiration via Unvalidated `creation_date` Causes NaN TTL Check to Never Expire - ([File: wallet.js])

### Summary
`prosaic_contract_offer` and `arbiter_contract_offer` device messages accept an attacker/peer-supplied `creation_date` string that is validated only with a loose regex (`^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$`), which checks digit *format* but not calendar validity. This string is later turned into a JS `Date` object (`creation_date_obj`) and used together with the contract's `ttl` to decide whether a contract offer/response has expired. An out-of-range date (e.g. month/day/hour `99`) produces an `Invalid Date`, whose arithmetic always yields `NaN`. Since any comparison against `NaN` is `false`, the "contract already expired" check silently fails open — exactly analogous to the `@cyyynthia/tokenize` bug where a `NaN` generation date made tokens never expire regardless of the invalidation field.

### Finding Description
A correspondent/paired device can send a `prosaic_contract_offer` or `arbiter_contract_offer` message to another wallet. The `creation_date` field is validated only by format, not by actual calendar validity: [1](#0-0) [2](#0-1) 

The value is stored as-is and later converted to a `Date` object in `decodeRow`: [3](#0-2) 

When the contract is later responded to (`prosaic_contract_response` / `arbiter_contract_response`), the code computes an expiration boundary from `creation_date_obj` and `ttl`, and rejects the response if the boundary is in the past: [4](#0-3) [5](#0-4) 

If `creation_date` is a string like `"9999-99-99 99:99:99"` (which passes the regex but is not a real date), `new Date(...)` produces an `Invalid Date`. Calling `.getHours()`/`.getMinutes()`/`.getSeconds()` on it returns `NaN`, `setHours(NaN, NaN, NaN)` returns `NaN`, and the comparison `NaN < Date.now()` always evaluates to `false`. The expiry guard therefore never fires, regardless of the actual (stale) age of the offer or the `ttl` value — the contract offer effectively never expires, exactly like the referenced `@cyyynthia/tokenize` NaN-generation-date bug that let tokens live forever "regardless of the `lastTokenReset` field."

The `ttl` field itself is checked to be a positive number (`body.ttl > 0`), so the flaw is isolated to the unchecked date-format validation, not the ttl validation.

### Impact Explanation
The expiry mechanism is a security control intended to prevent stale prosaic/arbiter contract offers — which can commit funds via shared multisig addresses and arbiter-mediated payments — from being accepted or acted upon indefinitely. By crafting a malformed (but regex-valid) `creation_date`, a malicious paired device can force its own offer/response window to never close. This lets an attacker hold a counterparty's device to an old commercial or payment-related agreement far beyond its intended validity, or manipulate response acceptance windows in ways the protocol design explicitly tries to prevent (auto-invalidate stale offers). Since arbiter contracts can lead to real fund commitments via `wallet_arbiter_contracts` shared addresses, this weakens a safety boundary meant to protect private-payment/contract counterparties from stale/expired terms.

### Likelihood Explanation
Trivially reachable: any paired/correspondent device can send `prosaic_contract_offer` or `arbiter_contract_offer` with an attacker-chosen `creation_date` string that satisfies the regex `^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$` but is not a real calendar date (e.g., `"2024-13-40 25:61:61"`). No special privileges beyond an established device pairing are required, matching the "paired device" reachability allowed by scope.

### Recommendation
Validate that `creation_date` represents an actual valid calendar date/time (e.g., parse and confirm `!isNaN(Date.parse(...))`, or reconstruct and compare the string, similar to the pattern already used in `evaluation.js`'s `parse_date` for AA formulas) before accepting `prosaic_contract_offer` / `arbiter_contract_offer` messages. Additionally, treat a `NaN` result from the expiry computation as "expired" (fail closed) rather than defaulting to `false` on invalid dates.

### Proof of Concept
1. Device B sends Device A a `prosaic_contract_offer` (or `arbiter_contract_offer`) message with `creation_date: "9999-99-99 99:99:99"` — this passes the `/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/` check in `wallet.js`.
2. Device A stores the contract; `decodeRow` sets `creation_date_obj = new Date("9999-99-99T99:99:99.000Z")`, which is an `Invalid Date`.
3. Later, Device B sends a `prosaic_contract_response`/`arbiter_contract_response` (potentially long after the offer's intended `ttl` window).
4. In `wallet.js`, `objDateCopy.setHours(NaN, NaN, NaN)` returns `NaN`; `NaN < Date.now()` is `false`, so the `"contract already expired"` branch is never taken — the response is accepted no matter how much time has passed.

### Citations

**File:** wallet.js (L470-471)
```javascript
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
```

**File:** wallet.js (L548-552)
```javascript
						if (objContract.status !== 'pending')
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
```

**File:** wallet.js (L628-629)
```javascript
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
```

**File:** wallet.js (L909-914)
```javascript
						var isAllowed = objContract.status === "pending" || (objContract.status === 'accepted' && body.status === 'accepted');
						if (!isAllowed)
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
```

**File:** prosaic_contract.js (L106-110)
```javascript
function decodeRow(row) {
	if (row.cosigners)
		row.cosigners = JSON.parse(row.cosigners);
	row.creation_date_obj = new Date(row.creation_date.replace(' ', 'T')+'.000Z');
	return row;
```
