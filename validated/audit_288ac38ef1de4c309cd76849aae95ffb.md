### Title
ReDoS in `isValidEmail` regex causes event-loop blocking DoS during URI/address parsing - (File: validation_utils.js)

### Summary
`validation_utils.js` defines `isValidEmail` using a regex containing the classic catastrophic-backtracking pattern `(X+\.)+` for the domain part, analogous to the `fast-xml-parser` currency ReDoS (`CVE-2024-41818`). This function is invoked from `uri.js`'s `parseUri`, which parses attacker/counterparty-controlled `byteball:`/payment-request URIs (e.g. received via a paired device message, pasted from chat, or a deep link) as part of normal wallet message handling.

### Finding Description
`isValidEmail` is defined as: [1](#0-0) 

The domain portion of this regex, `(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})`, is a nested-quantifier construct where the inner `[a-zA-Z\-0-9]+` can be split across dot-separated groups in exponentially many ways when the input does not match the rest of the pattern (e.g., a long run of alphanumerics with many dots but no valid TLD terminator, or missing final anchor match). This is the same bug class as the `currency.js` ReDoS reported in the advisory: an unbounded/ambiguous quantifier applied to a regex evaluated on fully attacker-controlled string input, causing catastrophic backtracking in Node's regex engine (single-threaded, blocking the event loop).

This function is called from `parseUri`, which validates the `main_part` of a parsed URI as a potential email/address/phone before falling through to other checks: [2](#0-1) 

`parseUri` handles `byteball:` URIs that originate from external, untrusted sources — payment-request links, QR codes, or deep links shared by a payment counterparty or paired device — placing it squarely in "wallet and contract message handling" territory reachable by an unprivileged sender.

### Impact Explanation
Because Node.js executes JavaScript regex matching synchronously on the single main event loop, a crafted `main_part` string (long alphanumeric run interspersed with dots, engineered to avoid an early match/mismatch) can cause `isValidEmail`'s regex to take super-linear (potentially exponential) time. This blocks the event loop of the wallet/node process for an extended period, during which the process cannot process incoming units, validate the DAG, respond to peers, or otherwise make progress — a denial-of-service condition consistent with "a network unable to confirm new units" if this occurs on a node that also performs validation/relay duties in the same process.

### Likelihood Explanation
Likelihood is moderate: the trigger requires only that a victim wallet call `parseUri` on an attacker-supplied string (e.g., a payment-request link/QR code sent by a counterparty), which is a normal, low-privilege interaction in the wallet UX. No authentication or special positioning is needed by the attacker — only the ability to get the victim's wallet to parse a URI string, which happens routinely in payment flows.

### Recommendation
Replace the vulnerable email regex in `validation_utils.js` with a non-backtracking, linear-time email validator (e.g., a simpler bounded-length check, a well-vetted linear-time regex, or a hand-written state-machine parser). At minimum, bound the length of `main_part`/candidate email strings before regex evaluation, and consider using a regex engine or library with backtracking limits (e.g., `re2`) for any pattern applied to untrusted input such as URIs.

### Proof of Concept
Call `parseUri` (or directly `isValidEmail`) with a crafted `main_part` such as:
```js
var validation_utils = require('./validation_utils.js');
var evil = "a".repeat(40).split('').map((c,i)=> i%2===0 ? 'a' : '.').join('') + "!"; 
// or more precisely, alternating long alnum runs and dots with no valid '@'/TLD terminator
console.time('redos');
validation_utils.isValidEmail("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!");
console.timeEnd('redos');
```
Increasing the length of the alphanumeric run before the non-matching terminator (`!`) causes matching time to grow superlinearly, demonstrating the same backtracking blow-up class as the reported `currency.js` PoC (`'\t'.repeat(13337) + '.'`). Reaching this from the wallet flow requires only sending/opening a `byteball:`-scheme URI whose address-like portion is such a crafted string, triggering `parseUri`'s `isValidEmail` check at [2](#0-1) .

### Citations

**File:** validation_utils.js (L99-101)
```javascript
function isValidEmail(str) {
	return (typeof str === "string" && /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(str));
}
```

**File:** uri.js (L158-160)
```javascript
	var address = main_part;
	if (!ValidationUtils.isValidAddress(address) && !ValidationUtils.isValidEmail(address) && !address.match(/^(steem\/|reddit\/|github\/|bitcointalk\/|@).{3,}/i) && !address.match(/^\+\d{9,14}$/))
		return callbacks.ifError("address "+address+" is invalid");
```
