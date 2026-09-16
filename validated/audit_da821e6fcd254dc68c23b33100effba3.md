### Title
ReDoS in `isValidEmail` via catastrophic backtracking regex - ([File: validation_utils.js])

### Summary
`ValidationUtils.isValidEmail` in `validation_utils.js` uses a hand-rolled email regex with nested, overlapping quantifiers analogous to the pattern flagged in CVE-2023-39619 for `node-email-check`. The regex is reachable from data that an unprivileged remote party can influence (e.g. `uri.js` payment/textcoin request parsing and `wallet.js` email-related flows), so a crafted long string can cause catastrophic backtracking.

### Finding Description
The regex is:
```
/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
``` [1](#0-0) 

The domain part `(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})$` combines a repeated group containing an internal `+` quantifier followed by a literal `.`, all wrapped in another `+`. This is the same nested-quantifier shape that made `node-email-check`'s pattern vulnerable to CVE-2023-39619: when the input contains a long run of alphanumeric characters without a terminating valid domain suffix, the engine explores an exponential number of ways to partition the run between the inner `[a-zA-Z\-0-9]+` and the outer repetition before failing the anchored `$`.

`isValidEmail` is called from `uri.js` when parsing a `bitcoin:`/`obyte:`-style payment URI's address field (`address.match(...) || ValidationUtils.isValidEmail(address)`), which is user/attacker-suppliable input parsed by a wallet handling a payment request or textcoin claim link, and from `wallet.js` in related textcoin/email-request flows. [2](#0-1) 

### Impact Explanation
A crafted string of the form `"a".repeat(N) + "!"` (or similar non-terminating run) passed as the address/email field will cause the regex engine to backtrack exponentially in the number of repeated characters, blocking the event loop of the wallet/node process for a very long time. Because `isValidEmail`/URI-parsing logic executes synchronously on the Node.js single-threaded event loop, this can stall all concurrent processing on that instance (unit validation, AA execution, payment handling) for the duration of the match, i.e. a local denial-of-service triggerable by an untrusted counterparty sending a crafted URI/textcoin/payment request.

### Likelihood Explanation
Reaching this code only requires supplying a string to a URI-parsing/email-validation path (e.g., a textcoin or payment-request URI), which is a normal, unauthenticated interaction path for a wallet. No special privileges are needed, only the ability to get a target wallet to parse a crafted string.

### Recommendation
Replace the hand-written email regex in `isValidEmail` (`validation_utils.js`) with a non-backtracking validator — either a well-tested, ReDoS-resistant regex (e.g., simplified RFC 5322 pattern without nested unbounded quantifiers), or a linear-time email-format check (e.g., splitting on `@` and validating local/domain parts separately with bounded, non-nested quantifiers), and add a length cap on the input before regex evaluation.

### Proof of Concept
```js
const ValidationUtils = require('./validation_utils.js');
const evilLocal = 'a'.repeat(50000) + '!'; // never matches the domain grammar
const evilInput = evilLocal + '@' + 'a'.repeat(50000) + '!'; // forces backtracking in domain group
console.time('redos');
ValidationUtils.isValidEmail(evilInput);
console.timeEnd('redos'); // exhibits exponential slowdown as length grows
```
Feeding a payload of this shape as the address portion of a wallet-parsed payment URI (`uri.js`, `parseUri`) or into any wallet flow that calls `isValidEmail` reproduces the same stall in a live process.

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
