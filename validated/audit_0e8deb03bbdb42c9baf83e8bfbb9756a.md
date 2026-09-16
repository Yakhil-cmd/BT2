### Title
AA trigger identity (`trigger.address`) is derived from author-array sort order, not from the payer of the triggering funds - (File: `aa_composer.js`)

### Summary
`aa_composer.js`'s `getTrigger()` sets the AA's `trigger.address` (and `trigger.initial_address`) to `objUnit.authors[0].address` unconditionally. [1](#0-0)  Because `unit.authors` must be sorted lexicographically by address (enforced in `validateAuthors`), "author[0]" is simply whichever signing address happens to sort first alphabetically - it has no necessary relationship to which author's funds actually paid into the AA. [2](#0-1)  `trigger.address` is exposed directly to oscript/AA formulas (`trigger.address`, `trigger.initial_address`) and is the standard identity value AA authors use to attribute a trigger to "the sender". [3](#0-2) 

### Finding Description
A single unprivileged unit poster (an "AA trigger sender") can construct a multi-authored unit consisting of:
1. A freshly-generated, otherwise-unused "sacrificial" address `A` chosen so that it sorts alphabetically before the real funding address (trivial - just keep generating addresses until one sorts first), added purely as a co-signing author with no economic stake in the transaction.
2. The attacker's real address `B`, which actually supplies the payment output(s) to the AA.

Because `unit.authors` must be sorted by address, `A` becomes `authors[0]`. [4](#0-3)  `getTrigger()` computes `trigger.address = objUnit.authors[0].address`, i.e., `A`, even though `B` is the address whose funds the payment message actually spent (the payment-input validation only requires the payer to be *some* author, not `authors[0]`). [1](#0-0) [5](#0-4) 

Any AA logic that treats `trigger.address` as "the identity of whoever is triggering/paying" - e.g., per-address rate limiting or one-time bonuses, tracking a depositor's balance for later withdrawal by the same address, or gating access via an `attested` condition on `trigger.address` - can be defeated: the attacker mints a brand-new low-sorting throwaway address for every trigger, so `trigger.address` never repeats and never matches the real (attested/whitelisted/rate-limited) payer address `B`, while the funds still flow from `B`. Conversely, state that an AA associates with `trigger.address` (e.g. "this state belongs to address X, and only a trigger from X can withdraw it") can be attached to an attacker-chosen throwaway address instead of the true funding address, letting the attacker separate "who is recognized" from "who actually paid," undermining any access-control or accounting logic built on that assumption. This is analogous to the vela webhook CVE's core problem (CWE-345 Insufficient Verification of Data Authenticity / CWE-290 Authentication Bypass by Spoofing): a value used as an authoritative identity claim (`repo` owner in vela, `trigger.address` here) is taken from unauthenticated/attacker-controllable structural metadata (webhook body fields there, author-array sort order here) instead of being cryptographically bound to the actual party performing the sensitive action (the payer).

### Impact Explanation
AA authors commonly rely on `trigger.address` to attribute deposits, enforce single-use vouchers/airdrops, implement per-address limits, or gate access with an `attested` condition. Because that address is not bound to the actual payer, an attacker can spoof the recognized "sender" identity on every trigger (by minting a new sorting-first author) while keeping the real funding source constant, or vice versa attach AA state/entitlements to a throwaway identity instead of the account that is supposed to be recognized. Depending on the specific AA's logic this can lead to: bypass of one-time/per-address restrictions to repeatedly drain a bonus/faucet AA (fund loss), bypass of `attested`/KYC-gated withdrawal conditions, or state confusion that can freeze or misdirect AA funds - all "AA fund loss or freezing" outcomes explicitly in scope.

### Likelihood Explanation
Exploitation requires nothing more than the ability to generate new addresses (free and instant) and craft an ordinary multi-authored unit with a second, real funding address - both are standard, unprivileged operations available to any wallet user or bot interacting with an AA. No special network position, hub/witness compromise, or protocol-level trust is needed; a single posted unit triggering an AA is sufficient.

### Recommendation
Do not treat `authors[0].address` as an authenticated "trigger sender" identity for the purpose of AA fund/state accounting when a payment is combined from multiple co-authors. Either bind `trigger.address` to the specific author whose address matches the payer in the payment message that funds the trigger (rather than the lexicographically-first author), or explicitly document/restrict `trigger.address` semantics so AA authors do not use it as an authenticated payer identity in multi-author units, and provide a distinct, unambiguous field (e.g., derived strictly from the input-owning address of the funding payment) for that purpose.

### Proof of Concept
1. Generate address `A` (throwaway) such that `A < B` lexicographically, where `B` is the attacker's real funding address.
2. Compose a unit with two authors, `A` and `B` (sorted `[A, B]` as required), where the `payment` message's inputs/outputs are funded solely by `B`, sending to AA address `X`.
3. Post the unit. `aa_composer.getTrigger()` sets `trigger.address = A` (not `B`). [6](#0-5) 
4. Any AA logic keyed on `trigger.address` (e.g. "one claim per address", `attested` check on `trigger.address`) sees a brand-new, unrestricted identity `A` on every repetition, even though the real payer `B` is constant and may already be rate-limited/blacklisted/already-claimed.
5. Repeat with a fresh throwaway `A'` each time to bypass address-based restrictions indefinitely while draining/abusing the AA.

### Citations

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** validation.js (L1128-1140)
```javascript
function validateAuthors(conn, arrAuthors, objUnit, objValidationState, callback) {
	if (objValidationState.bAA && arrAuthors.length !== 1)
		throw Error("AA unit with multiple authors");
	if (arrAuthors.length > constants.MAX_AUTHORS_PER_UNIT) // this is anti-spam. Otherwise an attacker would send nonserial balls signed by zillions of authors.
		return callback("too many authors");
	objValidationState.arrAddressesWithForkedPath = [];
	var prev_address = "";
	for (var i=0; i<arrAuthors.length; i++){
		var objAuthor = arrAuthors[i];
		if (objAuthor.address <= prev_address)
			return callback("author addresses not sorted");
		prev_address = objAuthor.address;
	}
```

**File:** validation.js (L2499-2501)
```javascript
							var owner_address = src_output.address;
							if (arrAuthorAddresses.indexOf(owner_address) === -1)
								return cb("output owner is not among authors");
```

**File:** formula/evaluation.js (L1062-1072)
```javascript
			case 'this_address':
				cb(address);
				break;

			case 'trigger.address':
				cb(trigger.address);
				break;

			case 'trigger.initial_address':
				cb(trigger.initial_address);
				break;
```
