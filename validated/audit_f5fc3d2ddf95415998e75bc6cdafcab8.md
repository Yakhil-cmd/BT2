### Title
AA trigger identity is bound to `authors[0]` instead of the address that actually funded the payment - ([File: aa_composer.js])

### Summary
The Socket incident stemmed from a swap module that authorized moving a user's approved funds based on the wrong "owner" identity — it trusted an attacker-influenced address instead of verifying the actual approver, letting one user's funds be attributed/spent on behalf of another. In `ocore`, the AA (Autonomous Agent) trigger-construction logic has an analogous identity-binding flaw: `trigger.address`, which every AA uses as the canonical "who sent this money / who to credit or refund," is hardcoded to `objUnit.authors[0].address` rather than to the address that actually owns the coins credited to the AA.

### Finding Description
`getTrigger()` builds the trigger object AAs execute against: [1](#0-0) 

```
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	...
```

`trigger.address` is unconditionally set to the address of the **first author** in the unit's `authors` array — it is never cross-checked against which author's spent output actually funded the `payment` message's outputs credited to the AA (`trigger.outputs`). This is the single field AA authors are told to trust as "the sender" (used throughout the AA scripting language for state-var keying, refunds, and access control, e.g. `var['balance_' || trigger.address || ...]` in the shipped sample templates): [2](#0-1) [3](#0-2) 

`ocore`'s wallet/composer layer routinely produces multi-authored units where the address that pays network fees (`fee_paying_addresses`) is different from the address whose coins are actually transferred as the asset payment (`paying_addresses`): [4](#0-3) 

Because `unit.authors` are canonically address-sorted (not composed in wallet-intent order) and payment validation only enforces that "the output owner is among the unit's authors" — not that the owner is `authors[0]` specifically — [5](#0-4) 

the address that actually owns the spent output funding the AA deposit can end up at `authors[1]` (or later), while an unrelated co-author (e.g. a fee-paying address) sorts first and becomes `authors[0]`. `getTrigger()` then reports that unrelated address as `trigger.address` to the AA, mis-attributing the deposit's identity.

This is architecturally the same bug class as Socket: a fund-moving module resolves "who owns/authorized this value" from the wrong field (first signer / first approver-looking identity) instead of verifying it against the entity that actually supplied the funds.

### Impact Explanation
Any AA whose logic keys balances, ownership, withdrawal rights, one-time bonuses, deposit caps, KYC/attestation gating, or auction/order identity off `trigger.address` (the pattern used throughout the shipped `test/samples/*.oscript` reference templates, i.e. this is the officially recommended pattern for AA authors) can be tricked into crediting/debiting the wrong address whenever the triggering unit is composed with more than one author and the value-supplying address is not the address that sorts first. This can result in funds being credited to an attacker-chosen identity distinct from whichever address actually funded the deposit, double-claiming of per-address one-time benefits, or state corruption that lets one identity siphon value intended for another user's balance key inside the AA — a concrete AA fund-loss/misattribution scenario, in the same spirit as Socket's approved-fund misdirection.

### Likelihood Explanation
Likelihood is Medium: exploitation requires a unit author (an ordinary, unprivileged unit poster / AA trigger sender) to deliberately construct a two-author unit (e.g., using a distinct fee-paying address alongside the value-paying address, a supported and common wallet composition pattern), and requires the target AA to trust `trigger.address` for identity-sensitive logic without additionally validating that the value came specifically from that same author — which is exactly the pattern used in the project's own canonical AA examples (bank, order-book exchange, market-maker). No privileged access, malicious peer, or protocol-consensus break is needed; it's directly reachable by any address that can post a multi-authored unit to an AA.

### Recommendation
- In `getTrigger()`, do not silently default `trigger.address` to `authors[0]`. Either restrict qualifying AA triggers to single-authored units, or expose to the AA formula language the exact set of authors that funded each specific asset's `trigger.outputs`, so AA authors can bind identity to the actual coin owner rather than to an arbitrary first-sorted author.
- At minimum, document and enforce (at validation time) that `trigger.address`-based identity is only safe for single-author trigger units, and consider rejecting/flagging multi-author payments to AAs where the addresses funding `trigger.outputs` differ from `authors[0]`.
- Update the reference AA templates (`test/samples/*.oscript`) accordingly, since they are the pattern developers copy.

### Proof of Concept
1. Deploy an AA using the canonical "bank" pattern that keys balances by `trigger.address` (as in `test/samples/a_bank_without_percent.oscript`).
2. From a wallet, compose a payment to the AA using `paying_addresses: [addrA]` (the address whose coins fund the deposit) and `fee_paying_addresses: [addrB]`, where `addrB < addrA` lexicographically, causing `objUnit.authors = [addrB, addrA]` after canonical sorting (per `composer.js`'s `paying_addresses: _.union(...)` union/sort behavior).
3. The AA receives `trigger.outputs` reflecting the value sent from `addrA`'s spent output, but `getTrigger()` sets `trigger.address = objUnit.authors[0].address = addrB`.
4. The AA credits/records the deposit under `addrB`'s state-var key instead of `addrA`'s, even though `addrA` supplied the funds — demonstrating the identity/fund-attribution confusion.

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

**File:** test/samples/a_bank_without_percent.oscript (L1-30)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{trigger.data.asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.data.amount}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var[$key] = var[$key] - trigger.data.amount;
							var[$base_key] = var[$base_key] - $fee;
						}`
					}
				]
			},
```

**File:** test/samples/order_book_exchange.oscript (L1-26)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND trigger.data.amount <= var[$key]
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{trigger.data.asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.data.amount}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var[$key] = var[$key] - trigger.data.amount;
						}`
					}
				]
			},
```

**File:** composer.js (L221-234)
```javascript
		app: "payment",
		payload_location: "inline",
		payload_hash: hash_placeholder,
		payload: {
			inputs: [],
			// first output is the change, it has 0 amount (placeholder) that we'll modify later. 
			// Then we'll sort outputs, so the change is not necessarity the first in the final transaction
			outputs: arrChangeOutputs
			// we'll add more outputs below
		}
	};
	var total_amount = 0;
	arrExternalOutputs.forEach(function(output){
		objPaymentMessage.payload.outputs.push(output);
```

**File:** validation.js (L2499-2501)
```javascript
							var owner_address = src_output.address;
							if (arrAuthorAddresses.indexOf(owner_address) === -1)
								return cb("output owner is not among authors");
```
