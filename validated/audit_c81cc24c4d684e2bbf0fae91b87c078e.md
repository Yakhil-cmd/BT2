### Title
Unbounded private-payment `chains` array in a single device message causes per-chain fan-out into unbounded validation/DB transactions - (File: wallet.js)

### Summary
`handlePrivatePaymentChains()` in `wallet.js` accepts a single incoming device message whose `body.chains` field is only checked for being a non-empty array, with no upper bound on the number of chains. Each element is then fanned out into a full, independent private-payment validation and database-write pipeline via `network.handleOnlinePrivatePayment()` → `privatePayment.validateAndSavePrivatePaymentChain()`, mirroring the vLLM bug where an unbounded outer list turns one request into an attacker-controlled number of backend subrequests.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` is invoked by `wallet.js` for the `"private_payments"` message subject, which is delivered to any device correspondent (a private-payment counterparty) through the hub message-handling path (`handleMessageFromHub`).

The function's only guard on the outer list is: [1](#0-0) 

```js
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
```

There is no `MAX_CHAINS`-style cap analogous to `MAX_MESSAGES_PER_UNIT`, `MAX_INPUTS_PER_PAYMENT_MESSAGE`, `MAX_SPEND_PROOFS_PER_MESSAGE`, or `MAX_DATA_FEEDS_PER_MESSAGE` that ocore enforces almost everywhere else a unit-embedded array can be attacker-supplied. [2](#0-1) 

After the shallow shape check on each chain element, the code iterates the full `arrChains` array and, for every element, performs a full asynchronous validation-and-persist cycle: [3](#0-2) 

```js
async.eachSeries(
	arrChains,
	function(arrPrivateElements, cb){ // validate each chain individually
		...
		network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, { ... });
	},
	...
);
```

`network.handleOnlinePrivatePayment()` in turn calls `privatePayment.validateAndSavePrivatePaymentChain()`, which for every chain: reads the asset definition from the DB, takes a DB connection from the pool, begins a transaction, executes duplicate-detection queries, and (on success) delegates to `indivisible_asset.js`/`divisible_asset.js` to run the full spend-proof/signature/hash validation and issue `INSERT`/`UPDATE` queries per chain element: [4](#0-3) [5](#0-4) 

Because `arrChains.length` is entirely attacker-controlled and unbounded, a single incoming `private_payments` message causes an attacker-chosen number of DB connection pool acquisitions, transactions, and cryptographic validations — the same "one request → N backend subrequests, no aggregate bound" pattern flagged in the vLLM advisory (list of prompts → list of engine generators). Note that `handleOnlinePrivatePayment()` itself does apply a per-chain length distinction for light clients (`arrPrivateElements.length > 1`), but this only affects a single chain's internal element count, not the number of chains in the outer array.

### Impact Explanation
A correspondent device (a normal, paired private-payment counterparty — not an operator, hub, or node-level attacker) can send one `private_payments` message with tens of thousands of `chains` entries. Each entry triggers: a DB connection checkout, a `BEGIN`/transaction, multiple `SELECT`/`INSERT`/`UPDATE` queries, and full asset/spend-proof/definition validation logic (`validateAndSavePrivatePaymentChain`, `validatePrivatePayment`, `parsePrivatePaymentChain`). This can exhaust the DB connection pool, drive high CPU/memory usage, and stall or crash the recipient wallet/hub-connected node, denying it the ability to process legitimate payments or unit validation — a "network unable to confirm new units" style disruption for the targeted node. This matches the CWE-400 / uncontrolled resource consumption class of the analog report.

### Likelihood Explanation
Likelihood is high for any node that accepts private-payment chat messages from paired devices (the standard wallet flow, including textcoin claims and multi-device payment flows). No special privilege beyond being a paired correspondent is required, and the payload is a simple JSON array that any device-messaging client can construct arbitrarily large. The check present (`isNonemptyArray`) does nothing to bound size, unlike virtually every other array field derived from a posted unit or trigger in this codebase (messages, inputs, outputs, spend proofs, data feeds, denominations, attestors, poll choices, `foreach` counts, array literals, `weighted and` set sizes), all of which have explicit caps.

### Recommendation
Add an explicit upper bound on `body.chains.length` in `handlePrivatePaymentChains()` (and correspondingly in `network.handleOnlinePrivatePayment` for the batch-forwarding paths that call it), analogous to `constants.MAX_MESSAGES_PER_UNIT`/`MAX_SPEND_PROOFS_PER_MESSAGE`. Reject the whole message with a validation error before any per-chain DB work begins (i.e., before the `async.eachSeries(arrChains, ...)` loop and before `network.requestUnfinishedPastUnitsOfPrivateChains(arrChains)` is invoked for light clients), so that an oversized `chains` array cannot trigger any connection-pool acquisition, transaction, or cryptographic validation. Add regression tests covering: a single chain, a bounded batch, and an oversized batch that must be rejected pre-validation.

### Proof of Concept
A malicious paired device sends, over the hub, a `private_payments` justsaying/message with a body such as:
```json
{
  "subject": "private_payments",
  "body": {
    "chains": [ /* tens of thousands of syntactically-valid single-element chains,
                   each satisfying the isNonemptyObject/isNonemptyString shape checks
                   in handlePrivatePaymentChains but referring to bogus/duplicate units */ ]
  }
}
```
Because `handlePrivatePaymentChains` only checks `isNonemptyArray(arrChains)` before iterating and invoking `network.handleOnlinePrivatePayment` (and subsequently `validateAndSavePrivatePaymentChain`) once per array element, the recipient device/hub-connected node performs one DB transaction and full validation pipeline per array element with no cap, exhausting DB connections/CPU proportional to the attacker-chosen array length — unlike a single small `chains` array, which is the intended, cheap negative-control case.

### Citations

**File:** wallet.js (L955-958)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
```

**File:** wallet.js (L1020-1035)
```javascript
	async.eachSeries(
		arrChains,
		function(arrPrivateElements, cb){ // validate each chain individually
			var objHeadPrivateElement = arrPrivateElements[0];
			if (!!objHeadPrivateElement.payload.denomination !== ValidationUtils.isNonnegativeInteger(objHeadPrivateElement.output_index))
				return cb("divisibility doesn't match presence of output_index");
			var output_index = objHeadPrivateElement.payload.denomination ? objHeadPrivateElement.output_index : -1;
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
```

**File:** constants.js (L42-55)
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
```

**File:** private_payment.js (L23-46)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
```

**File:** network.js (L2412-2429)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
```
