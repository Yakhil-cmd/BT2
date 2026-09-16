### Title
Missing Validation of `arbstore_address` Before Composing Arbiter Contract Completion Payment - ([File: arbiter_contract.js])

### Summary
`complete()` in `arbiter_contract.js` builds a payment (`opts.asset_outputs`/`opts.base_outputs`) that pays out `arbstore_amount` to `objContract.arbstore_address`, but this address is filled in earlier by `fillArbstoreAddresses(objContract)` and is never validated to be a non-empty, valid address before being used as an output destination. This mirrors the reported bug class: an address retrieved from storage/state and used to route a payment/response without a "not zero/empty" check.

### Finding Description
In `complete(hash, walletInstance, arrSigningDeviceAddresses, cb)`, when `objContract.me_is_payer` and the asset is not private/fixed-denomination, the code reads the shared address definition and extracts `arbstore_amount` from it, then does: [1](#0-0) 
```
if (arbstore_amount === 0) {
    opts.to_address = objContract.peer_address;
    opts.amount = objContract.amount;
} else {
    opts[objContract.asset && objContract.asset != "base" ? "asset_outputs" : "base_outputs"] = [
        { address: objContract.peer_address, amount: peer_amount},
        { address: objContract.arbstore_address, amount: arbstore_amount},
    ];
}
```
`objContract.arbstore_address` originates from `fillArbstoreAddresses(objContract)` called earlier in the same function [2](#0-1) . That helper is only invoked to succeed/fail via an `err` return, and its success path is trusted to have populated `objContract.arbstore_address` correctly, but there is no explicit re-check with `ValidationUtils.isValidAddress(objContract.arbstore_address)` (or a not-empty check) immediately before it is used as a payment output address in `complete()`. If `arbstore_address` were ever empty/stale/mismatched (e.g., due to a race in updating arbiter/arbstore info, a partially-completed `fillArbstoreAddresses` call, or a contract object read before that field was populated), the resulting `opts.asset_outputs`/`opts.base_outputs` would contain an invalid or empty destination address for the arbstore cut.

This differs from other payment paths in the codebase (e.g., `sendMultiPayment`, `aa_composer.js` bounce checks) where addresses used as payment destinations are checked with `ValidationUtils.isValidAddress` before or at the point of use. Here, the address is consumed directly from the mutable `objContract` object without a defensive check colocated with its use as a payment destination — exactly the class of bug described in the report (retrieving an address from storage and using it to route funds/messages without validating it is non-zero/non-empty).

### Impact Explanation
If `arbstore_address` is empty or invalid at the time `complete()` composes the payment, the wallet either:
- Fails deep inside the payment composer with an unhandled/opaque error (denial of service for contract completion, funds stuck in the shared address), or
- In degenerate cases, could construct a payment whose commission-share output is malformed, jeopardizing correct settlement of the arbstore's cut and complicating dispute resolution/fund release for the arbiter contract.

Given this touches the fund-settlement path of arbiter contracts (a wallet/contract message handling feature reachable by any user with an open contract), a missing check could result in fund-freezing or an inability to correctly complete contract settlement, matching the "AA fund loss or freezing" / "node disagreement on validity" class of impact the validation rules require, at Medium severity (funds are only at risk of being stuck/misrouted for the arbstore cut, not the whole balance, and requires a state inconsistency to manifest).

### Likelihood Explanation
The likelihood is Medium: this path only triggers when `objContract.me_is_payer` is true, the asset is not private/fixed-denomination, and `fillArbstoreAddresses` has not (yet) correctly populated `objContract.arbstore_address` when `complete()` runs. This can plausibly occur due to the asynchronous nature of `arbiters.getArbstoreInfo`/`getInfo` and repeated calls to `fillArbstoreAddresses` across the contract lifecycle (`openDispute`, `deriveSharedAddress`, `complete`), where a stale or partially-filled contract object could be used.

### Recommendation
Add an explicit check before composing the payment in `complete()`:
```js
if (arbstore_amount > 0 && !ValidationUtils.isValidAddress(objContract.arbstore_address))
    throw new Error("invalid or missing arbstore_address for contract " + objContract.hash);
```
placed immediately before constructing `opts.asset_outputs`/`opts.base_outputs`, mirroring the recommendation from the external report (reject/execute early return if the address is not valid, rather than trusting it implicitly from a prior async fill step).

### Proof of Concept
1. Create/accept an arbiter contract with a non-private, non-fixed-denomination asset and `hasArbStoreCut` true, so `arbstore_amount > 0`.
2. Trigger a race/edge case where `objContract.arbstore_address` is empty when `complete()` is invoked (e.g., call `complete()` immediately after a contract state transition, before any code path has awaited a successful `fillArbstoreAddresses`, or simulate `arbiters.getArbstoreInfo` returning no/invalid address).
3. Observe that `complete()` proceeds to build `opts.asset_outputs`/`opts.base_outputs` with `address: objContract.arbstore_address` set to an empty/invalid value and calls `walletInstance.sendMultiPayment(opts, ...)`, which will fail deep in composition or produce an invalid destination, rather than being rejected immediately with a clear, contract-specific error at the point of use.

### Citations

**File:** arbiter_contract.js (L719-726)
```javascript
function complete(hash, walletInstance, arrSigningDeviceAddresses, cb) {
	getByHash(hash, async function(objContract) {
		if (objContract.status !== "paid" && objContract.status !== "in_dispute")
			return cb("contract can't be completed");
		const err = await fillArbstoreAddresses(objContract);
		if (err)
			return cb(err);
		storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
```

**File:** arbiter_contract.js (L761-771)
```javascript
							if (arbstore_amount > peer_amount)
								throw new Error(`arbstore cut is more than 50% of the total amount, peer_amount: ${peer_amount}, arbstore_amount: ${arbstore_amount}`);
							if (arbstore_amount === 0) {
								opts.to_address = objContract.peer_address;
								opts.amount = objContract.amount;
							} else {
								opts[objContract.asset && objContract.asset != "base" ? "asset_outputs" : "base_outputs"] = [
									{ address: objContract.peer_address, amount: peer_amount},
									{ address: objContract.arbstore_address, amount: arbstore_amount},
								];
							}
```
