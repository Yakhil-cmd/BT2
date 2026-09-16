### Title
Stale ArbStore payout address/cut baked into an immutable shared-address definition can strand or misroute contract funds - (File: arbiter_contract.js)

### Summary
This is analogous to the reported `withdrawalWallet` desync bug: one place (`arbiters.getArbstoreInfo`, cached in memory and used at contract/shared-address creation time in `deriveSharedAddress`) permanently bakes an ArbStore payout address and cut into an *immutable* on-DAG address definition, while a second, independent code path (`fillArbstoreAddresses`, used later at `complete()`/`openDispute()`/`appeal()` time) re-fetches the ArbStore's address fresh from the hub/ArbStore server. If the ArbStore's registered payout address changes between contract creation and contract completion, these two values diverge and the shared-address spending condition can no longer be satisfied as `complete()` expects, exactly like `ReturnsAggregator` continuing to reference a stale `withdrawalWallet` after `Staking` updates it.

### Finding Description
When a contract is created, `deriveSharedAddress()` calls `arbiters.getArbstoreInfo(contract.arbiter_address, ...)` [1](#0-0)  to obtain `arbstoreInfo.address` and `arbstoreInfo.cut`, and hardcodes them into the `["has", {..., address: arbstoreInfo.address}]` spending condition of the shared address's definition [2](#0-1) . This info is served from an in-memory cache `arbStoreInfos` in `arbiters.js` that, once populated, is never invalidated or refreshed [3](#0-2) . Once the shared address is created and its definition is disclosed on-chain, that definition (and the ArbStore address encoded in it) is permanently fixed — Byteball/Obyte address definitions cannot be altered after being locked into the chash-derived address.

Later, when the payer calls `complete()` to release funds, the code calls a *separate* function, `fillArbstoreAddresses()`, which performs a fresh lookup via `getArbstoreAddresses()` — hitting `hub/get_arbstore_address` and the ArbStore HTTP API again — and stores whatever it currently returns into `objContract.arbstore_address` [4](#0-3) . `complete()` then builds the payment `asset_outputs`/`base_outputs` using this freshly-fetched `objContract.arbstore_address` for the arbiter's cut [5](#0-4) .

There is no mechanism to keep the address baked into the immutable shared-address definition (set at creation time) in sync with the address independently re-queried at completion time. If the ArbStore rotates its payout address (a legitimate, expected operational action — comparable to the admin updating `withdrawalWallet` in the report) after a contract's shared address has already been created but before the contract is completed, `complete()` will construct an output set that pays the *new* arbstore address, while the actual, permanent spending condition encoded on-chain in the shared address's definition still requires payment to the *old* address recorded at creation time. This is architecturally the same “updatable in one place, frozen in another” pattern described in the report.

### Impact Explanation
If the two addresses diverge, the transaction composed by `complete()` will not satisfy the `has` condition baked into the shared address definition (wrong `address` for the required output), so the unit fails oscript validation and cannot be posted/accepted — the payer is unable to complete the contract and release the shared-address funds through the normal flow. This is a fund-freezing condition on a payment already escrowed in the shared address, requiring off-band/AA-adjacent workaround. There is also a Bad UX/asset misdirection concern that a client trusting the freshly re-fetched `arbstore_address` value throughout `complete()` (used to render the operation to the user and to sign) diverges from the actual required address without any explicit reconciliation check against the definition it will spend from (unlike the reading done separately in the `me_is_payer` branch which fetches the required amounts from `readSharedAddressDefinition` but not the required address, at arbiter_contract.js:753-771).

### Likelihood Explanation
The likelihood is contingent on operational events (an ArbStore rotating its payout address / changing its cut) occurring within the lifecycle of an open contract, which is entirely plausible for long-lived contracts (`ttl` defaults to 168 hours = 1 week) and is a "recommendation, not a code bug reachable directly by exploit", similar in nature to the original report which is also about an operational admin action breaking downstream consistency rather than a directly exploitable attacker path. No malicious peer/hub behavior is required — only a legitimate change on the ArbStore side.

### Recommendation
Persist the exact ArbStore address (and cut) used at shared-address creation time as an immutable, contract-scoped attribute, and reuse that persisted value in `complete()`/`openDispute()`/`appeal()` instead of independently re-fetching it via `fillArbstoreAddresses()`. Alternatively, derive the actual expected arbstore payout address directly from the on-chain shared-address definition (as is already done for `peer_amount`/`arbstore_amount` at arbiter_contract.js:753-771) rather than trusting a fresh, possibly-changed lookup, ensuring the two paths can never diverge.

### Proof of Concept
1. Alice and Bob create an arbiter contract with `arbiter_address` A; ArbStore currently reports payout address `X` and cut `c`.
2. `createSharedAddressAndPostUnit` → `deriveSharedAddress` bakes `X`/`c` into the immutable shared-address definition; the shared address is posted and funded [6](#0-5) .
3. Before the payer calls `complete()`, the ArbStore operator changes its registered payout address from `X` to `Y` (a normal administrative action on the ArbStore side, not requiring any protocol-level malicious behavior).
4. Payer calls `complete()`; `fillArbstoreAddresses()` re-queries and now returns `Y`, storing it as `objContract.arbstore_address` [4](#0-3) .
5. `complete()` builds `asset_outputs`/`base_outputs` sending the arbstore cut to `Y` [5](#0-4) , but the shared address's on-chain definition still requires an output to `X` (baked in step 2) — the composed unit fails to satisfy the spending condition and cannot be validated/posted, freezing the escrowed funds in the shared address until manually reconciled.

### Citations

**File:** arbiter_contract.js (L247-260)
```javascript
function fillArbstoreAddresses(objContract, cb) {
	if (!cb)
		return new Promise(resolve => fillArbstoreAddresses(objContract, resolve));
	if (objContract.arbstore_device_address && objContract.arbstore_address)
		return cb();
	getArbstoreAddresses(objContract.arbiter_address, function(err, result) {
		if (err)
			return cb(err);
		var { arbstore_address, arbstore_device_address } = result;
		objContract.arbstore_address = arbstore_address;
		objContract.arbstore_device_address = arbstore_device_address;
		db.query("UPDATE wallet_arbiter_contracts SET arbstore_address=?, arbstore_device_address=? WHERE hash=?", [arbstore_address, arbstore_device_address, objContract.hash], function () { cb(); });
	});
}
```

**File:** arbiter_contract.js (L461-461)
```javascript
		arbiters.getArbstoreInfo(contract.arbiter_address, function(err, arbstoreInfo) {
```

**File:** arbiter_contract.js (L504-521)
```javascript
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer || isFixedDen || !hasArbStoreCut ? contract.amount : Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
							address: offeror_address
						}]
					]];
					if (!isFixedDen && hasArbStoreCut) {
						arrDefinition[1][offeror_is_payer ? 1 : 2][1].push(
							["has", {
								what: "output",
								asset: contract.asset || "base",
								amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
								address: arbstoreInfo.address
							}]
						);
```

**File:** arbiter_contract.js (L578-629)
```javascript
function createSharedAddressAndPostUnit(hash, walletInstance, cb) {
	deriveSharedAddress(hash, true, function(err, arrDefinition, assocSignersByPath) {
		if (err)
			return cb(err);
		require("./wallet_defined_by_addresses.js").createNewSharedAddress(arrDefinition, assocSignersByPath, {
			ifError: function(err){
				cb(err);
			},
			ifOk: function(shared_address){
				setField(hash, "shared_address", shared_address, async function(contract) {
					const err = await fillArbstoreAddresses(contract);
					if (err)
						return cb(err);
					// share this contract to my cosigners for them to show proper ask dialog
					shareContractToCosigners(contract.hash);
					shareUpdateToPeer(contract.hash, "shared_address");

					const contacts_hash = getContactsHash(contract);

					// post a unit with contract text hash and send it for signing to correspondent
					var value = {"contract_text_hash": contract.hash, "arbiter": contract.arbiter_address, contacts_hash};
					var objContractMessage = {
						app: "data",
						payload_location: "inline",
						payload_hash: objectHash.getBase64Hash(value, true),
						payload: value
					};

					walletInstance.sendMultiPayment({
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						asset: "base",
						to_address: shared_address,
						amount: exports.CHARGE_AMOUNT,
						arrSigningDeviceAddresses: contract.cosigners.length ? contract.cosigners.concat([contract.peer_device_address, device.getMyDeviceAddress()]) : [],
						signing_addresses: [shared_address],
						messages: [objContractMessage]
					}, function(err, unit) { // can take long if multisig
						if (err)
							return cb(err);

						// set contract's unit field
						setField(contract.hash, "unit", unit, function(contract) {
							shareUpdateToPeer(contract.hash, "unit");
							setField(contract.hash, "status", "signed", function(contract) {
								cb(null, contract);
							});
						});
					});
				});
			}
		});
	});
```

**File:** arbiter_contract.js (L763-771)
```javascript
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

**File:** arbiters.js (L51-79)
```javascript
function getArbstoreInfo(arbiter_address, cb) {
	if (!cb)
		return new Promise(function(resolve, reject){
			getArbstoreInfo(arbiter_address, function(err, info){
				if (err) return reject(err);
				resolve(info);
			});
		});
	if (arbStoreInfos[arbiter_address]) return cb(null, arbStoreInfos[arbiter_address]);
	device.requestFromHub("hub/get_arbstore_url", arbiter_address, function(err, url){
		if (err) {
			return cb(err);
		}
		if (!validationUtils.isNonemptyString(url))
			return cb("invalid url received from hub");
		requestInfoFromArbStore(url+'/api/get_info', function(err, info){
			if (err)
				return cb(err);
			if (!validationUtils.isNonemptyObject(info))
				return cb("invalid info received from arbstore");
			const cut = parseFloat(info.cut);
			if (!info.address || !validationUtils.isValidAddress(info.address) || isNaN(cut) || cut < 0 || cut >= 1) {
				return cb("malformed info received from ArbStore");
			}
			info.url = url;
			arbStoreInfos[arbiter_address] = info;
			cb(null, info);
		});
	});
```
