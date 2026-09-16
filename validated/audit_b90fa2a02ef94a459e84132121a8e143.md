### Title
No mechanism to replace an unresponsive or malicious arbiter in arbiter-contract shared addresses, permanently freezing escrowed funds - ([File: arbiter_contract.js])

### Summary
When two ocore wallet users create an arbitrated payment contract, `deriveSharedAddress()` bakes the `arbiter_address` permanently into the shared-address definition as the oracle whose data feed decides who wins a dispute. Once this address is created and funded, there is no protocol mechanism to change the arbiter if that arbiter becomes unavailable, colludes, or otherwise refuses to publish a resolution. This is the same class of bug as the reported KintoWallet issue — an immutable trusted-role address embedded in a definition with no update path — except here the "recoverer" role is played by the `arbiter_address`, and the asset at risk is the escrowed payment held at the derived shared address.

### Finding Description
`arbiter_contract.deriveSharedAddress()` builds the shared-address definition for an arbitrated contract as an `or` of five branches: mutual signature by both parties, or a payout conditioned on `in data feed` from `contract.arbiter_address` (for public assets) matching `CONTRACT_<hash>`. [1](#0-0) [2](#0-1) 

This definition is hashed to compute the shared address and passed to `wallet_defined_by_addresses.createNewSharedAddress`, becoming the immutable on-chain address definition once the c-hash is committed and funds are sent to it. [3](#0-2) 

The `arbiter_address` column stored on the contract, and the dispute flow (`openDispute`, `parseWinnerFromUnit`) all resolve strictly against this one fixed address for the lifetime of the contract: [4](#0-3) [5](#0-4) 

Unlike a regular ocore address, which can be re-keyed via `address_definition_change` messages validated in `validation.js` (`validateInlinePayload`, case `"address_definition_change"`), the arbiter binding inside the shared-address definition cannot be swapped out after creation — doing so would change the definition c-hash and therefore the address itself, requiring both parties (offeror and acceptor) to cooperate on creating a brand-new shared address and re-funding it. [6](#0-5) 

There is no code path that lets either party unilaterally, or through any governance/appeal mechanism inside this file, substitute a new arbiter address into an already-funded contract's shared address. The only "escape" from the arbiter is the mutual-signature branch (`r.0.0`/`r.0.1`), which requires the *counterparty's* cooperation — exactly the scenario that fails when the counterparty is adversarial and the appointed arbiter is compromised, colluding with the counterparty, or has simply disappeared.

### Impact Explanation
If the appointed `arbiter_address` becomes unavailable (e.g., the arbiter's device/hub is gone, keys are lost) or turns malicious/colludes with one party, and the counterparty refuses to mutually co-sign a release, the escrowed funds at the shared address are frozen indefinitely with no on-chain or off-chain protocol mechanism to appoint a replacement arbiter for the existing contract. This is a concrete AA/contract fund-freezing condition reachable by an ordinary contract counterparty (an unprivileged private-payment participant), matching the report's "no mechanism to change untrusted/critical role address" bug class.

### Likelihood Explanation
This requires only that one of the two ordinary contract counterparties pays into an arbiter contract whose arbiter subsequently becomes unreachable or dishonest and the other party does not cooperate — a realistic scenario given arbiters are chosen once at contract-creation time and can never be swapped, and no expiry/fallback logic returns funds automatically in this file.

### Recommendation
Add a supported mechanism to migrate escrowed funds to a new shared-address definition with a different `arbiter_address` (e.g., a time-locked fallback branch that lets either party reclaim funds after a dispute timeout, or a re-arbitration flow requiring cosigner consensus to re-derive the shared address with a new arbiter) so that funds are not permanently held hostage by a single, immutable arbiter binding.

### Proof of Concept
1. Alice (offeror) and Bob (acceptor) create an arbiter contract naming Arbiter A; `createSharedAddressAndPostUnit` derives shared address `S` whose definition permanently embeds `arbiter_address = A` (arbiter_contract.js:465-481, 578-613).
2. Alice pays into `S` (`pay()`), contract status becomes `"paid"`.
3. A dispute arises; Alice calls `openDispute()`, which contacts arbiter `A`'s arbstore (arbiter_contract.js:262-318).
4. Arbiter `A` is unreachable (device/hub down) or colludes with Bob and never publishes a `CONTRACT_<hash>` data feed resolving in Alice's favor.
5. Bob refuses to co-sign the mutual-release branch (`r.0.0`/`r.0.1`).
6. There is no code path in `arbiter_contract.js`/`wallet.js` that lets Alice unilaterally or via any governance process replace `arbiter_address` in `S`'s definition — the funds at `S` remain permanently unspendable.

### Citations

**File:** arbiter_contract.js (L262-271)
```javascript
function openDispute(hash, cb) {
	getByHash(hash, function(objContract){
		if (!["paid", "in_dispute"].includes(objContract.status))
			return cb("contract can't be disputed");
		device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, function(err, url){
			if (err)
				return cb(err);
			arbiters.getInfo(objContract.arbiter_address, async function(err, objArbiter) {
				if (err)
					return cb(err);
```

**File:** arbiter_contract.js (L465-481)
```javascript
				var arrDefinition =
					["or", [
						["and", [
							["address", offeror_address],
							["address", acceptor_address]
						]],
						[], // placeholders [1][1]
						[],	// placeholders [1][2]
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
					]];
```

**File:** arbiter_contract.js (L494-513)
```javascript
				} else {
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer && !isFixedDen && hasArbStoreCut ? Math.floor(contract.amount * (1 - arbstoreInfo.cut)) : contract.amount,
							address: acceptor_address
						}]
					]];
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
```

**File:** arbiter_contract.js (L578-613)
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
```

**File:** arbiter_contract.js (L798-814)
```javascript
function parseWinnerFromUnit(contract, objUnit) {
	if (objUnit.authors[0].address !== contract.arbiter_address) {
		return;
	}
	var key = "CONTRACT_" + contract.hash;
	var winner;
	objUnit.messages.forEach(function(message){
		if (message.app !== "data_feed" || !message.payload || !message.payload[key]) {
			return;
		}
		winner = message.payload[key];
	});
	if (!winner || (winner !== contract.my_address && winner !== contract.peer_address)) {
		return;
	}
	return winner;
}
```

**File:** validation.js (L1719-1745)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();
```
