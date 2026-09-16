### Title
Missing `payer_address`/`payee_address` in `arbiter_contract.getHashSrc()` breaks hash integrity binding for arbiter contracts - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` computes a content-integrity hash (`getHash`/`getHashSrc`) for arbiter contract offers that is checked by peers/cosigners before the contract is trusted and used to derive the shared payment address. Analogous to the reported `LISTING_TYPEHASH` bug (a field used in a signed/committed process but omitted from the hash/type definition), the currently-active hash format in `getHashSrc()` omits the `payer_address`/`payee_address` fields entirely, so the addresses that ultimately control fund flow are not bound by the integrity hash.

### Finding Description
`getHashSrc()` selects between two hash formats based on `contract.creation_date`: [1](#0-0) 

```
const src = contract.creation_date > exports.NEW_HASH_DATE
     ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
     : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
```

`exports.NEW_HASH_DATE` is hardcoded to `'2026-11-01'`: [2](#0-1) 

Since `createAndSend()` stamps `creation_date` with the current time (`new Date().toISOString()...`), and today's date (2026-09-15) is before `NEW_HASH_DATE`, every contract created right now falls into the **old** branch, which excludes `payer_address` and `payee_address` from the hash input, including only `payer_name`/`payee_name` (free-text, optional, often empty strings). This hash is what peers and cosigners rely on to verify contract integrity:

- On offer receipt: `if (body.hash !== arbiter_contract.getHash(body)) return callbacks.ifError("wrong contract hash");` (wallet.js `arbiter_contract_offer` handler).
- After swapping payer/payee roles to the recipient's perspective, the code re-derives and asserts the hash is unchanged: [3](#0-2) 

The addresses `my_address`/`peer_address` stored alongside the hash are later used, unverified against the hash, to derive the actual multi-sig shared payment address and payment conditions: [4](#0-3) [5](#0-4) 

Because the hash the parties use to confirm they agree on the same contract terms does not bind the payer/payee addresses, a party that controls or influences the contract record (e.g., a malicious cosigner sharing the contract via `arbiter_contract_shared`, or any relay path that can alter the stored `my_address`/`peer_address` fields while keeping `payer_name`/`payee_name` and other hashed fields identical) can present a contract whose hash still validates while the actual fund-controlling addresses differ from what the counterpart or cosigner believes they are agreeing to. Since `deriveSharedAddress()` builds the payment definition directly from `contract.my_address`/`contract.peer_address` (taken from the DB row, populated by the untrusted body), this can result in the multisig/shared address being derived using an address the honest party did not actually agree to, or a cosigner not detecting a swapped counterpart address, because the "wrong contract hash" check — the only integrity guard in the flow — cannot detect the tampering.

### Impact Explanation
Impact is Medium: the addresses that determine who ultimately receives escrowed funds are excluded from the field that both the offer receiver and cosigners rely on for tamper detection (`getHash`/`getHashSrc`). This can allow fund flow to be redirected to an unintended address while the integrity check silently passes, since the hash appears unchanged. This matches the reported bug class of "field used in a signing/commitment process but excluded from the corresponding hash/type," undermining the very integrity guarantee the hash is meant to provide.

### Likelihood Explanation
Likelihood is Medium: the vulnerable ("old") hash branch is the one currently active in production (since today's date, 2026-09-15, precedes the hardcoded `NEW_HASH_DATE` of `2026-11-01`), so it is reachable by any peer/cosigner in the arbiter-contract flow without any special privilege — simply by initiating or relaying an `arbiter_contract_offer`/`arbiter_contract_shared` message, both of which are handled by any correspondent device per `wallet.js`.

### Recommendation
Always include `payer_address` and `payee_address` (and any other field materially affecting fund flow, such as `ttl` if relevant) in `getHashSrc()`, and either remove the date-gated legacy branch or apply the "new" (address-inclusive) hash format for all contracts, independent of `creation_date`. If backward compatibility with pre-existing stored hashes is required, restrict acceptance of the legacy (address-less) format to old already-agreed contracts only, not for validating newly created/offered ones.

### Proof of Concept
1. Device A calls `arbiter_contract.createAndSend()` today (creation_date ≈ 2026-09-15, before `NEW_HASH_DATE`), producing `hash = getHash(contract)` computed from `[title, text, creation_date, payer_name, arbiter_address, payee_name, amount, asset]` — addresses are not part of the input (`arbiter_contract.js:199-201`).
2. A relaying/cosigning device (or a compromised intermediate step that can influence the stored `my_address`/`peer_address` values before `arbiter_contract_shared`/`arbiter_contract_offer` is delivered) substitutes a different `my_address` or `peer_address` while keeping `title`, `text`, `creation_date`, `payer_name`, `payee_name`, `arbiter_address`, `amount`, `asset` identical.
3. The receiving device validates `body.hash === arbiter_contract.getHash(body)` (wallet.js), which passes because the tampered addresses were never part of the hash input.
4. `deriveSharedAddress()` is later invoked using the tampered `contract.my_address`/`contract.peer_address` to build the escrow definition (`arbiter_contract.js:454-512`), causing funds to be escrowed to/released to an address the victim never actually agreed to, without any detectable hash mismatch.

### Citations

**File:** arbiter_contract.js (L16-19)
```javascript
var status_PENDING = "pending";
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

**File:** arbiter_contract.js (L194-203)
```javascript
function getHashSrc(contract) {
	const payer_name = contract.me_is_payer ? contract.my_party_name : contract.peer_party_name;
	const payee_name = contract.me_is_payer ? contract.peer_party_name : contract.my_party_name;
	const payer_address = contract.me_is_payer ? contract.my_address : contract.peer_address;
	const payee_address = contract.me_is_payer ? contract.peer_address : contract.my_address;
	const src = contract.creation_date > exports.NEW_HASH_DATE
		 ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
		 : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
	return src;
}
```

**File:** arbiter_contract.js (L454-481)
```javascript
function deriveSharedAddress(hash, bOfferor, cb) {
	getByHash(hash, function (contract) {
		const offeror_address = bOfferor ? contract.my_address : contract.peer_address;
		const acceptor_address = bOfferor ? contract.peer_address : contract.my_address;
		const offeror_is_payer = bOfferor ? contract.me_is_payer : !contract.me_is_payer;
		const offeror_device_address = bOfferor ? device.getMyDeviceAddress() : contract.peer_device_address;
		const acceptor_device_address = bOfferor ? contract.peer_device_address : device.getMyDeviceAddress();
		arbiters.getArbstoreInfo(contract.arbiter_address, function(err, arbstoreInfo) {
			if (err)
				return cb(err);
			storage.readAssetInfo(db, contract.asset, function (assetInfo) {
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

**File:** arbiter_contract.js (L494-512)
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
```

**File:** arbiter_contract.js (L636-646)
```javascript
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		deriveSharedAddress(hash, false, function (err, arrDefinition, assocSignersByPath) {
			if (err) {
				if (retry_count >= 10)
					return console.log(`failed derivation of shared address ${shared_address} after 10 retries, giving up`, err);
				console.log("error deriving shared address definition, will retry in 30 seconds", err);
```
