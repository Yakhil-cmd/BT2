### Title
Unrestricted address type for `system_vote` casting allows pooled/shared addresses to dictate governance vote weight - (File: validation.js)

### Summary
`system_vote` messages let any address weight `op_list`, `threshold_size`, `base_tps_fee`, and `tps_interval`/`tps_fee_multiplier` governance votes by the address's on-chain byte balance, counted later in `countVotes()`. The only address-type restriction in the validator is that the *voting* address is not an AA — nothing restricts it from being a multi-party "shared address" (a pooled, multi-signature/oscript-defined address) that a single operator effectively controls for message authoring, while many depositors' funds sit inside it.

### Finding Description
`validation.js` validates the `system_vote` payload but the only identity check performed on the voting address is: [1](#0-0) 

No check exists preventing the author address from being a shared/pooled address (an address whose `definition` combines many participants' keys or uses permissive `or`/timing branches, as used e.g. for `wallet_defined_by_addresses.js` shared addresses and `arbiter_contract.js` shared contract addresses): [2](#0-1) 

Once the `system_vote` unit stabilizes, its `author_addresses` are simply recorded in `system_votes`/`op_votes`/`numerical_votes` with no further filtering by address "kind": [3](#0-2) 

Vote weight is then computed purely from the address's stable-good spendable byte balance, again with no distinction between a personal wallet address and a pooled/shared address: [4](#0-3) [5](#0-4) 

An operator can construct a shared address definition (using standard oscript primitives such as `and`/`or`, `in data feed`, delays, etc. — the same building blocks used for arbiter/prosaic shared addresses) that: (1) accepts deposits from many participants who are attracted by incentives (yield-sharing, "staking" service, priority access, etc.), and (2) permits the operator alone to author non-spending messages such as `system_vote` (e.g., an `or` branch that lets the operator sign solo for anything that isn't a payment output to themselves, or a branch usable after a short data-feed/time condition). Because `system_vote` is validated exactly like a normal message authored by that address's definition, the operator can cast one system vote from the shared address and have it weighted by the entire pooled balance, exactly as in the original AuraLocker report where a bad actor's smart contract accumulates lockers' tokens and then dictates the delegated vote — here the "lock" is simply depositing bytes into a shared address that the operator can unilaterally use to author `system_vote`.

### Impact Explanation
This lets a single operator disproportionately influence core governance decisions that gate consensus behavior:
- `op_list` — determines the elected witness set, i.e., who is trusted for stability determination.
- `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier` — network-wide fee/throughput parameters that affect what units can be validly posted and confirmed.

Concentrating this influence in an operator-controlled pooled address undermines the "one balance, one vote weight, controlled by its true owner" assumption `countVotes()` relies on, and can bias witness elections or fee/throughput parameters network-wide — a governance/consensus-parameter integrity issue, matching the Medium severity assigned to the original report (governance risk without direct fund loss).

### Likelihood Explanation
Building an attractive shared/pooled address using standard oscript features (multisig, `or`, data-feed/time-gated branches) is well within reach of any user with basic Obyte scripting knowledge; no privileged access is required. The incentive to attract deposits (yield, "staking" perks) is a normal social-engineering vector already seen in DeFi-style patterns on other chains, and nothing in the validator (`validation.js` system_vote case) or in the vote-tallying code (`main_chain.js` `countVotes`) checks the definition/type of the voting address.

### Recommendation
Restrict `system_vote` (and the balance used for `countVotes`) to addresses whose definition is a plain single-key `sig` (or otherwise flagged "EOA-like") address, or alternatively require that voting weight only reflects individually-verified user-controlled balances (e.g., disallow multi-author/shared-address definitions from casting `system_vote`, mirroring the existing `if (objValidationState.bAA) return callback("AA cannot cast system vote");` check but generalized to any non-simple-signature definition).

### Proof of Concept
1. Attacker creates a shared address whose definition is `["or", [["and",[...multisig branch requiring depositor+attacker keys for spends...]], ["and",[["address", attacker],["in data feed", [[attacker],"UNLOCK","=",1]]]]]]` — i.e., normal payments require both depositor and attacker, but any other message (including `system_vote`) can be authored solely by the attacker once a trivial data-feed condition (posted by the attacker themselves) is true.
2. Attacker advertises the pool as a high-yield "staking" service; many users send bytes to the shared address.
3. Attacker posts the unlocking data feed, then authors a `system_vote` unit from the shared address for `op_list`/`threshold_size`, satisfying validation at `validation.js:1844-1851` (only AA authorship is blocked) and `checkWitnessesKnownAndGood`/`checkNoReferencesInWitnessAddressDefinitions`.
4. At stabilization, `saveSystemVote()` records the vote for the shared address, and `countVotes()` weights it by the shared address's full pooled balance (`main_chain.js:1757-1777`, `1850-1858`), giving the attacker outsized influence over witness/parameter elections proportional to all depositors' funds, not just their own.

### Citations

**File:** validation.js (L1844-1851)
```javascript
		case "system_vote":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot vote for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot cast system vote");
			if (objValidationState.bHasSystemVote)
				return callback("can be only one system vote");
			objValidationState.bHasSystemVote = true;
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

**File:** main_chain.js (L1619-1636)
```javascript
								async function saveSystemVote(payload) {
									console.log('saveSystemVote', payload);
									const { subject, value } = payload;
									const objStableUnit = storage.assocStableUnits[unit];
									if (!objStableUnit)
										throw Error("no stable unit " + unit);
									const { author_addresses, timestamp } = objStableUnit;
									const strValue = subject === "op_list" ? JSON.stringify(value) : value;
									for (let address of author_addresses)
										await conn.query("INSERT INTO system_votes (unit, address, subject, value, timestamp) VALUES (?,?,?,?,?)", [unit, address, subject, strValue, timestamp]);
									let sqlValues = [];
									switch (subject) {
										case "op_list":
											const arrOPs = value;
											await conn.query("DELETE FROM op_votes WHERE address IN (?)", [author_addresses]);
											for (let address of author_addresses)
												sqlValues = sqlValues.concat(arrOPs.map(op_address => `(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`));
											await conn.query("INSERT INTO op_votes (unit, address, op_address, timestamp) VALUES " + sqlValues.join(', '));
```

**File:** main_chain.js (L1757-1777)
```javascript
	const bal_rows = await conn.query(`
		SELECT outputs.address, SUM(outputs.amount) AS balance
		FROM outputs
		JOIN units ON outputs.unit = units.unit
		WHERE outputs.address IN(${strAddresses})
			AND outputs.asset IS NULL
			AND units.is_stable = 1 AND units.sequence = 'good'
			AND NOT EXISTS (
				SELECT 1 FROM inputs
				JOIN units AS su ON inputs.unit = su.unit
				WHERE inputs.src_unit = outputs.unit
					AND inputs.src_message_index = outputs.message_index
					AND inputs.src_output_index = outputs.output_index
					AND su.sequence = 'good'
					AND su.is_stable = 1
			)
		GROUP BY outputs.address`);
	console.log('bal rows', bal_rows)
	for (let { address, balance } of bal_rows) {
		balances[address] = balance;
	}
```

**File:** main_chain.js (L1850-1858)
```javascript
			const op_rows = await conn.query(`SELECT op_address, SUM(balance) AS total_balance
				FROM ${votes_table}
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=?
				GROUP BY op_address
				ORDER BY total_balance DESC, op_address
				LIMIT ?`,
				[since_timestamp, constants.COUNT_WITNESSES]
			);
```
