### Title
Headers-commission recipients are never checked against AA addresses, permanently freezing bytes routed to an AA - (File: `validation.js`, `headers_commission.js`)

### Summary
`validateHeadersCommissionRecipients()` lets any multi-authored unit route a share of the unit's future headers-commission earnings to an arbitrary valid address, with no check that the designated address is (or will become) an autonomous agent (AA). At spend time, however, `validatePaymentInputsAndOutputs()` unconditionally rejects `headers_commission`/`witnessing` type inputs whenever the spending author is an AA. The combination means bytes credited via `earned_headers_commission_recipients` (or via witnessing payouts) to an AA address become permanently unspendable — the exact "reward accrual path allows crediting a role that structurally can never claim it" pattern described in the Aloe `enrollCourier` report, where couriers accrue rewards they can never claim due to `require(!isCourier[msg.sender])`.

### Finding Description
1. When composing a multi-authored unit, the author(s) freely choose `earned_headers_commission_recipients`, an array of `{address, earned_headers_commission_share}`. The only validation performed is address-format/percentage-sum checking: [1](#0-0) 
There is no check that `recipient.address` is not (or will not become) an AA address.

2. When the unit is written, these recipients are stored verbatim and later used by `calcHeadersCommissions` to distribute the parent unit's headers commission among the named recipient addresses, ultimately inserting spendable balances into `headers_commission_outputs`: [2](#0-1) [3](#0-2) 

3. Separately, when any unit tries to spend a `headers_commission` or `witnessing` type input, the validator explicitly forbids this whenever the spending address belongs to an AA: [4](#0-3) 
This mirrors the Aloe pattern (`require(!isCourier[msg.sender])` in `claimRewards`) — the reward/commission "claim" path is intentionally closed off for the special role (AA), because the accounting/execution model for that role's units doesn't support this input type (AA response units are auto-composed by `aa_composer.js` and can never include hand-crafted `headers_commission`/`witnessing` inputs; also `objValidationState.bAA` unconditionally rejects the type).

4. Because step (1) does not cross-check against step (3)'s restriction, any regular unit author can name a known AA address as an `earned_headers_commission_recipients` entry. Once that unit's headers commission is actually won and credited (`headers_commission_outputs`), the bytes sit at the AA's address balance in a special ledger (`headers_commission_outputs`/`witnessing_outputs`) that can only be spent through a `headers_commission`/`witnessing` typed input — a path that is permanently closed for AAs. The AA also cannot "sweep" it through a normal payment because those outputs never become part of the `outputs` table until claimed via that specific input type.

### Impact Explanation
This results in **AA fund loss/freezing**: bytes destined as a headers-commission (or witnessing) reward for an AA address become permanently stuck and unspendable, with no mechanism in the protocol to release them. Since headers-commission/witnessing rewards can amount to a meaningful share of a unit's byte value over the DAG's lifetime, and the sink is deterministic and unrecoverable, this satisfies the "AA fund loss or freezing" impact bar (network-visible, no privileged access required — any ordinary unit author with more than one author, or one directing a share to a third-party AA address, can trigger it).

### Likelihood Explanation
Reaching this bug requires no privileged access: any user composing a multi-authored unit picks the `earned_headers_commission_recipients` list themselves and can name any valid, previously-known AA address (AA addresses are public and easily discoverable, e.g., well-known DeFi/exchange AAs). It could also occur unintentionally, e.g., a wallet mis-configuring shared-address commission-sharing rules to reference an address that is later deployed as an AA definition matching that chash (unlikely but the direct multi-author case doesn't need this — the AA already exists). No node collusion, catch-up manipulation, or malicious-peer behavior is needed — a single posted, otherwise well-formed unit suffices.

### Recommendation
In `validateHeadersCommissionRecipients()` (and analogously wherever witnessing payouts are assigned/validated), reject recipient addresses that are already registered AAs (check against `aa_addresses`/`storage.readAADefinition`), the same way an equivalent check should have been added to Aloe's `enrollCourier`. Alternatively, allow AAs to claim `headers_commission`/`witnessing` inputs through a dedicated, AA-compatible mechanism (e.g., have the protocol auto-convert such earnings into normal spendable AA balance instead of the restricted MC-output ledger) so no value is structurally strandable.

### Proof of Concept
1. Identify (or deploy) an AA address `AA1` with a known/spendable `messages` template.
2. Author a multi-authored unit `U1` (two or more authors sharing the same address, a common shared-address setup) that will plausibly win headers commission from descendant units, and set:
   ```
   earned_headers_commission_recipients: [
     { address: AA1, earned_headers_commission_share: 100 }
   ]
   ```
   This passes `validateHeadersCommissionRecipients` unmodified since the only checks are address validity/format and percentage sum. [1](#0-0) 
3. Let the DAG progress normally; `calcHeadersCommissions` distributes the commission and credits `AA1` in `headers_commission_outputs`. [2](#0-1) 
4. Attempt to spend that commission by constructing any unit (from AA1, as an AA response, or trying to author a hand-crafted unit from `AA1`) including a `headers_commission` type input for `AA1`.
5. `validatePaymentInputsAndOutputs` unconditionally errors `"headers_commission in AA"` because `objValidationState.bAA` is true for `AA1`. [5](#0-4) 
6. The credited bytes remain permanently in `headers_commission_outputs` for `AA1` with no valid path to spend them — confirming the freeze.

Note: I was not able to independently verify (within available tool budget) whether the OP-list/witness-designation flow contains an equivalent unchecked path for `witnessing_outputs` credited to an AA address (i.e., whether an AA could ever appear in the active OP list); the headers-commission-recipient path above is the concretely verified, directly user-reachable instance of this bug class.

### Citations

**File:** validation.js (L1101-1126)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
	cb();
}
```

**File:** validation.js (L2529-2536)
```javascript
				case "headers_commission":
				case "witnessing":
					if (objValidationState.bAA)
						return cb(type+" in AA");
					if (type === "headers_commission"){
						if (bHaveWitnessings)
							return cb("all headers commissions must come before witnessings");
						bHaveHeadersComissions = true;
```

**File:** headers_commission.js (L158-172)
```javascript
						conn.cquery(
							"SELECT \n\
								unit_authors.unit, \n\
								unit_authors.address, \n\
								100 AS earned_headers_commission_share \n\
							FROM unit_authors \n\
							LEFT JOIN earned_headers_commission_recipients USING(unit) \n\
							WHERE unit_authors.unit IN("+strWinnerUnitsList+") AND earned_headers_commission_recipients.unit IS NULL \n\
							UNION ALL \n\
							SELECT \n\
								unit, \n\
								address, \n\
								earned_headers_commission_share \n\
							FROM earned_headers_commission_recipients \n\
							WHERE unit IN("+strWinnerUnitsList+")",
```

**File:** headers_commission.js (L221-245)
```javascript
		function(cb){
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
				function(){
					if (conf.bFaster)
						return cb();
					conn.query("SELECT DISTINCT main_chain_index FROM units CROSS JOIN headers_commission_contributions USING(unit) WHERE main_chain_index>?", [since_mc_index], function(contrib_rows){
						if (contrib_rows.length === 1 && contrib_rows[0].main_chain_index === since_mc_index+1 || since_mc_index === 0)
							return cb();
						throwError("since_mc_index="+since_mc_index+" but contributions have mcis "+contrib_rows.map(function(r){ return r.main_chain_index}).join(', '));
					});
				}
			);
		},
		function(cb){
			conn.query("SELECT MAX(main_chain_index) AS max_spendable_mci FROM headers_commission_outputs", function(rows){
				max_spendable_mci = rows[0].max_spendable_mci;
				cb();
			});
		}
	], onDone);
```
