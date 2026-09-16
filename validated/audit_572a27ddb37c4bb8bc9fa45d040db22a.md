### Title
Payment-channel fraud-proof reward is not bound to the honest reporter and can be front-run to steal the entire channel balance - (File: test/samples/payment_channels.oscript)

### Summary
The bundled two-party payment-channel Autonomous Agent (`test/samples/payment_channels.oscript`) implements a "fraud proof" case that pays out the *entire* channel balance to `trigger.address` whenever a party proves the counterparty tried to close the channel with a stale/understated balance. The signed proof (`trigger.data.sentByPeer`) that is verified with `is_valid_signed_package()` is bound only to the channel address and the closing period — it is **not** bound to the address of whoever submits the fraud-proof trigger. This is the same class of bug as `reportUnauthorizedSigning()` in `KeepRandomBeaconOperator.sol`: a valid, otherwise-public proof entitles whoever submits it first to a reward/payout, so any observer can copy the proof out of the mempool/DAG and front-run the legitimate reporter, redirecting the payout to their own address.

### Finding Description
In the fraud-proof case of the AA: [1](#0-0) 

the `init` block validates `trigger.data.sentByPeer` (a signed message produced by one of the two channel counterparties, A or B) using `is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB)`, then checks that the peer under-reported the amount they had spent versus what they actually signed. Crucially, none of these checks constrain who may submit the triggering unit — `is_valid_signed_package` only proves that the *signed_message* was produced by the correct counterparty address, exactly as implemented in the oscript engine: [2](#0-1) 

The payout message then sends the full channel balance ("send all") to `trigger.address`: [3](#0-2) 

Because `trigger.address` is simply the address of whoever posted the current unit (any unprivileged user can trigger an AA with `trigger.data` copied from the honest party's would-be transaction), an attacker who observes an honest party (A or B) about to submit a fraud-proof unit containing `sentByPeer` can copy that exact `signed_message`/signature into their own trigger and post it first (front-run), or simply observe it directly from the counterparty's own communications/gossip before the honest party gets to submit it into a stable position. The proof itself is publicly reusable data (it is not consumed or tied to the reporter's own signature/address), so the attacker's copy passes every check the AA performs, and the resulting "send all" payment on close of dispute goes to the attacker's `trigger.address` instead of the honest reporting party — resulting in outright theft of the entire channel balance from both legitimate parties.

### Impact Explanation
This allows an unprivileged third party to steal all funds locked in the AA-based payment channel (both parties' balances) by racing a legitimate fraud-proof submission, exactly mirroring the front-running reward theft described in the external report, but with 100% of funds at risk (rather than the 5% reward in the original bug), since the entire channel balance—not just a "reward share"—is paid to whoever's `trigger.address` happens to be attached to the accepted unit. This is a concrete AA fund-loss/theft scenario reachable by any unprivileged AA trigger sender.

### Likelihood Explanation
Likelihood is high in a contended/adversarial environment: the signed fraud-proof package must be broadcast/submitted as part of a unit, and until it is stable/final, any node or observer that sees the pending unit (e.g., via DAG propagation prior to finality, or via any off-chain leak of the signed package used to build the trigger) can construct their own trigger reusing the same `sentByPeer` payload and post it with lower latency or higher priority. Nothing in the AA logic prevents this replay by a different `trigger.address`.

### Recommendation
Bind the fraud-proof payout to the legitimate reporter, not the anonymous transaction submitter. Concretely, the `signed_message` used as proof should itself contain (and the AA should verify) the intended recipient/reporter address — e.g., require the peer's `sentByPeer` counter-signature to additionally embed the reporting party's address (A or B) rather than paying blindly to `trigger.address`, or require that only the counterparty (`$bInitiatedByA ? $addressB : $addressA`, i.e., the non-initiating party) can be `trigger.address` for the fraud-proof case, so a third party cannot claim the payout. More generally, any oscript/AA pattern that pays `trigger.address` based on a reusable, unbound proof should tie the proof to the claimant's address (similar to binding `msg.sender` in the original Solidity fix) to prevent front-running of fraud/reward proofs.

### Proof of Concept
1. Party A and B open and fund the channel AA per the "refill the AA" case: [4](#0-3) .
2. Party B, acting maliciously, counter-signs a `signed_message` (with `channel`, `period`, `amount_spent`) for A to use to detect fraud, or A/B legitimately possesses such a signed package proving the peer under-reported spending during "start closing": [5](#0-4) .
3. Once the closing party under-reports (`transferredFromMe` < what they actually signed to the peer earlier), the honest counterparty prepares a trigger containing `{ fraud_proof: true, sentByPeer: <the peer's previously signed package> }` to claim the entire balance via the fraud-proof case: [1](#0-0) .
4. An attacker monitoring the network/mempool for such fraud-proof-eligible data (or who otherwise obtains the `sentByPeer` signed package, e.g. by being sent it as part of off-chain channel communication that gets exposed) crafts an identical trigger `{ fraud_proof: true, sentByPeer: <same signed package> }` from their own address and gets it included first.
5. Because `is_valid_signed_package` only checks the signature came from the correct counterparty address and not who is submitting the current unit, the AA executes the case successfully and sends the entire channel balance to the attacker's `trigger.address` instead of the honest reporter's, per [3](#0-2) .

### Citations

**File:** test/samples/payment_channels.oscript (L14-30)
```text
			{ // refill the AA
				if: `{ $bFromParties AND trigger.output[[asset=base]] >= 1e5 }`,
				messages: [
					{
						app: 'state',
						state: `{
							if (var['close_initiated_by'])
								bounce('already closing');
							if (!var['period'])
								var['period'] = 1;
							$key = 'balance' || $party;
							var[$key] += trigger.output[[asset=base]];
							response[$key] = var[$key];
						}`
					}
				]
			},
```

**File:** test/samples/payment_channels.oscript (L31-67)
```text
			{ // start closing
				if: `{ $bFromParties AND trigger.data.close AND !var['close_initiated_by'] }`,
				messages: [
					{
						app: 'state',
						state: `{
							$transferredFromMe = trigger.data.transferredFromMe otherwise 0;
							if ($transferredFromMe < 0)
								bounce('bad amount spent by me: ' || $transferredFromMe);
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
							}
							else
								$transferredFromPeer = 0;
							var['spentByA'] = $bFromA ? $transferredFromMe : $transferredFromPeer;
							var['spentByB'] = $bFromB ? $transferredFromMe : $transferredFromPeer;
							$finalBalanceA = var['balanceA'] - var['spentByA'] + var['spentByB'];
							$finalBalanceB = var['balanceB'] - var['spentByB'] + var['spentByA'];
							if ($finalBalanceA < 0 OR $finalBalanceB < 0)
								bounce('one of the balances would become negative');
							var['close_initiated_by'] = $party;
							var['close_start_ts'] = timestamp;
							response['close_start_ts'] = timestamp;
							response['finalBalanceA'] = $finalBalanceA;
							response['finalBalanceB'] = $finalBalanceB;
						}`
					}
				]
			},
```

**File:** test/samples/payment_channels.oscript (L103-129)
```text
			{ // fraud proof
				if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`,
				init: `{
					$bInitiatedByA = (var['close_initiated_by'] == 'A');
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
					$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
					if ($transferredFromPeer < 0)
						bounce('bad amount spent by peer: ' || $transferredFromPeer);
					$transferredFromPeerAsClaimedByPeer = var['spentBy' || ($bInitiatedByA ? 'A' : 'B')];
					if ($transferredFromPeer <= $transferredFromPeerAsClaimedByPeer)
						bounce("the peer didn't lie in his favor");
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							outputs: [
								// send all
								{ address: '{trigger.address}' }
							]
						}
```

**File:** formula/evaluation.js (L1653-1701)
```javascript
			case 'is_valid_signed_package':
				if (!objValidationState.count_signed_packages)
					objValidationState.count_signed_packages = 0;
				if (objValidationState.count_signed_packages >= constants.MAX_SIGNED_PACKAGES_PER_AA_EVAL && bPostPemCurvesFix)
					return setFatalError("too many signed packages in evaluation", { arr }, false, cb);
				objValidationState.count_signed_packages++;
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(address_expr, function (evaluated_address) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidAddress(evaluated_address))
						return setFatalError("bad address in is_valid_signed_package: " + evaluated_address, { arr }, false, cb);
					evaluate(signed_package_expr, async function (signedPackage) {
						if (fatal_error)
							return cb(false);
						if (!(signedPackage instanceof wrappedObject))
							return cb(false);
						signedPackage = signedPackage.obj;
						if (ValidationUtils.hasFieldsExcept(signedPackage, ['signed_message', 'last_ball_unit', 'authors', 'version']))
							return cb(false);
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
						}
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
					});
				});
```
