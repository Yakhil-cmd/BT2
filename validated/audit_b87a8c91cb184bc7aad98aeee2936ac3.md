### Title
Payment-Channel Fraud-Proof Reward Is Payable To Any Front-Running Address, Not Just The Wronged Channel Party - (File: test/samples/payment_channels.oscript)

### Summary
The reference Obyte payment-channel AA (`test/samples/payment_channels.oscript`, exercised for correctness by `test/ojson.test.js` "Payment channels" test) implements the same reward class described in the external report: a payout that is meant to go to the party who catches and reports counterparty misbehavior, but the AA case that pays this reward never checks that the *submitter* (`trigger.address`) is one of the two channel parties. Anyone who obtains the signed fraud-proof package can front-run the honest party and steal the entire channel balance.

### Finding Description
In the "start closing" case, the peer's last signed state (`sentByPeer`) is a portable, non-address-bound blob: `{signed_message: {channel, period, amount_spent}, ...}` signed by the cheating peer's private key and verified with `is_valid_signed_package(trigger.data.sentByPeer, peer_address)` [1](#0-0) . This package can legitimately be relayed off-chain, stored, or become visible once the honest party posts a unit containing it (mempool/DAG visibility).

The "fraud proof" case, which pays out the *entire* channel balance to whoever triggers it, only checks:
```
if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`
``` [2](#0-1) 

and its `init` block verifies the *peer's* signature on the state, the channel id, and the period — but never verifies that `trigger.address` equals `$addressA` or `$addressB` (i.e. it never checks `$bFromParties`, which is computed globally at lines 6-8 but not referenced anywhere in this case) [3](#0-2) . The payout message then sends the entire balance to `trigger.address`:
```
messages: [
  { app: 'payment', payload: { asset: 'base', outputs: [ { address: '{trigger.address}' } ] } },
  ...
]
``` [4](#0-3) 

Because the reward destination is `trigger.address` (the unit poster) rather than a fixed party (`$addressA`/`$addressB`) or an address embedded/committed inside the signed package itself, this is exactly the bug class in the external report: the "reporting" data contains nothing that binds the payout to the intended reporter, so it can be copied and resubmitted by a third party. Any user who sees the honest party's fraud-proof unit in the DAG before it stabilizes (or otherwise obtains the leaked `sentByPeer` package) can immediately post their own trigger unit with the same `trigger.data.fraud_proof` and `trigger.data.sentByPeer` payload, using their own address as `trigger.address`, and — if their unit is stabilized/ordered ahead of or instead of the honest party's — collect the full channel balance meant for the honest party.

### Impact Explanation
This results in direct, unauthorized loss of AA-held funds: the entire payment-channel balance (both parties' locked bytes) can be redirected to an unrelated address instead of the honest channel party who detected and proved the counterparty's cheating. This is a concrete AA fund loss/theft, not merely a missed fee, since "send all" pays out 100% of the channel's remaining balance.

### Likelihood Explanation
Any AA trigger sender can exploit this once they obtain the `sentByPeer` signed package — which becomes visible as soon as the honest party broadcasts their fraud-proof-triggering unit (units are visible in the DAG before they become stable, similar to a mempool). Only ordering (who gets included/stabilized first) determines the winner, so an attacker monitoring new units for `trigger.data.fraud_proof` payloads targeting this AA can react and repost the same data with themselves as author. No special privilege is required — an ordinary AA trigger sender suffices.

### Recommendation
Bind the fraud-proof payout to the identity that is authorized to receive it instead of the generic `trigger.address`:
- Require `$bFromParties` (i.e., `trigger.address == $addressA OR trigger.address == $addressB`) in the `if` condition of the fraud-proof case, same as the other cases, and additionally require that the caller is the party *opposite* the one who cheated (`$bInitiatedByA` should correspond to whichever party is NOT the reporter), or
- Pay the funds to a fixed, pre-determined address (e.g., "the party who did not initiate `close_initiated_by`" or "the honest party derived purely from state," not from `trigger.address`) rather than to whoever submits the trigger.

### Proof of Concept
1. Party A and Party B open and fund the channel AA; B eventually attempts to cheat, sending A a stale/incorrect signed state.
2. A detects the fraud and constructs a trigger unit: `trigger.data = { fraud_proof: 1, sentByPeer: <B's incriminating signed package> }`, and broadcasts it to close the channel and claim all funds.
3. Attacker C observes this unit in the DAG before it is included in a stable ball, copies the identical `trigger.data.sentByPeer` payload, and immediately posts their own trigger unit to the same AA with `trigger.address = C` and the same `fraud_proof`/`sentByPeer` data (paying a higher fee / getting favorable unit ordering).
4. The AA's `fraud_proof` case validates successfully (verification is only against B's signature and channel/period fields, never against `trigger.address`), and pays out the entire channel balance via `{ address: '{trigger.address}' }` to C instead of A. [5](#0-4)

### Citations

**File:** test/samples/payment_channels.oscript (L40-49)
```text
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
