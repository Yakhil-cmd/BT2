# Q2966: Bridge top-up pending-debt desynchronization

## Question
Can an unprivileged attacker, by bridging STRK so that `on_receive(l2_token, amount, depositor, message)` receives an amount exactly equal to the live pending request debt while there are several pending L1 mint requests, force `l1_pending_requested_amount` to be zeroed or decremented in a way that no longer matches the actual outstanding mint debt and thereby suppress or over-trigger later funding requests?

## Target
- File/function: src/reward_supplier/reward_supplier.cairo::on_receive
- Entrypoint: on_receive(l2_token, amount, depositor, message)
- Attacker controls: deposit amount and timing via StarkGate, depositor identity, repeated bridge deposits
- Exploit idea: Use public bridge deposits as an external balance source and check whether the pending-request accounting treats third-party top-ups and L1-settled mints as if they were economically identical.
- Invariant to test: The pending mint debt should only track requests that still need settlement, and third-party bridge top-ups must not silently erase that debt unless the funds really cover it.
- Expected Immunefi impact: Medium - Temporary freezing of funds
- Fast validation: Mock the reward supplier debt, push bridge deposits through the StarkGate callback path, and assert that the next `request_funds` decision matches an external debt model.
