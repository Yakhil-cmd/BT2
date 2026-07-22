Looking at the external bug pattern — an optimistic assumption that a condition holds, partial enforcement only when a revert would occur, and an inflated/wrong value used as a result — I need to find the same pattern in the sequencer's admission/validation path.

Let me trace the gateway stateful validation path carefully.