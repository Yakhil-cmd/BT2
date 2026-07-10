Looking at the Mooniswap analog — a one-way state transition (can pause, cannot unpause) causing permanent denial — I need to find a threshold-signatures protocol state that can be entered but has no recovery path, permanently blocking honest parties.

Let me examine the DKG final round and the `broadcast_success` function closely.