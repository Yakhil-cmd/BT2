I need to trace the full code path carefully to determine whether the pivot header's `StateRoot` can reach `FastSyncCommitHead` without consensus validation.

Let me check the key guard: `InsertHeaderChain` and what happens to the pivot block in `processFastSyncContent`.