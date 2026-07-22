Looking at the external bug class: **a state flag is reset by a cleanup operation, but a stale pending action (still within its validity window) can re-trigger the flag, bypassing the intended governance/security mechanism.**

I need to find the analog in Metric OMM where a "cleanup" clears one state slot but leaves a stale pending action that can re-assert authority.