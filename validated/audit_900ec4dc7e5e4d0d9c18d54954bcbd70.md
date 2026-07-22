Looking at the factory, admin, pause, and fee paths in the Metric OMM codebase, I need to identify a unit/value mismatch analogous to the BentoBox bug (wrong denomination stored in a critical state variable, causing incorrect downstream behavior).

The closest analog is in the pause-transition logic of `MetricOmmPoolFactory.sol`.