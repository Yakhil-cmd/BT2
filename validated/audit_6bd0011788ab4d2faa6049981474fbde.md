Looking at the external bug class: a configuration function checks a live balance/state value before allowing an update; an actor manipulates that state to cause the check to fail, persistently blocking the configuration. I need to find the same pattern in Kaia.

Let me search for the exact `sumOfRetiredBalance` implementation and the `finalizeApproval` flow.