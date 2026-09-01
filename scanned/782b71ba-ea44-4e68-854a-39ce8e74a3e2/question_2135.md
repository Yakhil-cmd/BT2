# Q2135: [allow_all] `unassigned` PR RCE via a self-added PR label name

## Question
On provisioning_behavior=`allow_all`, can an unprivileged `unassigned` pull request supply a self-added PR label name so the provisioned review stack executes attacker code (ReviewStack#env uppercases label names into env keys with no allowlist)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: a self-added PR label name on a `unassigned` fork PR under `allow_all`
- Exploit idea: the provision gate is reachable for `unassigned` under `allow_all`; ReviewStack#env uppercases label names into env keys with no allowlist, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: process the `unassigned` PR, set a self-added PR label name, assert the executed argv/env reflects attacker input.
