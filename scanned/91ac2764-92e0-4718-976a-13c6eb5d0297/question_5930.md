# Q5930: [allow_with_label] `edited` PR RCE via a self-added PR label name

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged `edited` pull request supply a self-added PR label name so the provisioned review stack executes attacker code (ReviewStack#env uppercases label names into env keys with no allowlist)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: a self-added PR label name on a `edited` fork PR under `allow_with_label`
- Exploit idea: the provision gate is reachable for `edited` under `allow_with_label`; ReviewStack#env uppercases label names into env keys with no allowlist, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: process the `edited` PR, set a self-added PR label name, assert the executed argv/env reflects attacker input.
