# Q5231: Review-stack RCE via a self-added PR label name on `labeled`/allow_all

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged contributor's `labeled` pull request supply a self-added PR label name so the provisioned review stack executes attacker code, given that ReviewStack#env uppercases label names into env keys with no allowlist?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: a self-added PR label name on the fork PR under `allow_all`
- Exploit idea: the `provision?` precedence and adapter attributes let the `labeled` PR provision a stack; ReviewStack#env uppercases label names into env keys with no allowlist, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled labels, machine_env, steps, or branch names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: process the `labeled` PR under `allow_all`, set a self-added PR label name, assert the executed argv/env reflects the attacker input.
