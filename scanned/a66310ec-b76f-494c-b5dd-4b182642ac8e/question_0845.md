# Q0845: [prevent_with_label] `synchronize` PR RCE via the fork branch shipit.yml machine.environment

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged `synchronize` pull request supply the fork branch shipit.yml machine.environment so the provisioned review stack executes attacker code (machine_env is merged verbatim into the deploy env)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the fork branch shipit.yml machine.environment on a `synchronize` fork PR under `prevent_with_label`
- Exploit idea: the provision gate is reachable for `synchronize` under `prevent_with_label`; machine_env is merged verbatim into the deploy env, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: process the `synchronize` PR, set the fork branch shipit.yml machine.environment, assert the executed argv/env reflects attacker input.
