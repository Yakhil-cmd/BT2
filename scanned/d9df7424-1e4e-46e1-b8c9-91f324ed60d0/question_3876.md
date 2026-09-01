# Q3876: Review-stack RCE via the fork branch shipit.yml machine.environment on `unlabeled`/allow_with_label

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged contributor's `unlabeled` pull request supply the fork branch shipit.yml machine.environment so the provisioned review stack executes attacker code, given that machine_env is merged verbatim into the deploy env?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the fork branch shipit.yml machine.environment on the fork PR under `allow_with_label`
- Exploit idea: the `provision?` precedence and adapter attributes let the `unlabeled` PR provision a stack; machine_env is merged verbatim into the deploy env, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled labels, machine_env, steps, or branch names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: process the `unlabeled` PR under `allow_with_label`, set the fork branch shipit.yml machine.environment, assert the executed argv/env reflects the attacker input.
