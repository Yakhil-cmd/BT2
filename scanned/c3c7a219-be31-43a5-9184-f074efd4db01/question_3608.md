# Q3608: Review-stack RCE via the fork branch shipit.yml deploy.override steps on `labeled`/allow_with_label

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged contributor's `labeled` pull request supply the fork branch shipit.yml deploy.override steps so the provisioned review stack executes attacker code, given that fork-authored steps become the executed argv?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the fork branch shipit.yml deploy.override steps on the fork PR under `allow_with_label`
- Exploit idea: the `provision?` precedence and adapter attributes let the `labeled` PR provision a stack; fork-authored steps become the executed argv, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled labels, machine_env, steps, or branch names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: process the `labeled` PR under `allow_with_label`, set the fork branch shipit.yml deploy.override steps, assert the executed argv/env reflects the attacker input.
