# Q2447: Review-stack RCE via the PR head.ref branch name on `reopened`/allow_all

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged contributor's `reopened` pull request supply the PR head.ref branch name so the provisioned review stack executes attacker code, given that the branch is checked out and its shipit.yml executed?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the PR head.ref branch name on the fork PR under `allow_all`
- Exploit idea: the `provision?` precedence and adapter attributes let the `reopened` PR provision a stack; the branch is checked out and its shipit.yml executed, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled labels, machine_env, steps, or branch names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: process the `reopened` PR under `allow_all`, set the PR head.ref branch name, assert the executed argv/env reflects the attacker input.
