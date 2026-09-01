# Q4794: [prevent_with_label] `ready_for_review` PR RCE via the fork branch shipit.yml deploy.override steps

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged `ready_for_review` pull request supply the fork branch shipit.yml deploy.override steps so the provisioned review stack executes attacker code (fork-authored steps become the executed argv)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the fork branch shipit.yml deploy.override steps on a `ready_for_review` fork PR under `prevent_with_label`
- Exploit idea: the provision gate is reachable for `ready_for_review` under `prevent_with_label`; fork-authored steps become the executed argv, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: process the `ready_for_review` PR, set the fork branch shipit.yml deploy.override steps, assert the executed argv/env reflects attacker input.
