# Q2153: [allow_all] `unassigned` PR RCE via the fork branch shipit.yml deploy.override steps

## Question
On provisioning_behavior=`allow_all`, can an unprivileged `unassigned` pull request supply the fork branch shipit.yml deploy.override steps so the provisioned review stack executes attacker code (fork-authored steps become the executed argv)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the fork branch shipit.yml deploy.override steps on a `unassigned` fork PR under `allow_all`
- Exploit idea: the provision gate is reachable for `unassigned` under `allow_all`; fork-authored steps become the executed argv, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: process the `unassigned` PR, set the fork branch shipit.yml deploy.override steps, assert the executed argv/env reflects attacker input.
