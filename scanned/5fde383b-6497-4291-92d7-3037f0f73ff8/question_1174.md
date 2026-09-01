# Q1174: [allow_all] `reopened` PR RCE via the PR head.ref branch name

## Question
On provisioning_behavior=`allow_all`, can an unprivileged `reopened` pull request supply the PR head.ref branch name so the provisioned review stack executes attacker code (the branch is checked out and its shipit.yml executed)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the PR head.ref branch name on a `reopened` fork PR under `allow_all`
- Exploit idea: the provision gate is reachable for `reopened` under `allow_all`; the branch is checked out and its shipit.yml executed, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: process the `reopened` PR, set the PR head.ref branch name, assert the executed argv/env reflects attacker input.
