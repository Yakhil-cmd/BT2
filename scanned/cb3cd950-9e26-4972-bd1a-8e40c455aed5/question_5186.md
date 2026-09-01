# Q5186: [allow_all] `opened` PR RCE via the fork branch shipit.yml machine.environment

## Question
On provisioning_behavior=`allow_all`, can an unprivileged `opened` pull request supply the fork branch shipit.yml machine.environment so the provisioned review stack executes attacker code (machine_env is merged verbatim into the deploy env)?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged pull_request webhook -> ReviewStackProvisioningQueue -> PerformTaskJob
- Attacker controls: the fork branch shipit.yml machine.environment on a `opened` fork PR under `allow_all`
- Exploit idea: the provision gate is reachable for `opened` under `allow_all`; machine_env is merged verbatim into the deploy env, reaching Command#start
- Invariant to test: Review-stack execution derives only from maintainer-approved refs/specs, never from fork-controlled input.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: process the `opened` PR, set the fork branch shipit.yml machine.environment, assert the executed argv/env reflects attacker input.
