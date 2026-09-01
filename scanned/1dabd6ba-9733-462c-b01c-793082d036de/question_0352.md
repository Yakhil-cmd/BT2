# Q0352: Unprivileged PR provisions/executes a review stack (operator-precedence bug in provision?, allow_with_label)

## Question
With repository provisioning_behavior=`allow_with_label`, can an unprivileged contributor's pull request exploit that `OpenedHandler#provision?` is `enabled && allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label)` — `&&` binds tighter than `||`, so the last two disjuncts never require `review_stacks_enabled`, so a `ReviewStack` is created and its fork-authored `shipit.yml` steps are later executed by `TaskCommands#perform` via `PTY.spawn`?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unprivileged pull_request webhook (opened/labeled/reopened) -> ReviewStackProvisioningQueue -> deploy
- Attacker controls: the PR head ref, labels, number, and sender.login; attacker relies that `OpenedHandler#provision?` is `enabled && allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label)` — `&&` binds tighter than `||`, so the last two disjuncts never require `review_stacks_enabled`
- Exploit idea: the provisioning gate and stack attributes are computed from fork-controlled webhook fields, so a PR provisions a review stack on a repository whose review stacks were never enabled
- Invariant to test: A review stack is provisioned and its steps executed only for a ref an authorized user approved on a repository with review stacks explicitly enabled.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: with the given provisioning_behavior, process an `opened` PR payload for an external head ref, assert a ReviewStack was created/queued and its checked-out shipit.yml steps would be spawned.
