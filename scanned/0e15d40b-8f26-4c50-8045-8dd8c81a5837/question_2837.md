# Q2837: Unprivileged PR provisions/executes a review stack (provisioning label self-assignment, prevent_with_label)

## Question
With repository provisioning_behavior=`prevent_with_label`, can an unprivileged contributor's pull request exploit that the PR author adds/removes the `provisioning_label_name` label on their own PR to flip archive/unarchive/provision, so a `ReviewStack` is created and its fork-authored `shipit.yml` steps are later executed by `TaskCommands#perform` via `PTY.spawn`?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unprivileged pull_request webhook (opened/labeled/reopened) -> ReviewStackProvisioningQueue -> deploy
- Attacker controls: the PR head ref, labels, number, and sender.login; attacker relies that the PR author adds/removes the `provisioning_label_name` label on their own PR to flip archive/unarchive/provision
- Exploit idea: the provisioning gate and stack attributes are computed from fork-controlled webhook fields, so the label gating provisioning is controllable by the unprivileged PR author
- Invariant to test: A review stack is provisioned and its steps executed only for a ref an authorized user approved on a repository with review stacks explicitly enabled.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: with the given provisioning_behavior, process an `opened` PR payload for an external head ref, assert a ReviewStack was created/queued and its checked-out shipit.yml steps would be spawned.
