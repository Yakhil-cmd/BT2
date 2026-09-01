# Q5651: Unprivileged PR provisions/executes a review stack (sender.login as acting user, allow_with_label)

## Question
With repository provisioning_behavior=`allow_with_label`, can an unprivileged contributor's pull request exploit that `ReviewStackAdapter#user` is `User.find_or_create_by_login!(params.sender['login'])`, creating/acting-as an arbitrary login, so a `ReviewStack` is created and its fork-authored `shipit.yml` steps are later executed by `TaskCommands#perform` via `PTY.spawn`?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unprivileged pull_request webhook (opened/labeled/reopened) -> ReviewStackProvisioningQueue -> deploy
- Attacker controls: the PR head ref, labels, number, and sender.login; attacker relies that `ReviewStackAdapter#user` is `User.find_or_create_by_login!(params.sender['login'])`, creating/acting-as an arbitrary login
- Exploit idea: the provisioning gate and stack attributes are computed from fork-controlled webhook fields, so the user attributed to review-stack actions is the authenticated actor, not an attacker-named login
- Invariant to test: A review stack is provisioned and its steps executed only for a ref an authorized user approved on a repository with review stacks explicitly enabled.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: with the given provisioning_behavior, process an `opened` PR payload for an external head ref, assert a ReviewStack was created/queued and its checked-out shipit.yml steps would be spawned.
