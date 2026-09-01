# Q0280: [allow_all] `GIT_EXEC_PATH` via a pull request label name (uppercased) affecting the `tasks.<name>.steps` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `GIT_EXEC_PATH` through a pull request label name (uppercased) so that when the review stack runs its `tasks.<name>.steps` section the deploy process redirects git subcommand resolution to an attacker directory?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_EXEC_PATH` via a pull request label name (uppercased); the `tasks.<name>.steps` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `tasks.<name>.steps` step inherits `GIT_EXEC_PATH` from Command#unbundled_env and redirects git subcommand resolution to an attacker directory
- Invariant to test: The `tasks.<name>.steps` step inherits no fork-controllable key such as `GIT_EXEC_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `tasks.<name>.steps` step, inject `GIT_EXEC_PATH` via a pull request label name (uppercased), assert the env reaches the spawned process.
