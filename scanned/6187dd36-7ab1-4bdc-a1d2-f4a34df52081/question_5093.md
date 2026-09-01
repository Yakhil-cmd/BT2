# Q5093: [allow_all] `PROMPT_COMMAND` via a pull request label name (uppercased) affecting the `rollback.override` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `PROMPT_COMMAND` through a pull request label name (uppercased) so that when the review stack runs its `rollback.override` section the deploy process names a command bash runs before each prompt in an interactive-ish step?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PROMPT_COMMAND` via a pull request label name (uppercased); the `rollback.override` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `rollback.override` step inherits `PROMPT_COMMAND` from Command#unbundled_env and names a command bash runs before each prompt in an interactive-ish step
- Invariant to test: The `rollback.override` step inherits no fork-controllable key such as `PROMPT_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `rollback.override` step, inject `PROMPT_COMMAND` via a pull request label name (uppercased), assert the env reaches the spawned process.
