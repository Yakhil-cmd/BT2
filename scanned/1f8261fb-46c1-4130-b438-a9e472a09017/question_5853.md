# Q5853: [allow_all] `SSH_ASKPASS` via a pull request label name (uppercased) affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `SSH_ASKPASS` through a pull request label name (uppercased) so that when the review stack runs its `fetch` section the deploy process names a program executed to answer ssh password prompts?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `SSH_ASKPASS` via a pull request label name (uppercased); the `fetch` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `fetch` step inherits `SSH_ASKPASS` from Command#unbundled_env and names a program executed to answer ssh password prompts
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `fetch` step, inject `SSH_ASKPASS` via a pull request label name (uppercased), assert the env reaches the spawned process.
