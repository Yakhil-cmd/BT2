# Q3377: [allow_all] `NODE_OPTIONS` via a pull request label name (uppercased) affecting the `review.checklist` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `NODE_OPTIONS` through a pull request label name (uppercased) so that when the review stack runs its `review.checklist` section the deploy process injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `NODE_OPTIONS` via a pull request label name (uppercased); the `review.checklist` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `review.checklist` step inherits `NODE_OPTIONS` from Command#unbundled_env and injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: The `review.checklist` step inherits no fork-controllable key such as `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `review.checklist` step, inject `NODE_OPTIONS` via a pull request label name (uppercased), assert the env reaches the spawned process.
