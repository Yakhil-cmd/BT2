# Q2501: [allow_all] `LD_LIBRARY_PATH` via a pull request label name (uppercased) affecting the `ci.require` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `LD_LIBRARY_PATH` through a pull request label name (uppercased) so that when the review stack runs its `ci.require` section the deploy process redirects dynamic linking to attacker libraries for spawned binaries?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `LD_LIBRARY_PATH` via a pull request label name (uppercased); the `ci.require` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `ci.require` step inherits `LD_LIBRARY_PATH` from Command#unbundled_env and redirects dynamic linking to attacker libraries for spawned binaries
- Invariant to test: The `ci.require` step inherits no fork-controllable key such as `LD_LIBRARY_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `ci.require` step, inject `LD_LIBRARY_PATH` via a pull request label name (uppercased), assert the env reaches the spawned process.
