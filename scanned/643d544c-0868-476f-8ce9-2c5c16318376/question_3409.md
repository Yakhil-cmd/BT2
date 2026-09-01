# Q3409: [allow_all] `PERL5LIB` via a pull request label name (uppercased) affecting the `tasks.<name>.steps` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `PERL5LIB` through a pull request label name (uppercased) so that when the review stack runs its `tasks.<name>.steps` section the deploy process adds an attacker perl include path?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PERL5LIB` via a pull request label name (uppercased); the `tasks.<name>.steps` section of the fork shipit.yml under `allow_all`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `tasks.<name>.steps` step inherits `PERL5LIB` from Command#unbundled_env and adds an attacker perl include path
- Invariant to test: The `tasks.<name>.steps` step inherits no fork-controllable key such as `PERL5LIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `tasks.<name>.steps` step, inject `PERL5LIB` via a pull request label name (uppercased), assert the env reaches the spawned process.
