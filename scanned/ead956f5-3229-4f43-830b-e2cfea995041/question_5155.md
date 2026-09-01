# Q5155: [prevent_with_label] `GEM_PATH` via a pull request label name (uppercased) affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `GEM_PATH` through a pull request label name (uppercased) so that when the review stack runs its `fetch` section the deploy process adds an attacker gem path consulted by `require`/`bundle`?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GEM_PATH` via a pull request label name (uppercased); the `fetch` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the `fetch` step inherits `GEM_PATH` from Command#unbundled_env and adds an attacker gem path consulted by `require`/`bundle`
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `GEM_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `fetch` step, inject `GEM_PATH` via a pull request label name (uppercased), assert the env reaches the spawned process.
