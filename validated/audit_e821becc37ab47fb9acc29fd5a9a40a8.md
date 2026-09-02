### Title
Secret-less org verification lets webhook payload's `repository.owner.login` diverge from `repository.full_name`, letting an unauthenticated attacker mutate any stack's accessibility - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/org config to verify against using `repository_owner`, taken from `params.dig('repository','owner','login')` (or `organization.login`), while the handler that actually resolves the target `Stack` uses a *different* field, `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name`. Because `verify_webhook_signature` short-circuits to `true` whenever the resolved org has no `webhook_secret` configured (`return true unless webhook_secret`), an attacker who knows any org in the Shipit config is secret-less can construct a raw JSON POST to `/webhooks` where `repository.owner.login` names that secret-less org (so signature checking is skipped entirely) but `repository.full_name` names an arbitrary victim `owner/repo`, causing `PushHandler`/other handlers to act on a stack belonging to a completely different, unrelated tenant.

### Finding Description
The binding the code should enforce is: `org used to verify the signature == org that owns the stack being mutated`, i.e. `params.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`. Nothing in the code enforces this equality.

- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` from the payload and fetches `Shipit.github(organization: repository_owner)`, then calls `github_app.verify_webhook_signature(...)`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) returns `true` unconditionally when `webhook_secret` is blank for that org config — i.e., for any "secret-less" org, **no cryptographic check is performed at all**, regardless of the `X-Hub-Signature` header or body content.
- After verification "passes," `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers, passing the raw parsed JSON (`params = JSON.parse(request.raw_post)`) as `payload`.
- `Handler#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38) resolves the target via `repository_name = payload.dig('repository', 'full_name')` — a completely separate field from the one used for signature verification.
- `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) then loads stacks for that `full_name`/branch and calls `stack.sync_github`, which enqueues `GithubSyncJob`.
- In `GithubSyncJob#handle_github_errors` (app/jobs/shipit/github_sync_job.rb:80-89), an `Octokit::NotFound` (trivial to trigger — the installation genuinely has no access to a repo the attacker doesn't own) causes `stack.mark_as_inaccessible!` to be called on the victim stack.

Because `repository.owner.login` and `repository.full_name` are both attacker-controlled fields inside a single raw HTTP POST body (this is not a real GitHub-signed webhook relay — the attacker POSTs directly to `/webhooks`), the attacker sets them inconsistently: `owner.login` = a known secret-less org (to bypass all signature checking), `full_name` = `victim-org/victim-repo` (to target an unrelated tenant's stack). Since `full_name` need not match `owner.login`, there is no cross-check anywhere in `verify_signature`, `drop_unhandled_event`, `check_if_ping`, or `Handler#initialize`/`ExplicitParameters` schema that ties them together.

### Impact Explanation
This is an authentication-bypass-driven cross-tenant write: an unauthenticated, unrelated party can flip `Stack#inaccessible` (and, via the accessible branch, `mark_as_accessible!`) on any stack in the installation, as long as one configured org in `Shipit.github_teams`-style config is secret-less. This directly matches the Critical category "payload for one repository mutating another's stack" and "authentication bypass (forged webhook ... accepted)." The blast radius spans every stack whose owning org is not the secret-less one, and it's fully repeatable per request — each POST can target a different victim stack, toggling accessibility state and potentially disrupting deploy eligibility / sync behavior for arbitrary tenants.

### Likelihood Explanation
Preconditions: at least one org in the Shipit deployment config must be configured without a `webhook_secret` (a documented, non-default but supported configuration — see `docs/setup.md` and `config/secrets.*.yml` examples referencing secret-less setups). The attacker needs no credentials, no GitHub App installation, no session, and no API token — only knowledge (or a guess) of one secret-less org's login and the ability to POST to `/webhooks`. This is low-cost and fully repeatable.

### Recommendation
Cross-validate that `repository.full_name`'s owner segment matches the `repository_owner` (or `organization.login`) used to select the verifying GitHub App config, rejecting the webhook (422) on mismatch, before dispatching to any handler. Additionally, consider disallowing "secret-less" org verification from being used to authorize processing of payloads referencing repositories outside that org's namespace, and prefer failing closed (require a configured `webhook_secret`) rather than treating a missing secret as "verified."

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "cross-org spoofed push targets victim stack owned by a different, secret-checked org" do
  secretless_org = "secretless-org"     # configured with no webhook_secret
  victim_stack = shipit_stacks(:shipit) # owned by e.g. "shopify/shipit-engine"

  payload = {
    "ref" => "refs/heads/#{victim_stack.branch}",
    "after" => "deadbeef" * 5,
    "repository" => {
      "full_name" => victim_stack.repository.full_name, # e.g. "shopify/shipit-engine"
      "owner" => { "login" => secretless_org }           # controls signature bypass only
    }
  }.to_json

  GithubSyncJob.any_instance.expects(:mark_as_inaccessible!).never # sanity baseline
  Stack.any_instance.expects(:sync_github).with(expected_head_sha: anything)

  post shipit.hooks_path, params: payload,
    headers: { 'X-Github-Event' => 'push', 'X-Hub-Signature' => 'sha1=bogus', 'Content-Type' => 'application/json' }

  assert_response :ok
  # Assert stack lookup happened via full_name (victim's org), not repository_owner (secretless_org)
  # i.e. victim_stack.repository.owner != secretless_org, yet sync_github was still invoked on victim_stack.
end
```
This demonstrates that `verify_signature` authorizes the request using `secretless_org` (no secret check performed), while the actual mutated resource (`victim_stack`) belongs to a different, unrelated org — violating the binding `verifying org == stack-owning org`.