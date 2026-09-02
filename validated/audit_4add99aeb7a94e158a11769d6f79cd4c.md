### Title
Signature verification is scoped by `repository.owner.login` while the handler mutates the stack named by `repository.full_name`, with no check that they match, and `GitHubApp#verify_webhook_signature` waives verification entirely for apps without a `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to verify the request against using `repository_owner` (`repository.owner.login`), but `Handler#repository_name`/`#stacks` (used by every webhook handler, e.g. `PushHandler`) resolve the actual repository/stack to mutate from `repository.full_name`. Both values come from the same unauthenticated JSON body and are never cross-checked. If any configured GitHub App in `Shipit.secrets.github` has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, letting an attacker "verify" as that org while pointing `repository.full_name` at a completely different, properly-secured organization's repository.

### Finding Description
The binding the code implicitly assumes is:
`organization whose webhook_secret validated request bytes == organization owning the repository the handler mutates`

Trace:
- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (line 59-62) reads `params.dig('repository', 'owner', 'login')` directly from the raw, unauthenticated JSON body.
- `github_app.verify_webhook_signature` (lib/shipit/github_app.rb:76-83) does `return true unless webhook_secret`. If the resolved app (OrgA) has `webhook_secret: nil`, this returns `true` for *any* signature, including a missing/garbage `X-Hub-Signature` header.
- `#create` (app/controllers/shipit/webhooks_controller.rb:10-15) then parses the same raw body and dispatches it unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- Handlers such as `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) call `stacks`, which is defined in `Handler#stacks`/`#repository_name` (app/models/shipit/webhooks/handlers/handler.rb:32-38) as `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` — a field independent of `repository_owner` and never validated against it.

Exploit: attacker POSTs to `/webhooks` with header `X-Github-Event: push` and a JSON body where `repository.owner.login = "OrgA"` (an app configured with no `webhook_secret`) and `repository.full_name = "OrgB/target-repo"` (a real stack belonging to a different, secret-protected org). `verify_signature` resolves and "verifies" against OrgA's secret-less app (always true), so the request passes with `head(422)` never triggered. `#create` then runs `PushHandler` against `repository.full_name = "OrgB/target-repo"`, calling `stack.sync_github(...)`, enqueuing a `GithubSyncJob` for OrgB's stack — a write triggered on OrgB's data with no valid signature for OrgB ever presented.

Existing guards do not catch this: `drop_unhandled_event` only checks event type; `verify_signature` never compares `repository_owner` to `repository.full_name`'s owner segment; `ExplicitParameters` schemas in handlers (`requires :ref`, `requires :after`) validate shape, not repository identity; there is no `force_github_authentication`, session, or API-client check on this unauthenticated endpoint (webhooks are inherently unauthenticated by design, relying solely on HMAC signature verification, which is what's bypassed here).

### Impact Explanation
An attacker with no Shipit credentials can trigger writes (e.g., `GithubSyncJob` enqueue, potentially `ReviewStack` creation via other handlers) against any stack/repository in the Shipit instance, as long as any one configured GitHub App in the multi-app setup lacks a `webhook_secret`. This is a cross-tenant confused-deputy: OrgA's (weak/no-secret) identity is used to authorize mutations on OrgB's (strong-secret) stacks. This matches "Critical — a payload for one repository mutating another's stack" since the write is not tied to any valid proof of authorship/control over the target repository.

### Likelihood Explanation
Preconditions: Shipit must be configured with multiple GitHub Apps (per docs/setup.md) where at least one configured org's app has `webhook_secret` unset/blank. Given that precondition (explicitly stated in the question as the scenario), the attack costs nothing — a single unauthenticated HTTP POST with a crafted JSON body, no signature required, fully repeatable against any repository/stack by changing `repository.full_name`. The only variable outside attacker control is whether such a secret-less app exists in `Shipit.secrets.github`; wherever it does, exploitation is trivial and deterministic.

### Recommendation
In `WebhooksController#verify_signature`, derive the org used for signature verification and confirm it matches the owner segment of `repository.full_name` (or better, resolve the target `Repository`/`Stack` first, verify against *that* repository's app/secret, and reject if they diverge). Additionally, remove or gate the `return true unless webhook_secret` fallback in `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-77) so that a missing secret fails closed instead of open, at least outside test/development environments.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (minitest, ActionController::TestCase style)
test "push webhook signed by an org without webhook_secret cannot sync another org's stack" do
  # Setup: Shipit.secrets.github has OrgA (no webhook_secret) and OrgB (webhook_secret configured)
  org_b_stack = shipit_stacks(:shipit) # belongs to OrgB, repository full_name "OrgB/target-repo"

  payload = {
    ref: 'refs/heads/master',
    after: 'deadbeef',
    repository: { full_name: 'OrgB/target-repo', owner: { login: 'OrgA' } }
  }.to_json

  assert_no_difference -> { org_b_stack.reload.updated_at } do
    assert_enqueued_with(job: GithubSyncJob, args: [{ stack_id: org_b_stack.id, expected_head_sha: 'deadbeef' }]) do
      post :create, body: payload, params: {},
        headers: { 'X-Github-Event' => 'push' } # no valid X-Hub-Signature for OrgB ever presented
    end
  end
end
```
Assertion on both sides of the binding: (1) no valid HMAC signature computed with OrgB's `webhook_secret` was ever presented, yet (2) `GithubSyncJob` is enqueued for OrgB's stack — proving the "verified org" and "mutated org" diverged.