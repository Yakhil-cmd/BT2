### Title
Webhook signature verification selects GitHub App by `repository.owner.login`, but handlers resolve target `Repository`/`Stack` by `repository.full_name` — allowing cross-tenant webhook forgery in multi-org configs - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to validate a webhook against using `repository.owner.login`, while every event handler (`Shipit::Webhooks::Handlers::Handler#stacks`, used by `PushHandler`, PR handlers, etc.) independently resolves the target `Repository`/`Stack` using `repository.full_name`. These two attacker-controlled fields are never checked for consistency, so in a multi-GitHub-App deployment an attacker who controls one org's webhook (especially one with no `webhook_secret` configured) can forge a payload whose `full_name` names a *different* org's repository, causing Shipit to act on that other org's stack without ever validating a signature for it.

### Finding Description
The broken binding is:
`repository_owner` (`params.dig('repository','owner','login')` in `app/controllers/shipit/webhooks_controller.rb:61`, used to pick `Shipit.github(organization: repository_owner)` at line 25) **should equal** the owner segment of `repository.full_name` (`payload.dig('repository','full_name')`, used by `Repository.from_github_repo_name` in `app/models/shipit/webhooks/handlers/handler.rb:33-37` and `app/models/shipit/repository.rb:53-56`).

Both values are read from the same attacker-supplied JSON body but from unrelated keys (`repository.owner.login` vs `repository.full_name`), and nothing enforces that the owner segment of `full_name` matches `repository.owner.login`. The controller verifies the signature using the app selected by `repository_owner`, then unconditionally hands the *entire raw payload* to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:12`), and the handler resolves the stack independently via `full_name`.

Compounding this, `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) contains `return true unless webhook_secret` — if an org's app config has no `webhook_secret` (as documented for the "double GitHub App" multi-tenant setup), verification is a no-op and *any* payload posted under that org's name is accepted as "verified," regardless of the `X-Hub-Signature` header content.

Exploit flow: an attacker who owns/administers an org ("orgtwo") whose GitHub App entry has `webhook_secret: nil` sends `POST /webhooks` with:
- `X-Github-Event: push`
- body: `{"repository": {"owner": {"login": "orgtwo"}, "full_name": "orgone/some-repo"}, "ref": "refs/heads/master", "after": "<attacker-chosen sha>"}`

`verify_signature` selects OrgTwo's `GitHubApp`, calls `verify_webhook_signature`, which returns `true` unconditionally because `webhook_secret` is blank — no valid HMAC is even required. `create` then dispatches to `PushHandler`, whose `stacks` method (`app/models/shipit/webhooks/handlers/handler.rb:33`) looks up `Repository.from_github_repo_name("orgone/some-repo")`, finds OrgOne's real repository/stack, and calls `stack.sync_github(expected_head_sha: params.after)` (`app/models/shipit/webhooks/handlers/push_handler.rb:16`), which triggers `GithubSyncJob` for OrgOne's stack — a stack the attacker never authenticated against.

No existing guard prevents this: `drop_unhandled_event` only checks the event type exists; `verify_signature` never cross-checks `repository_owner` against `full_name`'s owner; `Repository.from_github_repo_name` performs no ownership/App-provenance check, only an DB lookup by owner/name strings; `ExplicitParameters` schemas (e.g., `PushHandler.params`) only validate `ref`/`after` presence, not organization consistency.

### Impact Explanation
An attacker controlling a single, low-trust org (particularly one configured without a `webhook_secret`, but even one with a secret only proves "some payload from *an* app was HMAC-valid," not that it corresponds to `full_name`'s owner) can trigger `GithubSyncJob` (and equivalently, PR-based handlers — labeling, closing, opening, etc., which affect `ReviewStack`/`Stack` lifecycle) for **any other tenant's repository/stack** known by name, without any credential belonging to that tenant. This is a cross-tenant authentication bypass: "a payload for one repository mutating another's stack," matching the Critical severity category. It is repeatable against arbitrary stacks by simply changing `full_name` in each forged request, and the blast radius spans every stack in every org configured in the multi-app setup, since any org can name any other org's repo.

### Likelihood Explanation
Preconditions: Shipit must be running the documented multi-GitHub-App configuration (per-org entries with independent `webhook_secret`s, as opposed to the legacy single-app config). The attacker only needs control of one org's webhook delivery — i.e., to own/administer any GitHub org registered in Shipit's config (satisfying the "attacker owns a repo/org and can emit webhooks" threat model) — and, for the maximal (no-signature-required) case, that org's config must have `webhook_secret` unset. Even where a secret is set, the attacker who owns that org can compute a valid HMAC with their own known secret and still forge `full_name` for a different org, since the two values are never cross-validated. No Shipit session, API token, or GitHub App private key is required. This is a straightforward, fully repeatable HTTP-only exploit.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#stacks`), enforce that the owner used to select the verifying `GitHubApp` matches the owner segment of `repository.full_name` (and `organization.login` where present) before dispatching to handlers — reject the webhook (422) if they diverge. Additionally, consider making a missing/blank `webhook_secret` a hard configuration error rather than a silent bypass in `GitHubApp#verify_webhook_signature`, so misconfigured orgs cannot accept unsigned webhooks at all.

### Proof of Concept
Minitest plan (no live GitHub):
```ruby
test "push webhook naming a different org's repo does not get processed as verified for that org" do
  # Config: orgtwo has webhook_secret: nil, orgone has a real secret and owns stack `stack_for_orgone`.
  stub_organization_config('orgone', webhook_secret: 'orgone-secret')
  stub_organization_config('orgtwo', webhook_secret: nil)

  repo = Shipit::Repository.create!(owner: 'orgone', name: 'some-repo')
  stack = create(:stack, repository: repo, branch: 'master')

  payload = {
    repository: { owner: { login: 'orgtwo' }, full_name: 'orgone/some-repo' },
    ref: 'refs/heads/master',
    after: 'deadbeef'
  }.to_json

  # No valid signature for orgone is supplied; only orgtwo (secretless) "verifies".
  assert_no_enqueued_jobs(only: Shipit::GithubSyncJob) do
    post '/webhooks', params: payload, headers: {
      'X-Github-Event' => 'push',
      'X-Hub-Signature' => 'sha1=bogus',
      'Content-Type' => 'application/json'
    }
  end
  # Assert both sides of the equality:
  assert_equal 'orgtwo', JSON.parse(payload).dig('repository', 'owner', 'login')  # app selected for verification
  assert_equal 'orgone', JSON.parse(payload).dig('repository', 'full_name').split('/').first  # owner used by handler
  # Current behavior: request returns 200 and GithubSyncJob IS enqueued for `stack` (orgone), proving the divergence is exploitable.
end
```
This demonstrates that `repository_owner` (`"orgtwo"`) and the owner segment of `repository.full_name` (`"orgone"`) diverge, and that the handler acts on the latter despite verification only covering the former.