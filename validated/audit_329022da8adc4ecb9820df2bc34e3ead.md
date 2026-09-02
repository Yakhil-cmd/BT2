Confirmed vulnerability: the webhook signature is verified against `repository_owner` (`request.headers` + `params.dig('repository','owner','login')`), while the handlers act on `repository.full_name` (a completely separate payload field). These two fields are never cross-checked.### Title
Webhook signature verification uses `repository.owner.login` while push processing acts on `repository.full_name`, allowing cross-repository sync spoofing when any configured org has no `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to validate an inbound webhook using `repository_owner`, which is read from the JSON body itself (`params.dig('repository','owner','login')`, falling back to `params.dig('organization','login')`) — not from any header, credential, or out-of-band-verified source. The signature is verified with the secret belonging to that *claimed* owner. Once verification passes, `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` resolve the target repository/stack using a *different* payload field, `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:33-38`, and similarly in the `PullRequest` handlers at `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`). These two attacker-supplied fields are never cross-validated against each other.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb:24-49`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
The organization used to select the verifying secret (`repository_owner`) comes entirely from the JSON body. Meanwhile the code path that actually performs work — `app/models/shipit/webhooks/handlers/handler.rb:32-38`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
uses `repository.full_name`, a sibling field in the same payload, to find the `Repository`/`Stack` that gets synced (via `PushHandler#process` → `stack.sync_github` → `GithubSyncJob`), or (for pull-request events) to find/create a `ReviewStack`.

Additionally, `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) trivially returns `true` when `webhook_secret` is blank:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```
In a multi-organization deployment (as documented in `docs/setup.md:182-209` and the example configs `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`), it's common/expected for some orgs to have no `webhook_secret` configured, and the default single-app config example ships with `webhook_secret: # nil` as well.

Because `repository_owner` (used to pick which secret verifies the signature) is independent of `repository.full_name` (used to pick which repository/stack the payload acts on), an unprivileged attacker who can reach the `/webhooks` endpoint can craft a request where:
- `repository.owner.login` = an organization whose `webhook_secret` is blank (or one for which the attacker otherwise knows the secret) → passes `verify_signature`.
- `repository.full_name` = `"victim-org/victim-repo"` → drives `Repository.from_github_repo_name`, causing the handler to act on a stack the attacker does not control.

This breaks the trust binding: *organization that authenticated* ≠ *repository that is written*.

### Impact Explanation
For `push` events this lets an attacker trigger `GithubSyncJob` against an arbitrary tracked repository/stack with an attacker-chosen `expected_head_sha`/branch pushed to that stack's git remote check, potentially forcing premature/incorrect sync state or (combined with `continuous_deployment`) triggering deploy pipelines out of band, all without needing that repository's real webhook secret. For `pull_request` events with `opened`/`reopened` handlers, an attacker can spoof creation/unarchiving of `ReviewStack`s for a targeted repository (`Shipit::Webhooks::Handlers::PullRequest::OpenedHandler`, `ReopenedHandler`), causing unauthorized provisioning/deprovisioning actions on stacks belonging to a different, unrelated repository/organization than the one whose credentials were actually verified. This is a cross-repository write triggered without possessing the victim organization's webhook secret, matching the "cross-repository writes" / "unauthorized deploy" Critical-impact criteria.

### Likelihood Explanation
Requires only unauthenticated HTTP access to the public `/webhooks` endpoint (no session, no API token, no repository access) plus knowledge that at least one configured GitHub organization in `Shipit.secrets.github` has no `webhook_secret` set (a state explicitly shown as the default in the shipped example configs and reachable in any real single-org deployment that leaves the optional field blank, as the docs do not mandate setting it). No social engineering, TLS interception, or privileged credentials are needed — only crafting a JSON body with mismatched `repository.owner.login` and `repository.full_name`.

### Recommendation
Bind the two identities together: derive `repository_owner` from `repository.full_name` (or vice versa) rather than treating them as independent trust anchors, and reject payloads where they disagree. Do not allow `verify_webhook_signature` to short-circuit to `true` when `webhook_secret` is blank — a missing secret should be a hard configuration/deployment guard, not an implicit bypass. Consider verifying that the app instance authorized for `repository_owner` actually has installation access to `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with two configured organizations, `orgA` (no `webhook_secret` set — matches shipped example configs) and `victim-org` (tracked stacks, real secret unknown to attacker).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No `X-Hub-Signature` header (or any value) is required because `Shipit.github(organization: "orgA").verify_webhook_signature` returns `true` immediately (blank secret).
3. `WebhooksController#create` dispatches to `PushHandler`, whose `stacks` resolves via `Repository.from_github_repo_name("victim-org/victim-repo")`, enqueuing `GithubSyncJob` for the victim's stack — despite the request only ever having its signature checked (trivially) against `orgA`.

*Note: full exploitation impact (e.g., whether `continuous_deployment` is enabled on the targeted stack, and downstream effects of a forced sync) depends on runtime configuration not fully inspectable via the indexed code; a live/staging Shipit instance would be needed to confirm end-to-end deploy triggering.*