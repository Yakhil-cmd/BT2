### Title
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for an organization, allowing unsigned webhook forgery - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` short-circuits with `return true unless webhook_secret`, so any organization configured in `Shipit.secrets.github` (multi-org mode) without a `webhook_secret` accepts every webhook regardless of the `X-Hub-Signature` header content. An attacker who discovers such an org (by observing a `200 OK` instead of `422` when probing `POST /webhooks` with a bogus signature) can subsequently forge arbitrary webhook payloads for repositories under that org's name.

### Finding Description
The claimed binding is: `verify_webhook_signature(signature, body) == true` must imply `SecureCompare.secure_compare(signature_digest, HMAC(webhook_secret, body)) == true` (an actual secret-based check). In the code, `lib/shipit/github_app.rb:76-77`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```
this is violated: when `@webhook_secret` (set from `@config[:webhook_secret].presence` at `lib/shipit/github_app.rb:50`) is `nil`/blank, the method returns `true` with zero comparison performed — the equality is vacuously satisfied without any secret-based check.

Reachable path: `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) computes `repository_owner` directly from attacker-controlled JSON (`params.dig('repository','owner','login')`, `app/controllers/shipit/webhooks_controller.rb:59-61`), calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(header, raw_post)`. In multi-org mode, `Shipit#github` (`lib/shipit.rb:170-181`) looks up `github_app_config(organization)`; if the org key exists but its config has no `webhook_secret` (a documented, valid configuration state — see `test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`, which both ship orgs with `webhook_secret: # nil`), no exception is raised and a `GitHubApp` is built with a blank secret. The controller then accepts any signature for that org, and the raw JSON body is dispatched unauthenticated to every registered handler (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, `app/controllers/shipit/webhooks_controller.rb:12`) — e.g. `push` (queues `GithubSyncJob`), `status` (writes commit statuses), `membership` (adds/removes team members), or any custom handler.

Existing guards do not catch this: `drop_unhandled_event` only filters event *types*, not authenticity; the `422` returned for `GithubOrganizationUnknown` and the `422` returned for a bad signature on a *secured* org are actually the same status code, so an attacker cannot use that path to distinguish states — but they don't need to: a successful bypass produces `200 OK` directly, distinguishing "org has no secret" from "org has a secret and signature failed" (`422`) or "org unknown" (`422`). No other check in the request path (`ExplicitParameters` schemas, `Repository`/`Stack` validations) verifies webhook authenticity; they only validate payload shape after the (bypassed) signature check.

### Impact Explanation
For any multi-org-configured Shipit instance that has an organization entry without a `webhook_secret`, an unauthenticated attacker can submit arbitrary, unsigned webhook payloads that are accepted as authentic for that organization's repositories. This can trigger `GithubSyncJob`, forge commit statuses, and manipulate team membership (`MembershipHandler`) — writes attributed to a repository/org that never authenticated the request. This matches the Critical category: authentication bypass causing acceptance of a forged webhook and unauthorized state mutation for that org's repos/stacks/commits/teams. It is fully repeatable for every subsequent request against that specific organization once discovered.

### Likelihood Explanation
Requires: (1) the Shipit instance running multi-org GitHub App configuration (`Shipit#github_default_organization` non-nil), and (2) at least one configured organization lacking `webhook_secret`. This is not a hypothetical edge case — the shipped example/dev configs (`test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`) demonstrate this exact shape is a normal, supported configuration state, making accidental production occurrence plausible. The attacker needs no secrets or privileges: they only send unauthenticated `POST /webhooks` requests, which is explicitly in-scope for this attacker model.

### Recommendation
Change `verify_webhook_signature` to fail closed when no secret is configured (`return false unless webhook_secret`), and/or have `Shipit#github`/`WebhooksController` reject (422/500) webhook processing entirely for any organization whose config omits a `webhook_secret`, rather than silently treating "no secret" as "always verified."

### Proof of Concept
```ruby
# test/lib/shipit/github_app_test.rb (new/added case)
test "verify_webhook_signature returns true unconditionally when webhook_secret is blank" do
  app = Shipit::GitHubApp.new("someorg", { webhook_secret: nil, app_id: 1, installation_id: 1 })

  assert_equal true, app.verify_webhook_signature("sha1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "arbitrary body")
  assert_equal true, app.verify_webhook_signature("garbage-not-even-sha1", "any body at all")
end
```
Both assertions demonstrate the binding is broken: `verified == true` holds with no HMAC/secret comparison ever executed, for arbitrary bogus signatures and arbitrary bodies.