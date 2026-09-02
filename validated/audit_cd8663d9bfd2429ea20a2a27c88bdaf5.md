### Title
`GitHubApp#verify_webhook_signature` treats orgs with no `webhook_secret` as auto-verified, allowing unsigned `check_suite` webhooks to trigger `RefreshCheckRunsJob` for arbitrary repositories - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit.github(organization: repository_owner).verify_webhook_signature` short-circuits with `return true unless webhook_secret`, so any organization entry in `Shipit.github` config that lacks a `webhook_secret` accepts completely unsigned webhook requests as verified. Since `WebhooksController#verify_signature` looks up the app purely from the attacker-controlled `repository.owner.login` in the JSON body, and `CheckSuiteHandler#process` resolves the target stacks purely from the attacker-controlled `repository.full_name`, an attacker can name any repository/org in the payload and, if that org happens to be configured without a `webhook_secret`, force `RefreshCheckRunsJob` to enqueue for stacks of any repository under that org's namespace.

### Finding Description
The broken binding: the code treats `webhook_secret.present? == false` as `request_is_verified == true`, when it should be `request_is_verified == (signature matches HMAC(webhook_secret, raw_body))` regardless of whether a secret is configured (absence of a secret should mean "verification cannot succeed" for any org that is expected to be protected, or at minimum should not silently authenticate unsigned traffic for arbitrary repositories).

Path traced:
- `app/controllers/shipit/webhooks_controller.rb:24-30` (`verify_signature`) resolves `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` (line 59-62) is read directly from the untrusted JSON body (`params.dig('repository','owner','login')`).
- `lib/shipit/github_app.rb:76-83` (`verify_webhook_signature`): `return true unless webhook_secret` — if the resolved app's `@webhook_secret` (set at `lib/shipit/github_app.rb:50` from `@config[:webhook_secret].presence`) is nil, the method returns `true` without ever touching the `X-Hub-Signature` header or the raw body.
- Control then falls through to `WebhooksController#create` (lines 10-15), which dispatches to `Shipit::Webhooks.for_event('check_suite')` → `CheckSuiteHandler`.
- `app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-16` (`process`) calls `stacks.where(branch: ...).each { ... schedule_refresh_check_runs! }`.
- `stacks` is defined in the base `Handler` class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) as `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name` is `payload.dig('repository','full_name')` — again fully attacker-controlled, with no cross-check against `repository_owner` used for signature lookup consistency (though in the normal flow both come from the same JSON body).

Existing guards checked and found insufficient:
- `drop_unhandled_event` only checks that a handler exists for the event name; it does not check authenticity.
- `check_if_ping` only short-circuits `ping` events.
- The `ExplicitParameters` schema on `CheckSuiteHandler` (`requires :head_sha`, `:head_branch`) only validates shape/presence of fields, not authenticity of the sender.
- `GithubOrganizationUnknown` handling (`webhooks_controller.rb:39-49`) only fires when the org isn't configured at all; it does nothing when the org is configured but simply lacks `webhook_secret`.

Attacker exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: check_suite` and no `X-Hub-Signature` header, body `{"check_suite":{"head_sha":"<victim commit sha>","head_branch":"<victim branch>"},"repository":{"full_name":"<victim org>/<victim repo>","owner":{"login":"<victim org>"}}}`. If `<victim org>` is configured in `Shipit.github` without a `webhook_secret`, `verify_webhook_signature` returns `true`, the request is treated as authentic, and `CheckSuiteHandler` schedules `RefreshCheckRunsJob` for any stack whose `branch`/commit `sha` matches what the attacker named — with no proof the request came from GitHub at all.

### Impact Explanation
This is a genuine authentication bypass for orgs whose config omits `webhook_secret`, but the concrete impact is limited to `check_suite` handling: it enqueues `RefreshCheckRunsJob`, which (per its downstream API calls) refreshes/re-fetches check run state for the named commit from GitHub — it does not itself trigger deploys, rollbacks, merges, or expose secrets. This maps closest to an unauthenticated write for a resource (queuing a background job / GitHub API read) that the attacker didn't legitimately author, but it stops short of the Critical bar (RCE, secret exfiltration, cross-tenant stack/task mutation, unauthorized deploy) since `schedule_refresh_check_runs!`/`RefreshCheckRunsJob` only reads/refreshes check-run status, it doesn't execute commands or mutate deploy state. Blast radius is bounded to organizations that are (mis)configured without a `webhook_secret` — a configuration precondition, not a code defect that affects properly configured deployments.

### Likelihood Explanation
Exploitability strictly requires an operator-side misconfiguration: an entry in `Shipit.github` for an organization where `webhook_secret` is absent/blank. All the documented example secrets files (`config/secrets.development.example.yml`, `docs/setup.md`) show `webhook_secret` as a normal, expected field — Shipit's setup docs instruct operators to configure it. In a correctly configured production Shipit instance (every configured org has a `webhook_secret`), this path is inert since `verify_webhook_signature` would perform real HMAC verification. The bug is real but its trigger condition is an admin configuration gap, not something the attacker can force remotely.

### Recommendation
Change `GitHubApp#verify_webhook_signature` so that a missing `webhook_secret` never verifies to `true`. E.g., fail closed: `return false if webhook_secret.blank?` (and/or raise a configuration error at boot/app-resolution time if an org is configured without `webhook_secret`), so the absence of a secret can never be interpreted as an authenticated request.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "check_suite with no webhook_secret configured is NOT treated as verified" do
  Shipit.stubs(:github).with(organization: 'no-secret-org').returns(
    Shipit::GitHubApp.new('no-secret-org', { app_id: 1, installation_id: 1 }) # no webhook_secret key
  )

  request.headers['X-Github-Event'] = 'check_suite'
  # deliberately NO X-Hub-Signature header

  body = {
    check_suite: { head_sha: 'deadbeef', head_branch: 'master' },
    repository: { full_name: 'no-secret-org/victim-repo', owner: { login: 'no-secret-org' } }
  }.to_json

  assert_no_enqueued_jobs do
    post :create, body: body, as: :json
  end
  assert_response :unprocessable_entity # current buggy behavior: enqueues job & returns 200
end
```
Both sides of the equality: `webhook_secret.present? == false` should imply `request_verified == false`; currently `verify_webhook_signature` makes `request_verified == true`, which the above test demonstrates by asserting the job is *not* enqueued and the response is `422` — behavior that fails against the current code, confirming the divergence.