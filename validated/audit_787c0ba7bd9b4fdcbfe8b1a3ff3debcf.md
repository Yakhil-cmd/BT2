### Title
Cross-organization webhook forgery via mismatched `repository.owner.login` (signature scope) vs `repository.full_name` (mutation scope) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / webhook secret to validate the HMAC against using `params.dig('repository', 'owner', 'login')`, while `ClosedHandler#repository` looks up the `Repository` (and therefore the `ReviewStack` to archive/deprovision) using the entirely separate, independently-attacker-controlled `params.repository.full_name` field. Nothing ties these two values together, so a payload can be validly signed for one organization while acting on a completely different organization's repository/stack.

### Finding Description
The broken binding, stated as an equality that the code fails to enforce:
`org_owning(secret_used_to_verify_signature) == org_owning(repository_row_mutated_by_handler)`

should hold, but the code never checks it.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` purely from the raw JSON body via `repository_owner` (line 59-62): `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. It then fetches `Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against that org's `webhook_secret` (`lib/shipit/github_app.rb#verify_webhook_signature`).
- If verification succeeds, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the *same raw JSON body*, but the handler never re-uses `repository_owner`; it reads `params.repository.full_name` directly (`app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb:49-53`):
```ruby
def repository
  @repository ||=
    Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
    Shipit::NullRepository.new
end
```
- `ClosedHandler#process` then does `review_stack.archive!` (line 41-45), which resolves the `ReviewStack` via `ReviewStackAdapter#stack` matching on `environment: "pr#{params.number}"` scoped to `repository.review_stacks` (app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:15-17, 96-98), and `archive!` (lines 23-35) unconditionally calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!(user)` if a matching, non-archived stack exists.
- The `ExplicitParameters` schema for `ClosedHandler` (lines 8-39) only `requires :repository { requires :full_name, String }` — it never requires or cross-checks `repository.owner.login` against `full_name`.
- In Shipit's multi-organization mode, each organization can have its own independent GitHub App configuration/`webhook_secret` (`lib/shipit.rb#github_app_config`, `test/dummy/config/secrets_double_github_app.yml`). An attacker who legitimately administers their own org's GitHub App (and therefore knows/controls their own org's `webhook_secret`) can craft an arbitrary raw POST body to `POST /webhooks` — not a real GitHub-relayed event — setting `repository.owner.login = "attacker-org"` (so `verify_signature` selects and passes against the secret they know) while simultaneously setting `repository.full_name = "victim-org/victim-repo"` and `number` to the victim's PR number. Since HMAC covers the whole raw body and the attacker controls the whole body, they can compute a valid signature for that body using their own known secret.
- Existing guards do not stop this: `verify_signature` only checks the HMAC is valid for *some* org derived from attacker-controlled data — it doesn't and can't validate that the acted-upon repository belongs to that same org. `drop_unhandled_event` only filters unregistered events. The `ExplicitParameters` schema only validates shape/types, not cross-field organizational consistency. No model validation in `Repository`/`Stack` ties the record being mutated back to the org that authenticated the request.

### Impact Explanation
A successful forged request causes `Shipit::Stack#deprovision` and `Stack#archive!(user)` to run against a victim organization's live `ReviewStack`, using the Shipit app's own GitHub credentials for that victim's installation. This is a cross-tenant/cross-repository mutation triggered by a payload that only authenticated for a different organization — matching the Critical category "a payload for one repository mutating another's stack". It denies a legitimate deploy target and forces deprovisioning/archival infrastructure commands to run against victim infra without any authorization from the victim. This is repeatable against any repository/PR-number pair for which an active `ReviewStack` exists, as long as the attacker knows any organization's webhook secret they control.

### Likelihood Explanation
Preconditions: Shipit must be deployed in the multi-organization GitHub App mode (per-org `webhook_secret`s), and the attacker must control (know) the webhook secret of at least one organization that has the Shipit app installed — realistic if the attacker is an admin of their own tenant org in a multi-tenant Shipit installation. No Shipit session, API token, or victim secrets are needed. The victim only needs an existing `ReviewStack` for a guessable/known PR number/environment. Attacker cost is a single crafted HTTP POST with a self-computed HMAC; it is fully repeatable and scriptable against any victim repository/PR number known to the attacker.

### Recommendation
Bind the authenticated organization to the resource acted upon. E.g., in `WebhooksController#create`/`verify_signature`, derive the authoritative owner from the same field used for signature verification and pass it down; then in `ClosedHandler#repository` (and all other PR handlers using this pattern, e.g. `LabeledHandler`, `UnlabeledHandler`), reject/ignore the event unless `Repository#owner` (or `params.repository.full_name.split('/').first`) case-insensitively equals the `repository_owner` validated by `verify_signature`. Alternatively, require and validate `repository.owner.login` matches the owner portion of `repository.full_name` in the `ExplicitParameters` schema, and thread the verified organization through the handler dispatch so handlers can assert equality before performing any lookup/mutation.

### Proof of Concept
Minitest plan (no live GitHub, using `secrets_double_github_app.yml`-style multi-org config with per-org webhook secrets):
```ruby
test "cross-org closed event archives victim's review stack" do
  # Setup: OrgVictim has a review stack for PR #42 (environment "pr42")
  victim_repo = shipit_repositories(:victim_org_repo) # owner: "victim-org"
  victim_stack = create_review_stack(repository: victim_repo, environment: "pr42")
  victim_stack.update!(provision_status: :provisioned)

  # Attacker knows AttackerOrg's webhook secret (configured in Shipit for AttackerOrg)
  attacker_secret = "attacker-known-secret"
  body = {
    action: "closed",
    number: 42,
    pull_request: { id: 1, number: 42, url: "u", title: "t", state: "closed",
                     additions: 1, deletions: 1,
                     head: { sha: "a" * 40, ref: "attacker-branch" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    repository: { full_name: "victim-org/victim-repo", owner: { login: "attacker-org" } },
    sender: { login: "attacker" }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_secret, body)

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  # Binding under test, stated before tracing:
  # org_owning(secret_used_for_verification) == "attacker-org"
  # org_owning(repository_row_mutated)        == "victim-org"
  # These MUST be equal for the request to be legitimate; they are not.

  assert_not_equal "attacker-org", "victim-org" # both sides recorded distinctly

  refute victim_stack.reload.archived?

  post :create, body:, as: :json

  assert_response :ok
  assert victim_stack.reload.archived?, "victim-org's stack was archived by an attacker-org-signed request"
end
```
This demonstrates that a request whose HMAC validates only for `attacker-org`'s secret is able to mutate (archive/deprovision) `victim-org`'s `ReviewStack`, confirming the two sides of the equality diverge and are never checked.