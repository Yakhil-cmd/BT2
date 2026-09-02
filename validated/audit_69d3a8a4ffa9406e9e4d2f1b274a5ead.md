### Title
Signature verification org (`repository.owner.login`) is not bound to the repository resolved for `ReviewStack` creation (`repository.full_name`) - ([File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `params.dig('repository','owner','login')` (or `organization.login`), while `LabeledHandler#repository` resolves the target `Shipit::Repository` using the independent field `params.repository.full_name`. Nothing enforces these two attacker-controlled JSON fields refer to the same organization, so on a multi-org Shipit install an attacker who owns a valid, onboarded organization can sign a payload with their own `webhook_secret` (matched via `owner.login`) but point `repository.full_name` at a different tenant's repository to trigger `ReviewStack` creation on it.

### Finding Description
The claimed binding, `organization_that_verified_signature == organization_that_gates_stack_creation`, is **not enforced**.

- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (fallback `organization.login`) and calls `Shipit.github(organization: repository_owner)` to get the `GitHubApp` (and its `webhook_secret`) used to verify `X-Hub-Signature` (`app/controllers/shipit/webhooks_controller.rb:24-49,59-62`).
- `Shipit.github`/`github_app_config` looks up the config keyed by organization name from `secrets.github` (`lib/shipit.rb:170-200`), which is only distinct per-org in the "multiple GitHub Applications" configuration mode (`docs/setup.md:182-209`, `test/dummy/config/secrets_double_github_app.yml`).
- `LabeledHandler#repository` resolves the tenant *repository row* using `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which just splits the string on `/` and does a DB lookup by `owner`/`name` (`app/models/shipit/repository.rb:53-56`) — it never re-checks `params.repository.owner.login`.
- The `LabeledHandler` `params` schema only `requires :repository do requires :full_name, String end` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:33-35`) — it does not require or validate `repository.owner.login` at all, and even if present, it's never cross-checked against `full_name`.
- `LabeledHandler#unarchive?` → `stack.unarchive!` → `ReviewStackAdapter#unarchive!` → `create!` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:37-50,72-85`) creates a brand-new `Shipit::ReviewStack` scoped to `repository.review_stacks` — i.e., scoped to whatever `Repository` row `from_github_repo_name` returned, regardless of which org's secret verified the request.

Exploit flow (multi-org config precondition): Attacker controls `attacker-org` which is legitimately onboarded to this Shipit instance (has its own `webhook_secret`). They craft a raw JSON webhook body where `repository.owner.login = "attacker-org"` (so `verify_signature` selects and validates against the secret they know) but `repository.full_name = "victim-org/victim-repo"` (the tenant whose `Repository` row has `provisioning_behavior_allow_with_label` and `review_stacks_enabled` set). They add the provisioning label to their own PR (all self-authored, no privileged access needed) and POST the signed payload to `/webhooks` with event `pull_request`/action `labeled`. Signature check passes (attacker-org's secret matches attacker-org's payload signing), `drop_unhandled_event`/schema validation pass since the payload is well-formed, and `LabeledHandler` then resolves `victim-org/victim-repo` and calls `ReviewStack.create!` for it.

None of the existing guards close this gap: `verify_signature` never re-derives or checks organization from `full_name`; `ExplicitParameters` schema validates types/presence, not cross-field consistency; `Repository` validations (`owner`/`name` format) don't protect against a mismatched-but-valid full_name; `EnvironmentVariables#permit` and `force_github_authentication`/`User#authorized?` are irrelevant to this webhook path (webhooks bypass session auth entirely by design).

### Impact Explanation
An attacker can cause `Shipit::ReviewStack.create!` (and downstream `ReviewStackProvisioningQueue.add`, which triggers a provisioning deploy task) for a repository belonging to a different, unrelated tenant that never authenticated or authorized the request. This is a payload for one repository/org mutating another's stack — matching the Critical impact category ("a payload for one repository mutating another's stack ... or an unauthorized deploy"). It is repeatable against any victim repository configured with `provisioning_behavior_allow_with_label` and `review_stacks_enabled` on any Shipit instance running the documented multi-org configuration, since the attacker only needs to alter the `full_name` string per request — the blast radius spans every tenant hosted on the same Shipit instance.

### Likelihood Explanation
Requires: (1) Shipit configured with the "multiple GitHub Applications" scheme (distinct per-org `webhook_secret`s), (2) attacker controls/owns an org that is itself legitimately onboarded to that Shipit instance (so they know a valid `webhook_secret`), (3) the target victim repository has `review_stacks_enabled` and `provisioning_behavior_allow_with_label` configured with a known label name, and (4) attacker can author a PR with that label from their own fork. Given these preconditions (which the question stipulates as given), the attack cost is a single crafted HTTP POST with a valid HMAC computed from a secret the attacker legitimately possesses — no guessing or brute force needed, fully repeatable and scriptable.

### Recommendation
In `WebhooksController`, after determining the verified organization, cross-check it against the organization embedded in `repository.full_name` (or any other repository/org identifier used downstream) and reject (422) on mismatch. Alternatively, have `LabeledHandler`/`ReviewStackAdapter` (and sibling handlers `ReopenedHandler`, `UnlabeledHandler`, `OpenedHandler`) resolve the target `Repository` using the same `repository_owner` value that was used for signature verification, rather than independently trusting `params.repository.full_name`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test, multi-org secrets)
test "signature verified against attacker org must not authorize stack creation for a different repository's full_name" do
  # Setup: two orgs configured with distinct webhook secrets (secrets_double_github_app.yml style)
  Shipit.stubs(:secrets).returns(multi_org_secrets_with_known_webhook_secrets)

  victim_repo = shipit_repositories(:victim) # owner: "victim-org", name: "victim-repo"
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_with_label,
                       provisioning_label_name: "deploy-pr")

  payload = payload_parsed(:pull_request_labeled)
  payload["repository"]["owner"]["login"] = "attacker-org"      # used for verify_signature
  payload["repository"]["full_name"] = "victim-org/victim-repo" # used for Repository lookup
  payload["pull_request"]["labels"] = [{ "name" => "deploy-pr" }]
  body = payload.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_org_webhook_secret, body)

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  assert_difference -> { victim_repo.review_stacks.count }, 1 do
    post :create, body:, as: :json
  end
  assert_response :ok
  # Assert: org that verified signature ("attacker-org") != org owning the created stack's repository ("victim-org")
end
```
This asserts the binding equality (`verifying_org == owning_org`) fails while the exploit succeeds, i.e. `ReviewStack.create!` runs for `victim-org` despite `attacker-org`'s secret having verified the request.