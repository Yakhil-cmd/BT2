### Title
Signature verification org derived from `repository.owner.login` diverges from the write-target org derived from `repository.full_name`, allowing a no-secret org to authorize archiving a different org's ReviewStack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` used to validate `X-Hub-Signature` via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from `params.dig('repository','owner','login')`. `LabeledHandler#repository` independently resolves the repository to mutate via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. These two JSON fields are never cross-checked, and both are fully attacker-controlled in the raw POST body, so an attacker can pick an org for signature verification that has no `webhook_secret` while pointing the actual write at a different, securely-configured org's repository.

### Finding Description
The broken binding, stated as an equality that the code silently assumes but never enforces:

`organization_used_for_signature_check (params.repository.owner.login) == organization_that_owns_the_mutated_repository (owner segment of params.repository.full_name)`

Trace:
- `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`: `repository_owner` is read purely from `params.dig('repository','owner','login')` (or `organization.login`). `verify_signature` does `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(header, raw_post)`.
- `lib/shipit/github_app.rb:76-83`: `verify_webhook_signature` returns `true` unconditionally, before even inspecting the header, `unless webhook_secret` (`return true unless webhook_secret`). So if the org selected via `repository_owner` has no `webhook_secret` configured, **any** body/signature (including a missing `X-Hub-Signature` header) is accepted.
- `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:65-68`: `repository` is resolved completely independently, from `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`. This value has no relationship enforced with `params.repository.owner.login` used earlier for signature selection.
- `Shipit.github(organization:)` in `lib/shipit.rb:170-181` only maps to a shared/legacy app when the whole installation uses the single-org config schema (`github_default_organization` nil). In the documented multi-org configuration (`docs/setup.md:182-209`, and exercised by `test/dummy/config/secrets_double_github_app.yml`), each org key maps to its own `GitHubApp`/`webhook_secret`, so the attacker's chosen `repository_owner` genuinely selects a distinct, real `GitHubApp` instance.

Exploit flow (multi-org Shipit deployment, which is a supported/documented configuration):
1. Attacker's request body sets `repository.owner.login = "attacker-org"` (an org configured in Shipit with no `webhook_secret`) and `repository.full_name = "victim-org/victim-repo"` (an existing, unrelated repository whose org does have a configured `webhook_secret`).
2. `X-Github-Event: pull_request` header, no `X-Hub-Signature` header at all.
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` immediately — the request passes with zero signature material.
4. `LabeledHandler` is dispatched with `action: "labeled"`. `repository` resolves via `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")` to the real victim `Repository` record [1](#0-0) .
5. If the victim repo's `review_stacks_enabled`/provisioning behavior and the attacker-chosen `pull_request.labels` make `archive?` true, `stack.archive!` executes through `ReviewStackAdapter#archive!`, which deprovisions and archives the matching victim `ReviewStack` (looked up by PR-number-derived `environment`) [2](#0-1) .

Why existing guards fail: `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema for `LabeledHandler` only requires `repository.full_name` to be a `String`, with no relationship to `repository.owner.login`; `verify_signature`'s `rescue Shipit::GithubOrganizationUnknown` only blocks completely unconfigured org names, not configured-but-secretless ones; no model validation ties `Repository#owner` back to the webhook's claimed `repository.owner.login`.

### Impact Explanation
A request that authenticates against org A's (no-secret) `GitHubApp` is used to execute a write (`stack.archive!`, i.e. deprovision + archive a `ReviewStack`) against org B's repository/stack. This is exactly the "payload for one repository mutating another's stack" Critical-impact category: an unauthenticated actor with no knowledge of org B's `webhook_secret` can deprovision/archive any review stack in the same Shipit instance whose owning org key differs from the attacker-chosen no-secret org. Repeatable per request/PR-environment against any repository present in the database; blast radius spans every tenant/org hosted on the same multi-org Shipit installation.

### Likelihood Explanation
Requires a Shipit instance configured with the documented multi-org `github:` schema, containing at least one org entry with no `webhook_secret` (misconfigured or intentionally left open) and at least one victim org with a configured secret and existing `review_stacks_enabled` repository/stack. Given that, the attacker needs no credentials at all — a bare unauthenticated HTTP POST to `/webhooks` with a hand-crafted JSON body suffices; no GitHub account, PR, or signature is required. Feasibility is high and fully repeatable.

### Recommendation
Bind signature verification and the mutated resource to the same source of truth: derive the org used for `Shipit.github(organization: ...)` from the same `repository.full_name` (or the resolved `Shipit::Repository#owner`) that handlers use to select the target repository, not from a separately attacker-controlled `repository.owner.login`/`organization.login` field. Additionally, treat a missing/blank `webhook_secret` for an org as "signing not required for that org's own repositories only" — after resolving the repository from `full_name`, assert its owner matches `repository_owner`; reject if they differ.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, extended to a multi-org fixture like `test/dummy/config/secrets_double_github_app.yml`):
```ruby
test "cross-org labeled payload cannot use a no-secret org to archive another org's stack" do
  # Arrange: multi-org secrets where OrgOne has webhook_secret: nil (no secret)
  # and OrgTwo has a configured webhook_secret; victim repo/stack belongs to OrgTwo.
  Shipit.stubs(:secrets).returns(multi_org_secrets_with_orgone_no_secret_orgtwo_secret)
  victim_repo = create_repository(owner: "OrgTwo", review_stacks_enabled: true, provisioning_behavior: :prevent_with_label)
  victim_stack = create_review_stack(repository: victim_repo, environment: "pr2")

  payload = JSON.parse(payload(:pull_request_labeled))
  payload["repository"]["owner"]["login"] = "OrgOne"          # no-secret org
  payload["repository"]["full_name"] = victim_repo.github_repo_name # OrgTwo/victim-repo
  payload["pull_request"]["labels"] = [{ "name" => victim_repo.provisioning_label_name }]

  @request.headers["X-Github-Event"] = "pull_request"
  # no X-Hub-Signature header at all

  post :create, body: payload.to_json, as: :json

  assert_response :ok
  assert victim_stack.reload.archived?,
    "unauthenticated request selecting a no-secret org verified a write against a different org's stack"
end
```
This demonstrates the equality `repository_owner (signature org) == owner(full_name) (mutated repo org)` is false yet the request is accepted (`200 OK`) and the victim `ReviewStack` is archived with no valid signature anywhere in the request.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```
