Confirmed: `verify_signature` in `WebhooksController` derives `repository_owner` from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and uses that value alone to select which org's `webhook_secret` verifies the HMAC.### Title
Webhook signature is verified against `repository.owner.login` while provisioning/repository resolution uses the independent `repository.full_name` field, letting an attacker forge a cross-org signature - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which organization's `webhook_secret` validates the HMAC using `repository_owner`, computed solely from `params.dig('repository', 'owner', 'login')`. `OpenedHandler#repository` (and all sibling PR handlers) instead resolves the `Shipit::Repository` from the independent `params.repository.full_name` field via `Repository.from_github_repo_name`. Because both fields are fully attacker-controlled JSON in the same POST body and nothing enforces they agree, an attacker who owns an org (and therefore its `webhook_secret`) can sign a payload with `repository.owner.login = "OrgA"` while setting `repository.full_name = "OrgB/protected-repo"`, causing the request to be authenticated against OrgA's secret but processed against OrgB's `Repository`/provisioning policy.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`organization_that_signed_the_bytes (derived from params.repository.owner.login in verify_signature)` == `organization_owning_the_Repository_whose_policy_is_applied (derived from params.repository.full_name in OpenedHandler#repository)`.

Code path:
- `verify_signature` at [1](#0-0)  calls `Shipit.github(organization: repository_owner)` and verifies the raw POST body against that org's `webhook_secret`.
- `repository_owner` is read straight from the JSON body: [2](#0-1) .
- `OpenedHandler#repository` resolves the acting `Repository` from a *different* JSON field, `params.repository.full_name`: [3](#0-2) .
- `provision?` then evaluates entirely against that resolved (target) repository's own provisioning configuration, not the org that supplied a valid signature: [4](#0-3) .
- If `provision?` is true, `ReviewStackAdapter#find_or_create!`/`create!` provisions a real `ReviewStack` and stores attacker-controlled PR data (`title`, `head.sha`, etc.) via `build_pull_request.update!(github_pull_request: params.pull_request)`: [5](#0-4) .

`Repository.from_github_repo_name` does a plain `owner/name` lookup with no cross-check against the payload's top-level `repository.owner.login` used for signature verification: [6](#0-5) . `ExplicitParameters` schema for `OpenedHandler` only requires `repository.full_name`, it never requires or validates `repository.owner.login`, so nothing downstream re-derives or cross-checks the owner used for authentication: [7](#0-6) .

Exploit flow: attacker owns `OrgA` (and thus its `webhook_secret`). They send `POST /webhooks` with header `X-Github-Event: pull_request`, a body where `repository.owner.login = "OrgA"`, `repository.full_name = "OrgB/protected-repo"`, `pull_request.labels = []`, and `X-Hub-Signature` = HMAC-SHA1 of the raw body using OrgA's secret. `verify_signature` looks up `Shipit.github(organization: "OrgA")`, verifies successfully (attacker knows this secret), and the request proceeds. `OpenedHandler#repository` then resolves `OrgB/protected-repo`'s `Repository` record and evaluates `provision?` against OrgB's `provisioning_behavior_allow_all?`, which is true, so a `ReviewStack` is created for OrgB regardless of OrgA's own policy or the missing label.

None of the existing guards prevent this: `verify_signature` never checks that the signing org matches the org embedded in `full_name`; `drop_unhandled_event` only checks the event is handled; the `ExplicitParameters` schema validates presence/types but not cross-field consistency; and `Repository.from_github_repo_name`/model validations only validate the target repo's own `owner`/`name` format, not its relationship to the request's authentication.

### Impact Explanation
This is a genuine cross-tenant authentication/authorization bypass: a payload whose bytes are only proven to originate from OrgA's webhook integration is used to mutate OrgB's `Repository`-scoped state — provisioning a `ReviewStack` (and the downstream deploy infrastructure it triggers via `ReviewStackProvisioningQueue`) under OrgB, using attacker-supplied PR metadata (`title`, `head.sha`, branch). This matches "a payload for one repository mutating another's stack" / "an unauthorized deploy" in the Critical impact category. It is repeatable against any target repo whose owner has `provisioning_behavior_allow_all?` (or whose label policy the attacker can otherwise satisfy) as long as the attacker controls any org configured with its own `webhook_secret` in this multi-org Shipit deployment.

### Likelihood Explanation
Requires a multi-org Shipit deployment (distinct `webhook_secret` per org, as shown in `secrets.development.example.yml`'s multi-org schema) where the attacker legitimately owns at least one configured org (e.g. as a customer/tenant of a shared Shipit instance) and the target org/repo has `review_stacks_enabled` and a permissive `provisioning_behavior`. Given those preconditions, exploitation cost is a single crafted HTTP POST with a valid HMAC computed from a secret the attacker legitimately possesses — no other secrets, sessions, or privileges are needed, and it is trivially repeatable.

### Recommendation
In `WebhooksController#verify_signature`/`create`, derive the organization used both for signature verification and for resolving the target repository from the *same* trusted source, and reject the request if `repository.owner.login` does not match the owner segment of `repository.full_name`. Alternatively, have handlers resolve the `Repository` via the owner that was actually used to verify the signature (not an independently attacker-supplied field), e.g. pass the verified `repository_owner` into `Shipit::Webhooks.for_event` handlers and assert it equals `Repository#owner` before applying any provisioning policy.

### Proof of Concept
Minitest plan (controller-level, no live GitHub):
```ruby
test "cross-org signature does not authorize provisioning against a different org's repo" do
  # Arrange: two repos under different orgs with different provisioning policies and secrets
  org_a_secret = "org-a-secret"
  org_b_repo = Shipit::Repository.create!(
    owner: "orgb", name: "protected-repo",
    review_stacks_enabled: true, provisioning_behavior: :allow_all
  )
  # stub Shipit.github(organization: "OrgA") to a GitHubApp using org_a_secret
  # stub Shipit.github(organization: "OrgB") to a GitHubApp using a different secret

  payload = {
    action: "opened",
    number: 99,
    pull_request: {
      id: 1, number: 99, url: "u", title: "attacker pr", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "deadbeef", ref: "attacker-branch" },
      user: { login: "attacker" }, assignees: [], labels: [] # no label
    },
    repository: { full_name: "orgb/protected-repo", owner: { login: "orga" } }, # mismatched owner
    sender: { login: "attacker" }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_secret, payload)

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  assert_difference -> { org_b_repo.review_stacks.count }, 1 do
    post :create, body: payload, as: :json
  end
  assert_response :ok
  # Assert binding failure: signature verified under OrgA, but ReviewStack created under OrgB
end
```
Assertions on both sides of the equality: (1) `Shipit.github(organization: "orga")` is the app whose `verify_webhook_signature` returned true (organization that authenticated the bytes = OrgA); (2) `Shipit::ReviewStack.where(repository: org_b_repo)` gained a row (organization whose policy/state was mutated = OrgB) despite `pull_request.labels` being empty and OrgA never having consented.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
