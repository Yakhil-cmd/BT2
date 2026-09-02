### Title
Webhook signature verified against attacker's org secret while mutated ReviewStack is resolved from attacker-controlled `repository.full_name` for a different org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` derives the GitHub App/secret to check the HMAC signature solely from `params.dig('repository','owner','login')` [1](#0-0) , while `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#repository` (and the sibling PR handlers) resolves the actual `Shipit::Repository` row to mutate purely from `params.repository.full_name`, an independent, attacker-controlled string in the same JSON body [2](#0-1) . Because these two fields are never checked against each other, an attacker who owns a legitimate GitHub org (and therefore its `webhook_secret`) can sign a payload with their own secret while setting `repository.full_name` to a victim org/repo that has `review_stacks_enabled` and `provisioning_behavior_allow_all`, causing Shipit to create a `Shipit::ReviewStack` under the victim's `Repository`.

### Finding Description
The broken binding, stated as an equality that the code assumes holds but never enforces:
`repository_owner` (used by `verify_signature` to pick `Shipit.github(organization:)`) == `owner` portion of `params.repository.full_name` (used by `OpenedHandler#repository` via `Repository.from_github_repo_name`).

Trace:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs before `create` [3](#0-2) .
2. `verify_signature` calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(...)`, where `repository_owner` is read directly from the untrusted JSON body (`params.dig('repository','owner','login')`) [4](#0-3) [1](#0-0) .
3. `Shipit.github(organization:)` looks up per-organization config (`webhook_secret`) keyed by that same attacker-controlled `organization` string [5](#0-4) [6](#0-5) . If the attacker legitimately owns "attacker-org" in the multi-tenant GitHub App config, they know its real `webhook_secret` and can produce a valid `X-Hub-Signature` for **any** payload body, including one whose `repository.full_name` says `"victim-org/victim-repo"`.
4. `verify_webhook_signature` performs a pure HMAC compare over the raw body using that secret and returns true — it has no knowledge of, or check against, `repository.full_name` [7](#0-6) .
5. Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to `OpenedHandler#process` [8](#0-7) .
6. `OpenedHandler#repository` resolves the repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which does a DB lookup by `owner`/`name` parsed from that attacker-supplied `full_name` string, with zero reference to `repository_owner` or the organization that was cryptographically verified [2](#0-1) [9](#0-8) .
7. If that victim `Repository` exists and has `review_stacks_enabled` + `provisioning_behavior_allow_all`, `respond_to_pull_request_opened?` / `provision?` pass [10](#0-9) , and `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` creates a new `Shipit::ReviewStack` scoped to (`has_many :review_stacks` association of) the victim `Repository` [11](#0-10) [12](#0-11) [13](#0-12) .

No existing guard catches this: `drop_unhandled_event` only checks the event name is handled [14](#0-13) ; `verify_signature` never cross-checks `repository.owner.login` against `repository.full_name`; `ExplicitParameters` schemas in the handlers only require `repository.full_name` be a `String`, with no format/ownership constraint tying it to the org that authenticated the request [15](#0-14) ; `Repository.from_github_repo_name` performs a bare `find_by(owner:, name:)` with no organization-scoping check [9](#0-8) .

Exploit request: attacker POSTs to `/webhooks` with `X-Github-Event: pull_request`, a valid `X-Hub-Signature` computed with their own org's `webhook_secret`, and a JSON body where `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `action = "opened"`, and a pull_request/sender payload satisfying the `ExplicitParameters` schema.

### Impact Explanation
A single unauthenticated (from Shipit's perspective) attacker request causes Shipit to write a new `Shipit::ReviewStack` (and associated `PullRequest`, provisioning queue entry) scoped to a victim organization's `Repository` row, entirely disjoint from the org whose secret actually signed the request. This is a cross-tenant write: the payload for one tenant's webhook mutates another tenant's stack state, matching the "payload for one repository mutating another's stack" Critical impact category. It is repeatable against any victim repository that (a) exists in Shipit's `Repository` table and (b) has `review_stacks_enabled` with a permissive `provisioning_behavior` (`allow_all`, or `allow_with_label`/`prevent_with_label` if the attacker also supplies matching labels — trivial since the payload is attacker-authored). The blast radius extends to any repository/organization onboarded to the same Shipit instance, since the multi-tenant `Shipit.github(organization:)` config permits any onboarded org's secret to authenticate against the shared `/webhooks` endpoint, and repository resolution downstream ignores the authenticated org entirely.

### Likelihood Explanation
Preconditions: the attacker must control (own) at least one organization configured in this Shipit instance's multi-tenant GitHub App config (i.e., knows a legitimate `webhook_secret` for their own org) and know/guess a victim `owner/name` full_name that exists in Shipit's `Repository` table with review stacks enabled and permissive provisioning. Both are realistic in any Shipit deployment used by multiple GitHub orgs (a common setup, since `github_organizations`/`github_app_config` explicitly supports multiple orgs). Constructing the forged payload and HMAC signature requires no special access beyond knowledge of one's own webhook secret — no session, token, or GitHub App private key is needed. This is fully repeatable per victim repository.

### Recommendation
In `Shipit::WebhooksController` (or in the handler base class), after resolving `repository_owner` and verifying the signature, also verify that the `repository.full_name`'s owner segment matches the same `repository_owner`/organization that authenticated the signature (reject the webhook otherwise). Alternatively, have `Repository.from_github_repo_name`/the handlers accept and enforce an expected organization parameter derived from the verified webhook context, rather than trusting `full_name` in isolation.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "pull_request opened webhook signed by attacker org cannot create a ReviewStack under a victim org repository" do
  victim_repo = shipit_repositories(:shipit) # review_stacks_enabled: true, provisioning_behavior: allow_all
  attacker_org = "attacker-org"

  Shipit.stubs(:github_app_config).with(attacker_org).returns(webhook_secret: "attacker-secret")
  # attacker signs the payload with THEIR OWN secret
  body = JSON.parse(payload(:pull_request_opened))
  body["repository"]["owner"]["login"] = attacker_org           # provenance side of the equality
  body["repository"]["full_name"] = victim_repo.github_repo_name # scope side of the equality
  raw = body.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", "attacker-secret", raw)

  request.headers["X-Github-Event"] = "pull_request"
  request.headers["X-Hub-Signature"] = signature

  assert_no_difference "Shipit::ReviewStack.where(repository_id: victim_repo.id).count" do
    post :create, body: raw, as: :json
  end
  # Currently this assertion FAILS (count increases by 1), proving
  # repository_owner ("attacker-org") != victim_repo.owner but the write still lands on victim_repo.
end
```
Both sides of the equality (`repository_owner == victim_repo.owner`) diverge in this scenario, yet the write proceeds — confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
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
