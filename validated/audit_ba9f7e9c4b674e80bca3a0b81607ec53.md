### Title
Webhook signature verified against `repository.owner.login` while the mutated `PullRequest`/`Repository` row is selected by the independent `repository.full_name` field, allowing an attacker-controlled org's signature to authorize writes to a victim-org's PR — ([File: app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to validate the HMAC against using `params.dig('repository','owner','login')` (or `organization.login`), a value read straight from the untrusted, self-crafted JSON body. `AssignedHandler#repository` and `#pull_request` instead resolve the record to mutate using the separate `params.repository.full_name` field from the very same JSON body. Nothing enforces that these two independently-attacker-supplied strings refer to the same repository, so a request whose HMAC is valid for one org's configured webhook secret can still target and mutate another org's `PullRequest` row.

### Finding Description
Binding claimed to hold: `organization_verified_by_signature == owner(repository_actually_mutated)`, i.e. `params.dig('repository','owner','login')` (used in [1](#0-0)  and [2](#0-1) ) must equal the owner portion of `params.repository.full_name` used in [3](#0-2)  to resolve the `Repository` and, transitively, the `PullRequest` row updated at [4](#0-3) .

These two values are read from two different keys of the same POST body (`repository.owner.login` vs `repository.full_name`), both fully attacker-controlled, and there is no code anywhere that cross-checks them. `GitHubApp#verify_webhook_signature` only proves that the raw byte string of the POST body was HMAC-signed with the secret configured for the organization named in `repository.owner.login` (or, if that org has no `webhook_secret` configured, it trivially returns `true`, per `return true unless webhook_secret` in [5](#0-4) ). It says nothing about which repository the *content* of that body claims to describe elsewhere in the JSON.

Exploit flow: an attacker who legitimately controls (or is onboarded as a tenant of) `attacker-org` in this multi-tenant Shipit instance can compute a valid `X-Hub-Signature` for `attacker-org`'s configured secret over a JSON body of their own choosing (they need only know their own org's webhook secret, which they do since they are the account operating that GitHub App integration). They craft a `pull_request` "assigned" payload where:
- top-level `repository.owner.login = "attacker-org"` (used only for signature-org selection),
- top-level `repository.full_name = "victim-org/some-repo"` (used by the handler to find the actual `Repository`/`Stack`/`PullRequest`),
- `pull_request.number` = a known/guessed number of an existing victim `PullRequest`,
- `pull_request.assignees = [{ "login": "attacker-account" }]`.

`WebhooksController#verify_signature` computes/validates the HMAC against `attacker-org`'s secret and it matches (the attacker signed it themselves), so the request passes `head(422) unless verified` and flows to `Shipit::Webhooks.for_event('pull_request').each { |handler| handler.call(params) }` in [6](#0-5) . `AssignedHandler#process` then locates `victim-org/some-repo`'s `PullRequest` via `repository` at [7](#0-6)  and calls `pull_request.update(github_pull_request: params.pull_request)`, which invokes `PullRequest#github_pull_request=` at [8](#0-7) , setting `self.assignees = github_pull_request.assignees.map { |u| User.find_or_create_by_login!(u.login) }` — writing an attacker-controlled `User` (created on the fly if it doesn't exist) as the assignee of the victim's `PullRequest`.

Why existing guards fail: `drop_unhandled_event` only checks the event name exists; `verify_signature` only checks HMAC validity against whichever org is named in `repository.owner.login`; the `ExplicitParameters` schema in `AssignedHandler` ( [9](#0-8) ) only validates types/presence, not cross-field consistency; `Repository.from_github_repo_name` ( [10](#0-9) ) simply looks up whatever owner/name is given in `full_name` with no relation to the org that signed the request.

### Impact Explanation
This is a payload for one repository (nominally "belonging to" `attacker-org`'s signature) mutating another org's stack's `PullRequest` record — falling under "a payload for one repository mutating another's stack/commit/task/team." The attacker can set the assignee (and, via the same code path, title, state, labels, head commit reference) of any `PullRequest` in the victim's repository to an attacker-controlled identity, repeatable against any `PullRequest` number and any victim repository whose Shipit-tracked `Repository` row exists, as long as the attacker knows/controls a webhook secret for *some* org configured in the same Shipit instance (or an org with no secret configured at all, which auto-passes verification). This is a genuine repository-scope confusion: the write is not scoped to the org that was actually authenticated. If PR assignee data is later used for authorization or notification routing decisions, this becomes a stronger primitive; at minimum it's an unauthorized cross-tenant write.

### Likelihood Explanation
Preconditions: (1) the Shipit instance is multi-tenant, tracking more than one GitHub org, each potentially with distinct `webhook_secret` in config (see `config/secrets.development.shopify.yml` structure with `github: someorg: webhook_secret ...`); (2) the attacker must be able to produce a valid signature for at least one org known to Shipit — either because they are a legitimate tenant of that org (common in the described threat model of "attacker-org" vs "victim-org", each with their own onboarded Shipit configuration), or because that org's `webhook_secret` is unset in Shipit config, which causes `verify_webhook_signature` to return `true` unconditionally; (3) the victim's repository and target `PullRequest` number must exist and be discoverable (PR numbers are small sequential integers, easily guessed or observed publicly on GitHub). No GitHub secrets, session, or API token are required beyond the attacker's own signing capability. This is fully repeatable via direct HTTP POST to `/webhooks`, no live GitHub interaction needed.

### Recommendation
In `WebhooksController#verify_signature`, or in a shared handler concern, derive the "authenticated organization" the same way the handlers derive the repository to mutate, and cross-check that the owner of `params.repository.full_name` (or the `organization.login`) matches `repository_owner` used to select the verification secret. Reject the request (422) if they differ. Additionally, `AssignedHandler#repository` (and analogous handlers) should reject/ignore payloads where the top-level `repository.full_name` owner does not match the value used for signature verification, rather than trusting `full_name` in isolation.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "pull_request assigned webhook cannot mutate another org's PullRequest using a different org's signature" do
  victim_repo = shipit_repositories(:shipit) # owner e.g. "shopify"
  victim_pr = shipit_pull_requests(:review_stack_review) # belongs to victim_repo's stack

  attacker_org = "attacker-org"
  Shipit.stubs(:github).with(organization: attacker_org)
        .returns(GitHubApp.new(attacker_org, webhook_secret: "attacker-secret"))

  payload = payload_parsed(:pull_request_assigned)
  payload["repository"]["owner"] = { "login" => attacker_org }       # used only for signature org selection
  payload["repository"]["full_name"] = victim_repo.github_repo_name  # used to select the mutated record
  payload["number"] = victim_pr.number
  payload["pull_request"]["number"] = victim_pr.number
  payload["pull_request"]["assignees"] = [{ "login" => "attacker-account" }]

  raw = payload.to_json
  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', raw)}"

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = signature

  # Equality that should hold but doesn't:
  # owner_from_signature_check == owner_of_mutated_repository
  assert_no_changes -> { victim_pr.reload.assignees.map(&:login) } do
    post :create, body: raw, as: :json
  end
  # Demonstrates violation: without the fix, victim_pr.reload.assignees includes "attacker-account"
  # even though only attacker_org's secret was verified.
end
```

**Note on tool limitations:** I was unable to fully inspect `lib/shipit/shipit.rb`'s `Shipit.github(organization:)` resolution logic and the exact multi-org config validation (e.g., whether `GithubOrganizationUnknown` is raised for genuinely unconfigured orgs, and whether the deployment realistically permits `webhook_secret` to be nil for a "real" org) within this session's tool budget — this affects the exact likelihood/preconditions but not the core finding, which is that `repository.owner.login` (verification input) and `repository.full_name` (mutation-target input) are independently attacker-controlled fields with no cross-check.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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

**File:** app/models/shipit/pull_request.rb (L36-50)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
