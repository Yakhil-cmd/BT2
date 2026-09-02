### Title
Webhook signature verified against `repository.owner.login` is not bound to `repository.full_name` used for record lookup, enabling cross-tenant `Repository`/`ReviewStack` mutation - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')`. `OpenedHandler#repository` (and the sibling `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`) instead resolves the target `Shipit::Repository` using the independent field `params.repository.full_name`. Nothing ties these two fields together, so on a multi-org Shipit deployment a request that authenticates as organization A can write to a `Repository`/`ReviewStack` belonging to organization B.

### Finding Description
The binding that must hold is: **the organization whose `webhook_secret` verified the HMAC == the organization owning the repository identified by `full_name`** — i.e. `repository_owner == full_name.split('/').first`. This is never checked.

- `WebhooksController#verify_signature` picks the GitHub App config via `Shipit.github(organization: repository_owner)` and validates the signature against that org's `webhook_secret`: [1](#0-0) . `repository_owner` is read solely from `params.dig('repository','owner','login')`: [2](#0-1) .
- In multi-org configuration, each org key in `secrets.github` has its own independent `webhook_secret`, resolved by `github_app_config`/`github`: [3](#0-2) .
- `OpenedHandler#repository` resolves the target repository using a *different* field of the same payload, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`: [4](#0-3) . `from_github_repo_name` performs a plain `owner/name` split and DB lookup with no relation to the verifying org: [5](#0-4) .
- The same pattern (`params.repository.full_name` used for lookup, independent from the signature-verifying `owner.login`) exists in `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, and `LabelCapturingHandler`: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) .

Exploit flow, under a multi-org Shipit deployment (`secrets.github` keyed by org, as documented for "multiple Github applications for different Github organizations"): attacker owns org **A** with its own configured `webhook_secret` known to them (precondition given). They POST a JSON body to `/webhooks` with `X-Github-Event: pull_request`, `repository.owner.login = "A"` (so `verify_signature` selects and validates against A's secret, succeeding) but `repository.full_name = "B/target-repo"` where B is a different tenant's repository already tracked by Shipit. `OpenedHandler` never re-checks `repository.owner.login`; it looks up `Repository.from_github_repo_name("B/target-repo")` and, if B's review-stack provisioning settings allow it, calls `ReviewStackAdapter#find_or_create!`, creating a `Stack`/`PullRequest` record under B's repository — a write scoped to B triggered by a request only B never authenticated. `ExplicitParameters` only validates types/presence of `repository.full_name` and `sender.login`, not cross-field consistency with `repository.owner.login`: [10](#0-9) . `Repository` model validations only constrain owner/name character sets, not provenance: [11](#0-10) .

### Impact Explanation
A payload authenticated for one organization's GitHub App can create or mutate `Stack`, `ReviewStack`, and `PullRequest` records that belong to a completely different organization's repository — this matches the "Critical" category of "a payload for one repository mutating another's stack, commit, task or team." The attacker can repeat this against any `full_name` of any repository already registered in Shipit's shared `repositories` table, provisioning/archiving/unarchiving review stacks, or injecting attacker-controlled PR metadata (title, labels, head sha/ref) into another tenant's stack records, across the tenant boundary that Shipit's per-org `webhook_secret` design is meant to enforce.

### Likelihood Explanation
This requires the deployment to use Shipit's multi-organization GitHub App configuration (`secrets.github` keyed by org name, as documented in `docs/setup.md`), which is a supported and used pattern; single-org deployments only have one shared secret and thus no tenant boundary to violate. Given that, the only precondition is that the attacker legitimately knows the `webhook_secret` for their own org's app (stated precondition) and that the target repository (`B/target-repo`) already exists as a `Shipit::Repository` record (readily discoverable, e.g., via the public Shipit UI for that stack). No GitHub-side cooperation is needed since the attacker directly POSTs to `/webhooks`; the exploit is fully repeatable per request.

### Recommendation
In `WebhooksController#verify_signature` (or centrally in `Handler`), after resolving the verifying organization, assert that it matches the owner encoded in `repository.full_name` for every handler that reads `full_name` (i.e., require `repository_owner == full_name.split('/', 2).first`, case-insensitively) and reject (422) on mismatch, before any handler runs. Alternatively, have handlers resolve the target `Repository` scoped by the verified `repository_owner` rather than trusting the payload's `full_name` alone.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb` style), assuming multi-org secrets fixture with orgs `"org-a"` and `"org-b"`, each with a distinct `webhook_secret`, and pre-existing `Shipit::Repository` for `org-b/target-repo` with `review_stacks_enabled: true`, `provisioning_behavior: allow_all`:

```ruby
test "cross-tenant webhook: signature for org-a must not create a stack under org-b's repository" do
  repo_b = shipit_repositories(:org_b_repo) # owner: "org-b", name: "target-repo", review_stacks_enabled: true, provisioning_behavior: allow_all

  payload = JSON.parse(payload(:pull_request_opened))
  payload["repository"]["owner"]["login"] = "org-a"       # authenticates against org-a's webhook_secret
  payload["repository"]["full_name"]      = "org-b/target-repo" # targets org-b's repository
  body = payload.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_webhook_secret, body)
  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  # Equality being validated:
  #   verifying_org  = "org-a"   (from repository.owner.login, used by verify_signature)
  #   resolved_owner = "org-b"   (from repository.full_name, used by OpenedHandler#repository)
  # These MUST match for the write to be legitimate; here they diverge.

  assert_no_difference -> { repo_b.stacks.count } do
    post :create, body:, as: :json
  end
  # Currently FAILS: a stack is created under repo_b despite the request only
  # having proven knowledge of org-a's webhook_secret.
end
```

This demonstrates the divergence between the organization that authenticated the request (`repository.owner.login`) and the organization whose repository is mutated (`repository.full_name`), with no guard in `verify_signature`, `drop_unhandled_event`, `ExplicitParameters`, or `Repository`/`Stack` validations preventing it.

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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-38)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
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

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```
