Confirmed: `Repository.from_github_repo_name` performs a pure owner/name lookup with no cross-check against the org used to verify the signature. [1](#0-0) 

### Title
Webhook signature org selection is decoupled from the mutated repository, allowing cross-tenant review-stack forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `params.dig('repository','owner','login')`, but every `Handler` (e.g. `OpenedHandler`) resolves and mutates the target repository using the independent, attacker-controlled `params.dig('repository','full_name')` field. In a multi-org Shipit deployment (an officially documented and supported configuration), an attacker who legitimately administers one onboarded GitHub org can forge a `pull_request` payload whose `repository.owner.login` is their own org (so the signature validates against a secret they know) while `repository.full_name` names a victim org's repository, causing a `ReviewStack`/`PullRequest` to be created/mutated on the victim's repository with fabricated `head.sha`/`ref` data.

### Finding Description
The intended binding is: `verified_org (secret used to compute HMAC) == owner_of_repository_that_gets_mutated`. In code this equality is never enforced.

- `WebhooksController#verify_signature` computes `repository_owner` from the payload and fetches `github_app = Shipit.github(organization: repository_owner)`, then validates the raw POST body's `X-Hub-Signature` against that org's `webhook_secret`: [2](#0-1) [3](#0-2) 
- `Shipit.github(organization:)` looks up a distinct `GitHubApp` (and distinct `webhook_secret`) per organization key, as documented for multi-org setups: [4](#0-3) [5](#0-4) 
- Once signature validation passes (using the attacker's own org's secret), `WebhooksController#create` dispatches the **entire raw JSON payload** — including the `repository.full_name` field — to handlers, with no re-derivation from `repository_owner`: [6](#0-5) 
- `Handler#repository_name`/every PR handler's `repository` method resolves the target `Repository` purely from `payload.dig('repository','full_name')` / `params.repository.full_name`, independent of `repository_owner`: [7](#0-6) [8](#0-7) 
- `Repository.from_github_repo_name` does a bare owner/name lookup with zero cross-check against the org that validated the signature: [1](#0-0) 
- `OpenedHandler#process` then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, which creates a `Stack`/`PullRequest` keyed on `params.pull_request.head.sha`/`ref` scoped to whatever repository was resolved from `full_name`: [9](#0-8) [10](#0-9) [11](#0-10) 

**Attacker's exact request:** an attacker who administers `attacker-org` (a GitHub org legitimately onboarded to this Shipit instance, thus they know the `webhook_secret` they themselves configured for their org's webhook) sends `POST /webhooks` with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "opened",
  "number": 999,
  "pull_request": {
    "id": 1, "number": 999, "url": "...", "title": "x", "state": "open",
    "additions": 0, "deletions": 0,
    "head": { "sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "ref": "fabricated-branch" },
    "user": { "login": "attacker" }, "assignees": [], "labels": []
  },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
signed with HMAC-SHA1 using `attacker-org`'s known `webhook_secret`.

**Why this passes:** `verify_signature` only checks that the signature matches *some* org's secret that the attacker happens to control (`attacker-org`); it never confirms that `repository.full_name`'s owner (`victim-org`) equals `repository_owner` (`attacker-org`). The `ExplicitParameters` schema in `OpenedHandler` only requires the presence/type of `repository.full_name`, not that it matches the verifying org: [12](#0-11) . No model validation on `Repository`, `Stack`, or `ReviewStack` re-derives or checks the owning org against the webhook's verified identity: [13](#0-12) .

### Impact Explanation
If `victim-org/victim-repo` has `review_stacks_enabled` and `provisioning_behavior_allow_all?`, the attacker's forged payload causes Shipit to persist a `ReviewStack` (`Stack`) and `PullRequest` row scoped to `victim-org/victim-repo` with a completely fabricated head SHA/ref, and enqueue it into `ReviewStackProvisioningQueue`, from which `GithubSyncJob`/provisioning logic will subsequently attempt to fetch and build against a non-existent commit on the victim's real repository — this is "a payload for one repository mutating another's stack," matching the Critical severity bucket. The attack is repeatable against any onboarded repository whose owner login the attacker can guess/know (repository names are typically public), and the blast radius spans all tenants configured under the multi-org `github:` section documented in `docs/setup.md`.

### Likelihood Explanation
This requires: (1) the Shipit instance to be configured in multi-org mode (each org has its own `webhook_secret`), which is an officially supported/documented configuration; (2) the attacker to legitimately administer at least one onboarded GitHub org (and thus knows their own webhook secret, which they configured); (3) the victim repository to have `review_stacks_enabled` and `provisioning_behavior_allow_all?`. No GitHub permission on the victim repo, no Shipit session, and no knowledge of the victim's secret is required — only knowledge of the attacker's own org secret and the victim's public `owner/repo` name. The cost is a single crafted HTTP POST, fully repeatable.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#initialize`/`repository_name`), enforce that the organization used to validate the signature equals the owner segment of `payload.dig('repository','full_name')` (and/or `organization.login`), rejecting the request (422) on mismatch before dispatching to handlers.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or a new test, no live GitHub calls, following existing patterns using `secrets_double_github_app.yml`/`Shipit.github(organization:)` stubbing as in `test/unit/shipit_test.rb`):

1. Configure two orgs, `OrgOne` (attacker) and `OrgTwo` (victim), each with a distinct `webhook_secret`, using the multi-org secrets fixture pattern shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Create `Repository.create!(owner: "orgtwo", name: "victim-repo", review_stacks_enabled: true, provisioning_behavior: "allow_all")`.
3. Build a `pull_request` "opened" JSON payload where `repository.owner.login == "OrgOne"` but `repository.full_name == "orgtwo/victim-repo"`, with a fabricated `pull_request.head.sha`/`ref`.
4. Sign the raw body with `OrgOne`'s `webhook_secret` (`OpenSSL::HMAC.hexdigest('sha1', orgone_secret, body)`), set `X-Hub-Signature`, `X-Github-Event: pull_request`.
5. Assert equality before: `repository_owner (payload) == "OrgOne"` while `full_name.split('/').first == "orgtwo"` — these differ, so the binding is already broken pre-request.
6. POST to `/webhooks` and assert `response.status == 200` (i.e., signature verification succeeded despite org mismatch) and `assert_difference -> { Shipit::Stack.where(repository: Repository.find_by(owner: "orgtwo")).count }, 1 do ... end`, proving a stack was written for `orgtwo/victim-repo` off the strength of `OrgOne`'s secret alone.
7. If a fix is applied (owner==full_name-owner check), assert the same request now returns `422` and produces `assert_no_difference` on the victim's stack count.

### Citations

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
