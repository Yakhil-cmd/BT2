### Title
Cross-repository ReviewStack creation via webhook `repository.owner.login`/`repository.full_name` mismatch - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects the HMAC secret to verify a webhook using `repository.owner.login` from the JSON body, while `OpenedHandler#repository` (and the base `Handler#stacks`) resolve the target repository using the unrelated `repository.full_name` field from the same body. Because nothing binds these two fields together, a tenant that legitimately controls its own configured organization's `webhook_secret` can forge a signed payload whose `owner.login` matches their own org (so the signature verifies) but whose `full_name` names a different tenant's tracked repository, causing the handler to operate on the victim's `Repository`/`Stack` data.

### Finding Description
The broken binding: `params.repository.full_name`'s owner segment `==` the organization whose `webhook_secret` verified the signature. In practice:

- `WebhooksController#verify_signature` derives the signing org from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) and looks up that org's app config via `Shipit.github(organization: repository_owner)`, then HMAC-verifies the raw body against that org's `webhook_secret`. [1](#0-0) [2](#0-1) 
- `Shipit.github` in a multi-org setup (`github_app_config`) requires an exact, operator-configured organization key with its own `app_id`/`webhook_secret`, as documented for "Using Multiple Github Applications." [3](#0-2) [4](#0-3) 
- Separately, `OpenedHandler#repository` resolves the target `Shipit::Repository` purely from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [5](#0-4) 
- The base `Handler#stacks` helper does the same independent lookup: `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')`. [6](#0-5) 

Root cause: `repository.owner.login` (secret-selection key) and `repository.full_name` (target-resolution key) are two independently attacker-supplied fields inside the same signed JSON body, and no code checks that `full_name` starts with `owner.login` (or that they refer to the same org) before trusting `full_name` to pick the mutated record.

Attacker's exact request: a POST to `/webhooks` with header `X-Github-Event: pull_request`, HMAC-signed with the `webhook_secret` of the attacker's own configured organization `attacker`, and a body such as:
```json
{
  "action": "opened",
  "number": 2,
  "repository": { "owner": { "login": "attacker" }, "full_name": "victim-org/protected-repo" },
  "pull_request": { ... },
  "sender": { "login": "attacker" }
}
```
`repository_owner` resolves to `attacker`, so `verify_signature` succeeds using the attacker's own legitimately-held secret. `OpenedHandler#repository` then resolves `victim-org/protected-repo` and, if that repository has `review_stacks_enabled` with `provisioning_behavior_allow_all` (or a matching label), `ReviewStackAdapter#find_or_create!` mutates the victim's `review_stacks`/`Stack` records. [7](#0-6) [8](#0-7) 

Existing guards do not catch this: `drop_unhandled_event` only checks event type presence; `ExplicitParameters` schema only enforces field types/presence, not cross-field consistency; `Repository.from_github_repo_name` performs a plain owner/name lookup with no ownership check against the verified signer. [9](#0-8) 

Note: this requires a multi-organization Shipit deployment where the attacker legitimately administers one of the configured tenant organizations/GitHub Apps (and thus legitimately knows their own `webhook_secret`) — this is a documented, supported configuration in this engine (`docs/setup.md`, "Using Multiple Github Applications"), not a stolen or guessed secret belonging to the victim.

### Impact Explanation
An attacker who administers any one tenant organization configured in the same multi-org Shipit instance can trigger repository/PR webhook handlers (e.g., `OpenedHandler`, and by the same flaw other `pull_request`/push/status handlers using `payload.dig('repository','full_name')`) against any other tenant's tracked repository, causing unauthorized `ReviewStack`/`Stack` creation or mutation for a repository/org they do not own. This is repeatable against any repository name known to the attacker and matches the Critical category "a payload for one repository mutating another's stack."

### Likelihood Explanation
Requires a Shipit deployment using the multi-organization GitHub App configuration (each org with its own `app_id`/`webhook_secret`), and the attacker must be an administrator of at least one such configured tenant org (able to know/keep their own app's `webhook_secret`) — a documented and supported setup. Given that, the attack costs a single crafted HTTP POST with a valid HMAC computed from the attacker's own secret; it is trivially repeatable against any victim repository name that exists in the Shipit database, as long as that repo has review stacks enabled with a permissive provisioning behavior.

### Recommendation
In `WebhooksController#verify_signature`, or in `Handler`/`OpenedHandler`, enforce that the organization/owner used to select the verifying `webhook_secret` matches the owner segment of `params.repository.full_name` (and any other repository-identifying field used downstream) before processing the payload; reject the webhook otherwise.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (multi-org secrets fixture, e.g. `test/dummy/config/secrets_double_github_app.yml`):

```ruby
test "cross-org payload does not mutate victim repository's stacks" do
  # attacker administers org 'attacker' with its own webhook_secret in the multi-org config
  victim_repo = shipit_repositories(:victim_org_protected_repo) # owner: victim-org, review_stacks_enabled: true, allow_all
  attacker_secret = Shipit.github(organization: 'attacker').webhook_secret

  body = {
    action: 'opened',
    number: 2,
    repository: { owner: { login: 'attacker' }, full_name: 'victim-org/protected-repo' },
    pull_request: { id: 1, number: 2, url: 'https://x', title: 't', state: 'open',
                     additions: 1, deletions: 0,
                     head: { sha: 'abc', ref: 'feature' },
                     user: { login: 'attacker' }, assignees: [], labels: [] },
    sender: { login: 'attacker' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_secret, body)}"
  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { victim_repo.review_stacks.count } do
    post :create, body:, as: :json
  end
end
```
Assert both sides of the binding: `repository_owner` resolved during verification (`attacker`) must not equal the owner segment of `params.repository.full_name` (`victim-org`) that the handler actually mutates — currently the code allows this divergence, so the fix should make `verify_signature` (or the handler) reject the request instead of allowing `Shipit::Stack`/`review_stacks` counts for the victim repo to change.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L21-31)
```ruby
    def provisioning_behavior_allow_all?
      false
    end

    def provisioning_behavior_allow_with_label?
      false
    end

    def provisioning_behavior_prevent_with_label?
      false
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
