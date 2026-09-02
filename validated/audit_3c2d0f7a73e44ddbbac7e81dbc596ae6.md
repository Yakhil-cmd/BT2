Confirmed. This is enough to write up the finding.

### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but event handlers act on the repository derived from `repository.full_name` - allowing cross-organization/cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to check the HMAC signature using `params.dig('repository', 'owner', 'login')` (or `organization.login`), while every webhook handler that actually mutates state resolves the target `Repository`/`Stack` using an entirely different payload field: `repository.full_name`, via `Handler#repository_name`/`Handler#stacks` and the equivalent `Repository.from_github_repo_name(params.repository.full_name)` calls used across the pull-request handlers and `PushHandler`. Nothing ties these two fields together, so a payload can be crafted where the signature-selecting owner and the repository actually processed diverge.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is read from [2](#0-1) :
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`Shipit.github(organization:)` looks up a per-organization config/secret (`github_app_config`) in a multi-tenant deployment, as seen in [3](#0-2) . The HMAC is verified with the secret belonging to whatever organization is named in `repository.owner.login`.

However, once the signature check passes, `create` dispatches the *entire raw JSON payload* to handlers: [4](#0-3) . Every handler resolves the target repository/stack from a **different** field, `repository.full_name`, not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

`PushHandler`, which triggers `stack.sync_github`, uses this same `stacks` helper: [6](#0-5) . The pull-request handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, `LabelCapturingHandler`, etc.) independently call `Shipit::Repository.from_github_repo_name(params.repository.full_name)` to resolve the repository that gets archived/unarchived/merged, e.g. [7](#0-6) . `Repository.from_github_repo_name` splits `owner/name` straight out of that field with no cross-check against `repository.owner.login`: [8](#0-7) .

Binding broken: `organization authenticated (repository.owner.login → webhook_secret selection)` ≠ `repository written (repository.full_name → Repository/Stack resolved and mutated)`.

### Impact Explanation
On a multi-organization Shipit deployment (`secrets.github` keyed by multiple orgs, each with its own `webhook_secret`), a tenant who legitimately administers Org A's GitHub organization/repos (and therefore possesses Org A's `webhook_secret`, which they configured themselves and are entitled to know for their own org) can forge a signed webhook whose `repository.owner.login`/`organization.login` says `"OrgA"` (so the signature check passes against Org A's secret) but whose `repository.full_name` says `"OrgB/some-repo"`. Handlers will then resolve and mutate Org B's `Stack`/`Repository`/`PullRequest` records — triggering `GithubSyncJob`, archiving/unarchiving review stacks, or manipulating merge-queue state for a repository the attacker does not own and never proved control of via signature. This is a cross-tenant, cross-repository write achieved purely by controlling the payload body while satisfying signature verification for an unrelated organization.

### Likelihood Explanation
Requires only that the Shipit instance is configured with multiple GitHub organizations (a documented, supported configuration — `Shipit.github_organizations`), and that the attacker has legitimate control over one onboarded organization (their own `webhook_secret`, which they configure and know as a tenant admin, not a leaked secret). No repository write access to the victim repo, no session, and no other privileged credential of the victim org is needed — only crafting the JSON body's `repository.full_name` field independently of `repository.owner.login`.

### Recommendation
Bind signature verification and repository resolution to the same authenticated identity: verify the HMAC using the organization/owner derived from the *same* field the handlers use to resolve the repository (`repository.full_name`'s owner segment), or explicitly assert `repository.owner.login == repository.full_name.split('/').first` before dispatching to handlers. Reject the webhook if the two disagree.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `OrgA` (attacker-administered, webhook secret known to attacker) and `OrgB` (victim, has a stack tracking `OrgB/victim-repo`).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)`.
4. POST to `/github/webhooks`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully against the attacker's own known secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")`, matching `OrgB`'s stack, and calls `stack.sync_github(expected_head_sha: params.after)` — mutating Org B's stack state despite the signature only proving control of Org A.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
