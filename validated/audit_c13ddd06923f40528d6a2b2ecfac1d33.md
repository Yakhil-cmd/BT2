### Title
Webhook signature verification keys off `repository.owner.login` while all event handlers act on `repository.full_name` from the same unverified payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-org Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, a field read directly out of the attacker-supplied, not-yet-verified JSON body [1](#0-0) . The actual repository that every event handler subsequently acts on is derived independently from a *different* field of the same unverified payload, `repository.full_name` [2](#0-1) . Because the signature only proves "this request was signed with Org A's secret," not "this request concerns Org A's repositories," an attacker who legitimately controls a GitHub App/organization configured in Shipit (Org A) can forge a webhook whose `repository.owner.login` is `OrgA` (so it passes signature verification with a secret they know) but whose `repository.full_name` is `OrgB/some-repo`, causing Shipit to act on Org B's stack using Org A's credentials.

### Finding Description
`Shipit.github` supports per-organization configuration, each with its own `webhook_secret`, keyed by GitHub org name [3](#0-2) . The webhook controller picks which app/secret to verify against solely from `repository_owner`:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

and

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
``` [1](#0-0) 

Once the signature check passes, `create` dispatches the *entire raw JSON body* to handlers based only on the `X-Github-Event` header [5](#0-4) . Every handler independently re-derives the target repository from `payload.dig('repository', 'full_name')`:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

and resolves it via `Repository.from_github_repo_name`, which splits on `/` and looks up any owner/name pair in the database, with no relation back to `repository_owner` used during signature verification [7](#0-6) . `PushHandler`, the PR handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`, etc.) all use this same repository resolution before mutating stack/review-stack state [8](#0-7) [9](#0-8) .

The binding that should hold is: **`organization whose secret authenticated the request` == `organization whose repository is mutated`**. The engine breaks this equality: the signature only authenticates `repository.owner.login`, while the mutation is scoped by `repository.full_name`, an entirely separate, unauthenticated field in the same JSON body that is never cross-checked against `repository.owner.login`.

### Impact Explanation
Any GitHub organization/App configured in a shared multi-org Shipit instance can forge a webhook that is validly signed with its own secret but which claims to be about a repository owned by a *different* configured organization, causing Shipit to synchronize commits (`GithubSyncJob`), archive/unarchive review stacks, or otherwise mutate deploy state for a repository/stack it does not own or have GitHub access to. This is a cross-repository/cross-organization state manipulation ("cross-repository writes" style impact) achieved purely by controlling the JSON body of an inbound webhook, without ever needing Org B's `webhook_secret`, its `GITHUB_TOKEN`, or repository write access to Org B's actual GitHub repo.

### Likelihood Explanation
This requires: (1) a Shipit deployment configured with multiple GitHub organizations sharing one instance (the documented `secrets.yml` multi-org format), and (2) the attacker controlling one of the configured organizations/apps (a realistic scenario for a shared internal deploy tool used by multiple teams/orgs). Given those preconditions, exploitation only requires sending one crafted, self-signed HTTP POST to the public `/webhooks` endpoint — no session, no other organization's secret, and no repository access to the target org's GitHub repo are needed.

### Recommendation
After signature verification succeeds for `repository_owner`, re-validate that the same value equals the owner segment of `repository.full_name` (and of `organization.login`, if present) before dispatching to any handler; reject the request (422) on mismatch. Alternatively, pass the verified `repository_owner` into `Handler#stacks`/`Repository.from_github_repo_name` and scope repository lookups strictly to that organization.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with a distinct `webhook_secret`, both hosting stacks tracked by the same Shipit instance (per `docs/setup.md` multi-org config).
2. As an operator/attacker who controls `OrgA`'s GitHub App webhook secret, craft a `push` event payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
3. Sign the raw body with `OrgA`'s `webhook_secret` and set `X-Hub-Signature` accordingly, `X-Github-Event: push`.
4. POST to `/webhooks`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and successfully verifies the signature [1](#0-0) .
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/target-repo")` [2](#0-1)  and enqueues `stack.sync_github(expected_head_sha: params.after)` for `OrgB`'s stack [8](#0-7) , despite the request never being signed with `OrgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
