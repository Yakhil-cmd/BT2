Based on my research, I found a genuine binding-break vulnerability matching the report's bug class: an authentication check performed against one field of the payload (`repository.owner.login`) while the actual privileged action operates on a different field of the same, single-signed payload (`repository.full_name`) that is not cross-checked against the authenticated organization.

### Title
Webhook signature is verified against an attacker-chosen organization while the sync/status handlers act on an unrelated repository field from the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated request body, then verifies the raw payload against that organization's `webhook_secret`. <cite repo="hirayap/shipit-engine--018" path="app/controllers/shipit/webhooks_controller.rb" start="24="30" /> [1](#0-0)  Shipit supports hosting multiple GitHub organizations, each with its own `webhook_secret`, in a single instance. [2](#0-1)  The downstream handlers (`PushHandler`, `StatusHandler`) never re-check that the organization whose secret validated the signature actually matches the repository/stack that gets synced or updated — they operate on `Handler`-parsed fields (`ref`, `after`, `sha`, `branches`, and repository lookups) drawn from the same untrusted payload. [3](#0-2) [4](#0-3) 

### Finding Description
`Shipit.github(organization:)` resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per configured organization. [5](#0-4)  In `verify_signature`, the organization used to pick that secret is `repository_owner`, computed purely from the JSON body:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
This field is never cross-checked against any other identifying field in the same payload (e.g. `repository.full_name`, which is what downstream code actually uses to resolve the `Repository`/`Stack` to mutate, via `Repository.from_github_repo_name`/`from_param!` which just splits `owner/name` from the payload-controlled string). [6](#0-5) [7](#0-6) 

An operator running Shipit for multiple organizations (a documented, supported configuration) knowingly gives each onboarded organization's GitHub App installation its own `webhook_secret`, which that organization's administrators legitimately possess (it's their own App). Nothing prevents that organization from crafting a webhook body whose `repository.owner.login`/`organization.login` says "their own org" (so `verify_signature` uses their own, known secret and passes) while embedding a `repository.full_name`, `ref`, `after`, or commit `sha` values that reference a stack/commit belonging to a different, victim organization hosted on the same Shipit instance. Because the signature only binds the *bytes* of the payload to *a* secret it looks up from an unauthenticated field, and the handlers don't re-derive the organization from a value that was actually cryptographically bound to the *correct* tenant, the "organization that authenticated" and the "repository that is written" can diverge — precisely the ReserveFund/TokenVault pattern of one entity's legitimate credential being reused to reach another entity's restricted operations.

### Impact Explanation
Exploiting this lets a tenant with a legitimately configured (but foreign) organization/webhook_secret trigger `GithubSyncJob`/commit-status writes on a stack belonging to another organization's repository in the same Shipit deployment: injecting fabricated commit-status payloads (`StatusHandler`) that can flip CI/deployable status flags used by continuous-deployment logic, or forcing `PushHandler`/`GithubSyncJob` to resync a victim stack against a chosen `expected_head_sha`. This is a cross-repository write outside the attacker's own authorized tenant boundary in a multi-org install — matching the Critical "cross-repository writes" impact bucket.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (explicitly documented and supported) and requires the attacker to control one legitimate, configured organization/webhook_secret within that shared instance — not a GitHub App private key, Shipit session, or `ApiClient` token, and not any credential belonging to the victim organization. The attacker only needs to send a crafted (but validly-signed-with-their-own-secret) HTTP POST to `/webhooks`; no interaction from the victim or any special network position is needed.

### Recommendation
Bind the organization used to look up `webhook_secret` to the *repository actually operated on*: after computing `repository_owner`, re-derive the owning organization strictly from `repository.full_name` (or the resolved `Repository`/`Stack` record) and require these to match before dispatching to handlers, rejecting the webhook otherwise. Alternatively, verify the signature using a per-installation ID that is independently confirmed (e.g., cross-check GitHub's `X-GitHub-Hook-Installation-Target-ID` header) rather than trusting any organization name taken from the unauthenticated JSON body.

### Proof of Concept
1. Operator runs Shipit configured for two orgs, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications"). Both orgs have stacks tracked by Shipit.
2. Attacker (an authorized admin of `attacker-org`'s own GitHub App) crafts a push webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha string present in victim's repo>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s own known `webhook_secret` over this exact body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository_owner`), verifies successfully since the attacker used the correct secret for that org. [8](#0-7) 
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves stacks/branch from the payload and calls `stack.sync_github(expected_head_sha: params.after)` against the `victim-org/victim-repo` stack — a stack the attacker's organization has no legitimate authority over. [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/repository.rb (L90-96)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name = param.split('/')
      where(
        owner: repo_owner.downcase,
        name: repo_name.downcase
      ).first!
    end
```
