### Title
Webhook signature verification keys on `repository.owner.login` while every handler acts on the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to validate the `X-Hub-Signature` HMAC solely from `repository.owner.login` (or `organization.login`) inside the attacker-supplied JSON body, but every event handler (`PushHandler`, the `PullRequest::*` handlers, etc.) resolves the target `Repository`/`Stack` from the sibling field `repository.full_name`. Nothing binds these two fields together, so a signature that is valid for organization A's webhook secret can be replayed with a `full_name` pointing at a repository belonging to organization B tracked by the same Shipit instance.

### Finding Description
`repository_owner` is computed purely from the JSON payload the client controls: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This `repository_owner` is used only to pick which per-organization `webhook_secret` (`Shipit.github(organization:)` / `GitHubApp#verify_webhook_signature`, see [3](#0-2)  and [4](#0-3) ) is used to compute the HMAC — it is never checked against the value the handlers actually act on.

Every handler instead resolves which `Repository`/`Stack` to mutate from `repository.full_name`, with no re-validation that `full_name`'s owner segment matches the `repository.owner.login` used for signature selection: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

Because Shipit explicitly supports one `webhook_secret` per GitHub organization (multi-org config, `github_app_config`), each organization owner is trusted only for its own repositories: [9](#0-8) [10](#0-9) 

The security invariant the code is supposed to enforce is: `organization whose webhook_secret produced a valid signature == organization that owns the repository being written to`. The implementation instead checks `verify(secret_of(payload.repository.owner.login)) == true` and then acts on `payload.repository.full_name`, an entirely separate, unauthenticated field. An organization admin who legitimately controls (and can configure/receive real webhooks for) Org A can therefore forge a raw JSON body where `repository.owner.login = "OrgA"` (so the correct `webhook_secret` is selected and the HMAC validates) but `repository.full_name = "OrgB/some-repo"`, letting them drive `PushHandler`, `PullRequest::OpenedHandler`, `MembershipHandler`, etc. against a stack/repository belonging to Org B, a different trust domain hosted by the same Shipit instance.

### Impact Explanation
This breaks the organization‑authenticated vs. repository‑written binding across trust boundaries hosted by a single Shipit instance. Concretely reachable handlers act by looking up `Stack`s via `Repository.from_github_repo_name(full_name)` and then perform state-changing operations: `PushHandler` triggers `stack.sync_github(expected_head_sha:)` which schedules a `GithubSyncJob` (fetches and syncs commits, can advance the deploy queue), `PullRequest::OpenedHandler`/`ReopenedHandler`/`UnlabeledHandler` create, unarchive, or archive review stacks, and `MembershipHandler`/`CheckSuiteHandler` mutate team/check-run data — all against a repository the forging organization does not own. This crosses a cross-repository/cross-organization write boundary using credentials (a webhook secret) that are only supposed to authorize actions for one org.

### Likelihood Explanation
Requires (a) Shipit configured with the documented multi-organization GitHub App scheme, and (b) the attacker being a legitimate maintainer/admin of at least one onboarded GitHub organization (so they know or can derive that organization's `webhook_secret`, e.g. by inspecting their own App/webhook config) — not a fully anonymous internet attacker of the whole instance, but an attacker with no privilege on the *victim* organization or repository, which satisfies the "unprivileged attacker" bar for the target org. Likelihood is Medium: it requires an operator to run multi-org mode and an attacker who controls one tenant org among several sharing the instance.

### Recommendation
After verifying the HMAC using the secret for `repository_owner`, additionally assert that every field the handlers subsequently trust (`repository.full_name`, `organization.login` used elsewhere) is consistent with the verified `repository_owner`/organization — e.g. reject the webhook if `full_name.split('/').first.casecmp(repository_owner) != 0`. More robustly, handlers should receive the already-authenticated organization from the controller and use it (not payload-supplied fields) to scope the `Repository`/`Stack` lookup.

### Proof of Concept
1. Shipit is deployed with two configured GitHub orgs, `OrgA` and `OrgB`, each with its own `github.<org>.webhook_secret` (per `config/secrets.development.shopify.yml`), and both have repositories/stacks tracked by this Shipit instance.
2. Attacker is a legitimate admin of `OrgA`'s GitHub App installation and therefore knows `OrgA`'s `webhook_secret` (e.g., set it themselves when installing the app).
3. Attacker crafts a raw JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` reads `repository_owner = "OrgA"`, loads `Shipit.github(organization: "OrgA")`, and `verify_webhook_signature` succeeds because the signature genuinely matches `OrgA`'s secret over this raw body.
6. `Shipit::Webhooks::Handlers::PushHandler#process` is invoked with the full parsed payload; it resolves `stacks` via `repository_name = payload.dig('repository','full_name') = "OrgB/victim-repo"`, and calls `stack.sync_github(expected_head_sha: params.after)` on `OrgB`'s stack — a stack the attacker has no authorization over — using a signature only valid for `OrgA`.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
