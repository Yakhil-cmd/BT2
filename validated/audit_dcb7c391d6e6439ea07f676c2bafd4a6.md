### Title
Webhook signature verification is keyed by `repository.owner.login`/`organization.login` while the acted-upon repository is looked up from the separate, unverified `repository.full_name` field, allowing cross-organization webhook forgery in multi-app deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-GitHub-app deployments, `WebhooksController#verify_signature` picks *which* HMAC secret to check the payload against based on `repository_owner`, extracted from `params.dig('repository','owner','login')` (or `organization.login`) — a field that is never itself covered by the signature it is used to select. Once verification passes, every webhook `Handler` (e.g. `PushHandler`) resolves the target `Stack`/`Repository` using a *different* payload field, `repository.full_name`, without re-checking that this repository belongs to the organization whose secret validated the request.

### Finding Description
`WebhooksController#verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end
``` [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization app config and secret in `secrets.github`, keyed by the organization name derived from `repository_owner`: [3](#0-2) . Critically, `GitHubApp#verify_webhook_signature` treats an org with no configured `webhook_secret` as automatically verified: `return true unless webhook_secret` [4](#0-3) .

After `verify_signature` passes, `WebhooksController#create` dispatches to handlers using the *raw params*, not anything tied to the verified organization: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

Every handler resolves its target repository/stack from `repository.full_name`, an entirely separate payload field from `repository.owner.login`:
- `Handler#repository_name` / `#stacks`: `payload.dig('repository', 'full_name')` → `Repository.from_github_repo_name(...)` [6](#0-5) 
- `PushHandler#process` uses `stacks` (derived from `full_name`) to call `stack.sync_github(expected_head_sha: params.after)` [7](#0-6) 
- PR handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` independently, e.g. [8](#0-7) .

`Repository.from_github_repo_name` simply splits `owner/name` from this unverified `full_name` string and does a DB lookup: [9](#0-8) .

This breaks the binding: **organization that authenticated == repository that is written**. The signature check authenticates that *some* configured organization's secret (or an organization with no secret configured at all) matches the request; the action, however, is performed against whatever `repository.full_name` the attacker put in the JSON body, which is never cross-checked against `repository.owner.login`/the verified organization.

Concretely, in a multi-org config (`docs/setup.md` documents this schema, and `config/secrets.development.example.yml` shows `webhook_secret: # nil` is an accepted/default value for an app entry) [10](#0-9) [11](#0-10) , if *any* configured GitHub organization in the deployment has `webhook_secret` unset/blank (a documented, valid configuration state), an attacker can:
1. Send a POST to `/webhooks` with `repository.owner.login` (or `organization.login`) set to that no-secret organization — `verify_webhook_signature` returns `true` unconditionally, no signature needed.
2. Set `repository.full_name` in the very same payload to `victim-org/victim-repo` (a stack hosted under a *different*, secret-protected organization).
3. The handler (e.g. `PushHandler`) resolves `stacks` from `victim-org/victim-repo` and calls `stack.sync_github(expected_head_sha: params.after)`, or PR handlers archive/unarchive/create review stacks, or `MembershipHandler`-style handlers create users/teams — all scoped to the victim repository, despite the request never being authenticated by the victim organization's app.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary explicitly called out in scope: the webhook subsystem authenticates against org A's (possibly secret-less) GitHub App but writes state for org B's stacks/repositories. Depending on which handler is triggered, an attacker can force a `GithubSyncJob`/`sync_github` call against an arbitrary stack (`PushHandler`), or manipulate review-stack lifecycle (archive/unarchive/provision) for PRs on repositories they don't control (`PullRequest::*Handler`), all without holding a Shipit session, API token, or the victim organization's webhook secret. This is a cross-repository write triggered purely by controlling which organization is named in an unauthenticated field of the JSON body.

### Likelihood Explanation
Requires a specific but realistic and documented deployment shape: multiple GitHub organizations configured under `secrets.github` (the multi-org schema is first-class and documented), with at least one organization's `webhook_secret` unset — a state the example secrets file explicitly shows as acceptable (`webhook_secret: # nil`). Given that condition, exploitation requires only a single unauthenticated HTTP POST with a crafted JSON body and the correct `X-Github-Event` header; no credentials, sessions, or secrets are needed. Likelihood is moderate — contingent on operator misconfiguration (a missing secret for one org among several), but the engine itself provides no defense-in-depth (e.g., cross-checking `repository.owner.login` against `repository.full_name`'s owner segment) once that misconfiguration exists.

### Recommendation
- In `WebhooksController` or `Handler`, after determining `repository_owner` used for signature verification, assert that it matches the owner segment of `repository.full_name` (and `organization.login` where present) before dispatching to handlers; reject on mismatch.
- Do not allow `verify_webhook_signature` to silently return `true` for organizations with a blank `webhook_secret` in multi-org configurations; require every configured organization to have a non-blank secret, or explicitly disallow processing repository-scoped events for organizations lacking one.
- Consider deriving the repository/stack resolution scope directly from the same field used for authentication rather than trusting a second, independently-supplied field in the same untrusted payload.

### Proof of Concept
Given a Shipit deployment configured with multiple GitHub organizations where org `no-secret-org` has no `webhook_secret` set (a state the shipped example config explicitly documents as valid) and org `victim-org` has stacks configured with a real secret:

1. Attacker sends:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "no-secret-org" }
  }
}
```
2. `WebhooksController#repository_owner` returns `"no-secret-org"` [2](#0-1) , so `Shipit.github(organization: "no-secret-org")` loads that org's `GitHubApp`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [4](#0-3)  — no `X-Hub-Signature` header is even required.
3. `create` dispatches the same `params` to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("victim-org/victim-repo")` [6](#0-5) [9](#0-8) , and calls `stack.sync_github(expected_head_sha: params.after)` for all matching stacks under `victim-org/victim-repo` — for stacks whose branch matches — entirely bypassing the victim organization's actual webhook secret [7](#0-6) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** docs/setup.md (L184-209)
```markdown
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```
