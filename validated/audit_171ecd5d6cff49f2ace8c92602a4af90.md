Confirmed: `Handler#stacks` resolves the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`, which is a *different* payload field from `repository.owner.login` used by `WebhooksController#verify_signature` to select which GitHub App/webhook secret validates the request. These two fields are never checked for consistency.

### Title
Webhook signature verified against a different org than the repository actually acted upon in multi-org installs - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App configuration, `WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the webhook secret) to check the `X-Hub-Signature` against using `repository_owner`, taken from `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . However, the handler that actually acts on the payload (`Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`) resolves the target `Stack` using the unrelated field `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing ties these two fields together, and `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that org has no `webhook_secret` configured [4](#0-3) .

### Finding Description
The binding that should hold is: *`organization` whose secret authenticated the signature == `organization` that owns the repository being acted upon*. In practice the engine implements: *`organization` derived from `repository.owner.login` (attacker-controlled JSON field) authenticates the signature*, while *the repository/stack actually mutated is derived from `repository.full_name` (a second, independently-controlled JSON field)*.

In multi-org setups (`docs/setup.md` "Using Multiple Github Applications" section) each org has its own `webhook_secret`, and orgs are commonly left with no secret configured (every example/template ships `webhook_secret: # nil` or `webhook_secret:` blank) [5](#0-4) [6](#0-5) . When an org's `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally: `return true unless webhook_secret` [4](#0-3) .

An unprivileged network attacker who knows (a) that some configured org `OrgNoSecret` has no webhook secret set, and (b) the `full_name` of a real Shipit-tracked repository owned by a *different*, secret-protected org `OrgVictim`, can POST directly to `/webhooks` with:
```json
{"repository": {"owner": {"login": "OrgNoSecret"}, "full_name": "OrgVictim/target-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen-sha>"}
```
`repository_owner` resolves to `OrgNoSecret`, `Shipit.github(organization: 'OrgNoSecret')` is looked up, its `webhook_secret` is blank, so `verify_signature` passes with **no signature required at all** [7](#0-6) . The `push` handler is then dispatched with the raw params; it resolves the target stack via `Repository.from_github_repo_name('OrgVictim/target-repo')` [8](#0-7)  and calls `stack.sync_github(expected_head_sha: params.after)` on branch `main` of the real `OrgVictim/target-repo` stack [9](#0-8) , forcing Shipit to sync/fast-forward its record of that stack's HEAD to an attacker-chosen SHA without ever presenting a valid signature for `OrgVictim`.

### Impact Explanation
This is exactly the "organization that authenticated versus the repository that is written" binding class called out in scope. Forcing `expected_head_sha` on a real tracked stack can drive automatic deploy behavior (`sync_github` feeds the commit list Shipit deploys from) without any credential — this is an unauthenticated cross-organization write into a stack's deploy-relevant state, satisfying the High bar ("unauthenticated read of stack state" is explicitly listed; this goes further, mutating it) and edges toward "unauthorized deploy" depending on downstream `sync_github`/auto-deploy configuration for that stack.

### Likelihood Explanation
Requires only: (1) the target Shipit instance runs multi-org config, (2) at least one configured org has an empty/no `webhook_secret` (the default/example configuration shape shipped in this repo's own `template.rb` and `docs/setup.md`), and (3) attacker knows the `owner/name` of any tracked repository belonging to another org. No authentication, no GitHub credentials, and no prior access are needed — a bare unauthenticated HTTP POST to the public `/webhooks` endpoint suffices.

### Recommendation
`verify_signature` must select the signing organization from the same field that `Handler#repository_name` uses to resolve the target repository (i.e., derive the org strictly from `repository.full_name`'s owner segment, not from the separate, independently attacker-controlled `repository.owner.login`/`organization.login` field), and/or refuse to process any webhook whose declared `repository.owner.login` does not case-insensitively match the owner segment of `repository.full_name`. Additionally, treat a blank/unset `webhook_secret` for a *specific* org as a hard misconfiguration warning rather than an implicit "always verified" pass, or require all orgs in a multi-org config to have a non-blank secret.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `OrgNoSecret` (webhook_secret blank) and `OrgVictim` (webhook_secret set, has a tracked `Stack` for `OrgVictim/target-repo` on branch `main`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {"owner": {"login": "OrgNoSecret"}, "full_name": "OrgVictim/target-repo"},
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
No `X-Hub-Signature` header (or an arbitrary bogus one) is required.
3. Observe `verify_signature` passes (`OrgNoSecret` has no secret) and `PushHandler` runs `stack.sync_github(expected_head_sha: "deadbeef...")` against the real `OrgVictim/target-repo` stack [9](#0-8)  — a cross-organization write achieved with zero valid credentials for `OrgVictim`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** template.rb (L102-111)
```ruby
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
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
