### Title
Cross-repository commit status forgery via organization/repository binding mismatch in webhook processing - ([File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub webhook by looking up the `GitHubApp`/`webhook_secret` for whichever organization is named in the *payload itself* (`repository.owner.login`, falling back to `organization.login`), then verifies the HMAC signature against that org's secret. [1](#0-0) [2](#0-1)  Once the request is accepted, `StatusHandler#process` mutates state using only the `sha` field from the payload, with **no check at all** that the commit belongs to a stack/repository whose owner matches the organization that was actually authenticated: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2)  Unlike other handlers (e.g. `PushHandler`, `PullRequest` handlers), `StatusHandler` never calls the base `Handler#stacks`/`repository_name` scoping helper that filters by `Repository.from_github_repo_name`. [4](#0-3) [5](#0-4) 

### Finding Description
This engine supports multiple GitHub App installations, one per organization, each with its own independent `webhook_secret` selected purely from data inside the untrusted payload. [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization whose secret validated the signature == organization/repository whose state the handler mutates`

In `StatusHandler`, this equality is broken. The handler's only scoping key is the commit `sha`, which is unique within a repository's history but is **not** namespaced to a repository at the database or application level in this handler — `Commit.where(sha: ...)` searches across all `Commit` rows regardless of `stack`/repository ownership. [3](#0-2)  The `repository`/`organization` object in the `status` payload, which is what the controller used to select the signing secret, is not part of `StatusHandler`'s required params at all, so it is never cross-checked against the commit that gets updated. [8](#0-7) 

Concretely: an attacker who controls (or is a legitimate collaborator/admin of) any GitHub organization that this Shipit instance has installed a GitHub App for — including any organization configured with `webhook_secret: nil` (explicitly called out as "optional" in the setup docs and shown blank in every example secrets file) [9](#0-8) [10](#0-9)  — can send a forged `status` webhook. `verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the resolved organization, and organization resolution is driven by the attacker-supplied `repository.owner.login`. [11](#0-10) [1](#0-0)  The payload's `sha` field can then reference a commit belonging to an entirely different, unrelated repository/stack tracked by this same Shipit instance, and `StatusHandler` will happily write a forged CI status for it.

### Impact Explanation
Commit statuses drive Shipit's CI gating (`ci.require`, `ci.blocking`) which determines whether a commit is eligible for deploy/merge. By forging a "success" status on a commit belonging to a repository the attacker does not control, an attacker can satisfy required-status checks for that commit and enable an unauthorized deploy through Shipit's own deploy pipeline, and manipulate the merge queue's revalidation logic tied to statuses. This crosses the "unauthorized deploy" impact bar without needing any Shipit session, API token, or the target repository's actual webhook secret — only ability to trigger (or self-host, in a multi-org config) a webhook delivery for an organization that either has no `webhook_secret` configured or whose secret the attacker legitimately possesses for their own unrelated org.

### Likelihood Explanation
Any Shipit deployment tracking more than one GitHub organization (the documented "Using Multiple Github Applications" configuration) is exposed to any org admin able to trigger their own org's webhooks. Additionally, per the example/default configuration files, `webhook_secret` is commonly left blank/optional, which makes `verify_webhook_signature` a no-op for that organization and lets *anyone* who knows a target commit's SHA (routinely public information on GitHub) forge a status for it. The commit SHA is the only material the attacker needs to know, not a secret.

### Recommendation
Scope `StatusHandler` (and any other handler that doesn't already use the base `Handler#stacks` filter) to only update commits whose owning stack/repository matches `payload.dig('repository', 'full_name')`, mirroring what `PushHandler` already does via `Repository.from_github_repo_name(repository_name)`. Additionally, `WebhooksController#verify_signature` should not allow verification to trivially pass just because an organization has no `webhook_secret` configured when other organizations in the same deployment do — or at minimum the resolved `repository_owner` used for authentication must be enforced to match the repository/stack actually mutated by the corresponding handler.

### Proof of Concept
1. Shipit is deployed with the multi-org GitHub App config (`OrgOne`, `OrgTwo`, ...), as documented, or simply with one org whose `webhook_secret` is unset (the documented default). [7](#0-6) 
2. Shipit already tracks a stack for `victim-org/victim-repo`, and has a synced `Commit` row with `sha = "abc123..."`.
3. Attacker, who controls/administers `attacker-org` (or simply knows any org name whose config has no `webhook_secret`), POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "abc123...",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches that org's `GitHubApp`, and `verify_webhook_signature` returns `true` (no secret configured, or attacker computes a valid HMAC using their own org's known secret). [1](#0-0) [11](#0-10) 
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, finds the `victim-org/victim-repo` commit, and calls `create_status_from_github!`, writing a forged "success" status onto it — despite the request never being authenticated against `victim-org`'s app or secret. [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
