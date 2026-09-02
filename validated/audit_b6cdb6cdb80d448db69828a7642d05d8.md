### Title
Cross-organization webhook forgery via decoupled signature-org and target-repository fields — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which GitHub App/organization's `webhook_secret` to verify a webhook's HMAC signature against using `payload.dig('repository','owner','login')` (or `organization.login`), but the actual event handlers resolve the `Stack`/`Repository` to act on using an entirely different, unconstrained field: `payload.dig('repository','full_name')`. In a multi-organization Shipit deployment (a first-class, documented configuration), an attacker who controls a GitHub organization/App legitimately configured on the same Shipit instance can sign a payload with their own valid `webhook_secret`, while setting `repository.full_name` to a **different organization's** stack, causing Shipit to execute writes (sync commits/statuses, create teams/memberships, close/merge pull requests) against a repository that never authenticated the request.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to validate against strictly from the "owner"/"organization" login in the payload: [1](#0-0) [2](#0-1) 

This binds "who is authenticating" to `repository_owner`. However, once the HMAC check succeeds, the payload is handed unmodified to `Shipit::Webhooks.for_event(event)` handlers: [3](#0-2) 

Every default handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves its target stacks through `Handler#stacks`, which uses a **completely separate** field, `repository.full_name`, with no cross-check against `repository_owner`: [4](#0-3) [5](#0-4) [6](#0-5) 

Shipit explicitly supports hosting multiple, unrelated GitHub organizations from a single instance, each with its own `webhook_secret`: [7](#0-6) [8](#0-7) 

Equality that should hold but is broken:
`organization authenticated by verify_signature (repository_owner) == organization that owns the repository/stack actually written by handlers (repository.full_name)`

Because these two payload fields are independently attacker-controlled inside the request body (the HMAC only proves "some valid signer for `repository_owner`'s secret produced this exact byte-stream," not "the events inside only concern `repository_owner`'s repos"), an org that has legitimately configured its own GitHub App/webhook_secret on the shared Shipit instance can forge `repository.full_name` to point at any other organization's stack hosted on that instance and still pass signature verification.

### Impact Explanation
This breaks the tenant isolation between organizations sharing one Shipit deployment: an org that only authenticated to act on its own repository can inject `push`, `status`, `check_suite`, `pull_request`, or `membership` events that mutate a completely different organization's commits, deployable/CI status, teams, and merge/deploy pipelines. This satisfies the "Critical — cross-repository writes" impact bar, since Shipit actions ultimately drive unattended deploys/merges (e.g., forged `status`/`check_suite` success events on a victim commit can make it appear CI-passing and get auto-merged/auto-deployed by that other org's stack).

### Likelihood Explanation
Requires the attacker to control at least one legitimately configured GitHub App/organization on the shared Shipit instance (a normal, unprivileged position relative to any other tenant's repos) — no access to the victim organization's secrets, sessions, or `ApiClient` tokens is needed. This is realistic for any SaaS-style or shared-hosting deployment of Shipit serving multiple organizations, which is an explicitly documented and supported configuration.

### Recommendation
In `Handler#stacks` (and any other webhook-driven lookup), restrict the resolved `Repository`/`Stack` to the same organization that was authenticated in `WebhooksController#verify_signature` (e.g., pass `repository_owner` through to handlers and assert `Repository#owner` matches it before acting), rather than trusting `repository.full_name` alone.

### Proof of Concept
1. Configure Shipit with two orgs, `AttackerOrg` (attacker-controlled GitHub App/installation, secret known to attacker) and `VictimOrg` (unrelated tenant), as in `docs/setup.md`'s "Using Multiple Github Applications" section.
2. Attacker crafts a `push` (or `status`) webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `AttackerOrg`'s own `webhook_secret` (which they legitimately possess) over this exact payload, and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` looks up `Shipit.github(organization: 'AttackerOrg')` and successfully verifies the HMAC against `AttackerOrg`'s secret [1](#0-0) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name('VictimOrg/victim-repo')` [4](#0-3) , and triggers `GithubSyncJob`/status updates on `VictimOrg`'s stack — despite the signature only proving knowledge of `AttackerOrg`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
