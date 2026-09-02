### Title
Cross-organization webhook signature confusion allows unauthorized `GithubSyncJob` / status writes on another tenant's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check against using `repository.owner.login` (falling back to `organization.login`) from the untrusted request body, but the handlers that subsequently act on the event (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a *different* field, `repository.full_name`, via `Repository.from_github_repo_name`. Nothing ties the two together, so a valid signature for organization A's app does not guarantee the acted-upon repository actually belongs to organization A.

### Finding Description
In a multi-organization deployment (explicitly documented and supported, see `docs/setup.md` "Using Multiple Github Applications"), each onboarded GitHub organization configures its own `app_id`/`webhook_secret` in `Shipit`'s secrets, and `Shipit.github(organization:)` returns a distinct `GitHubApp` per org: [1](#0-0) .

`WebhooksController#verify_signature` picks the app/secret to validate against purely from the payload's `repository.owner.login` (or `organization.login`): [2](#0-1) [3](#0-2) 

The HMAC signature (`X-Hub-Signature`) is computed over the whole raw body, so it is internally consistent — but it only proves the body was signed by *some* org's secret, not that the org identified by `owner.login` matches the repository the handler actually operates on. Handlers derive the target repository from a separate JSON path, `repository.full_name`: [4](#0-3) 
which is resolved to an ActiveRecord `Repository`/`Stack` via `Repository.from_github_repo_name`, a straight DB lookup with no ownership cross-check against the value used for signature selection: [5](#0-4) 

`PushHandler#process` then finds all matching `Stack`s for that repository/branch and calls `sync_github`: [6](#0-5) 

Because `repository.owner.login` (used to pick/verify the secret) and `repository.full_name` (used to pick the acted-upon repo) are independent, unvalidated fields inside the same signed body, an org that legitimately controls its own GitHub App/webhook secret can construct a payload where `repository.owner.login` = its own org (so the signature check passes with its own known secret) while `repository.full_name` names a stack belonging to a different, victim organization onboarded to the same Shipit instance. This is the same "authorize on field X, act on field Y" class as the reported `CSModule` bug (bond checked via one call path, incremented via an unrelated permissionless path): the *organization that authenticated* is not equal to the *repository that is written*.

### Impact Explanation
This breaks the tenant-isolation guarantee that a webhook can only affect repositories belonging to the organization whose secret produced a valid signature. A malicious (but legitimately onboarded) organization can:
- trigger `GithubSyncJob`/`sync_github` for another tenant's `Stack` (`PushHandler`), and
- forge commit statuses for another tenant's commits (`StatusHandler`, same `repository`/`full_name` pattern),
without ever possessing that victim organization's webhook secret or any Shipit credentials for it. This is a cross-repository/cross-tenant write achieved purely by crafting payload fields the signature check ignores, matching the "cross-repository writes" impact bar.

### Likelihood Explanation
Requires: (1) the deployment to use the documented multi-org configuration, and (2) the attacker to control/administer at least one onboarded GitHub organization's App (and thus know its own `webhook_secret`) — no privileged Shipit account, `ApiClient` token, or GitHub App private key is needed. This is a realistic scenario for any shared/multi-tenant Shipit instance serving several independent GitHub orgs.

### Recommendation
After selecting the app/secret via `repository.owner.login`/`organization.login` and verifying the signature, re-validate that every repository-identifying field used later by handlers (`repository.full_name`, `repository.owner.login`, `organization.login`) is mutually consistent, and reject the webhook if `Repository.from_github_repo_name(payload.dig('repository','full_name'))`'s owner does not match the organization whose secret validated the signature.

### Proof of Concept
1. Onboard organization `attacker-org` on the shared Shipit instance with its own `webhook_secret` (known to the attacker, who administers that org's GitHub App).
2. Craft a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<victim commit sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Sign the raw body with `attacker-org`'s webhook secret and set `X-Hub-Signature` and `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, validates successfully against `attacker-org`'s secret.
5. `PushHandler#process` resolves `stacks` from `repository.full_name` = `victim-org/victim-repo`, triggering `sync_github` on the victim's stack, an action the attacker was never authorized to perform.

Note: I could not execute this end-to-end in a running instance (no execution/test environment available), so this is a static-analysis-based proof of concept derived from the code paths cited above; a Devin session with the full test suite would be needed to confirm behavior dynamically (e.g. via `test/controllers/webhooks_controller_test.rb` and `test/dummy/config/secrets_double_github_app.yml` fixtures for multi-org signature tests).

### Citations

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
