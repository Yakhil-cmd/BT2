### Title
Webhook signature verification binds the wrong organization to the repository actually acted on, allowing cross-organization event forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')`. However, the handlers that actually act on the payload (`Handler#repository_name`, used by `PushHandler`/`StatusHandler`/etc.) resolve the target `Repository`/`Stack` from a *different* field of the same JSON body: `payload.dig('repository', 'full_name')`. The HMAC signature only proves the raw bytes came from whoever holds the `webhook_secret` for the organization named in `repository.owner.login` — it does not bind that organization to `repository.full_name`. An attacker who legitimately controls one onboarded organization (and thus its GitHub App `webhook_secret`) can therefore forge a signed payload whose `repository.owner.login` matches their own org (to pass verification) while `repository.full_name` names a victim organization's repository, causing the victim's stacks to process the forged event.

### Finding Description
`Shipit.github(organization:)` resolves a distinct `GitHubApp` (and its own `webhook_secret`) per GitHub organization when the "multiple GitHub Applications" configuration schema is used (documented in `docs/setup.md` "Using Multiple Github Applications", exercised by `test/dummy/config/secrets_double_github_app.yml`). [1](#0-0) 

`WebhooksController#verify_signature` picks the organization used for signature verification purely from the payload's `repository.owner.login` (or `organization.login`): [2](#0-1) 

Once the signature is accepted, `create` hands the *entire raw payload* to the registered handlers: [3](#0-2) 

But the handler base class resolves the actual `Stack`/`Repository` to operate on using `repository.full_name`, a completely separate key of the same payload: [4](#0-3) 

`PushHandler` uses those `stacks` (found via `full_name`) to trigger a GitHub sync at an attacker-supplied `after` sha: [5](#0-4) 

`StatusHandler` looks commits up purely by `sha` (global, not scoped to the verified organization at all) and writes an arbitrary CI status: [6](#0-5) 

Nothing in this chain checks that the organization whose secret validated the HMAC (`repository_owner`) matches the owner encoded in `repository.full_name` used by the handlers. This is exactly the trust binding described by the report analog: "an organization that authenticated versus the repository that is written" is broken. Before the attack: `verified_org == full_name.owner` is assumed by the design (that's how GitHub itself always sends it). After a forged payload: `verified_org != full_name.owner`, yet the payload is processed as if it came from the organization owning the target repository.

### Impact Explanation
An attacker who has legitimate but unprivileged control over one org onboarded to this multi-tenant Shipit instance (e.g., they administer the GitHub App / know its `webhook_secret` for "OrgAttacker", without any Shipit account, GitHub team membership, or write access to the victim's repositories) can:
- Forge a `status` webhook naming any commit `sha` and setting `state: success`. If the victim's stack has `continuous_deployment` enabled, this is the exact trigger that causes `ContinuousDeliveryJob`/`trigger_deploy` to run (confirmed in `test/models/commits_test.rb`: "updating state to success triggers new deploy when stack has continuous deployment"), resulting in an **unauthorized deploy** — cross-organization/cross-repository impact from an unprivileged actor.
- Forge a `push` webhook with `repository.full_name` set to a victim's tracked repo/branch, causing `stack.sync_github(expected_head_sha: ...)` to run for a stack the attacker does not own.

This satisfies the required Critical/High impact bar ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires the deployment to use the documented multi-organization GitHub App configuration (a supported, documented feature, not a misconfiguration) with at least one organization controlled by a less-trusted party than others sharing the same Shipit instance. Given that configuration, the attack requires no Shipit credentials, no GitHub App private key theft, and no interaction with the victim org at all — only the ability to send a correctly HMAC-signed HTTP POST using a secret the attacker already legitimately possesses for their own onboarded org. This is a realistic likelihood in shared/enterprise Shipit deployments serving multiple organizations with differing trust levels.

### Recommendation
In `WebhooksController`/`Handler`, after signature verification, assert that the organization used to verify the signature (`repository_owner`) matches the owner segment of `repository.full_name` (and of `organization.login`, `sender.login` as applicable) before dispatching to handlers. Reject the request (422) on mismatch instead of implicitly trusting the payload's other fields once any valid signature is found.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgAttacker` and `victim-org`, each with distinct `webhook_secret`s (per `docs/setup.md` multi-org schema).
2. Attacker (who legitimately administers `OrgAttacker`'s GitHub App and knows its `webhook_secret`) builds a `status` payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/forged",
     "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "OrgAttacker" } }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `OrgAttacker`'s known `webhook_secret` over the raw JSON body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgAttacker")` and successfully verifies the signature. [7](#0-6) 
5. `create` dispatches to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — a commit belonging to `victim-org/victim-repo`'s stack — and creates a `success` status on it, regardless of the fact that the signature was verified against `OrgAttacker`, not `victim-org`. [6](#0-5) 
6. If that stack has `continuous_deployment: true`, this triggers an unauthorized deploy of `victim-org/victim-repo`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
