### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while event processing keys on the unrelated `repository.full_name` field, letting a valid signature from one GitHub organization forge events for a stack owned by a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments (`secrets.github` keyed by organization), the webhook signature check in `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate against using `repository_owner`, derived from `params.dig('repository','owner','login')` (or `organization.login`) taken from the *unverified* JSON body. [1](#0-0) [2](#0-1) 

Once the HMAC check passes for whatever organization `repository_owner` names, the controller dispatches the *entire* raw payload to `Shipit::Webhooks.for_event(event)` handlers, and every handler resolves the target `Stack`/`Repository` from a **different** field of the same payload: `payload.dig('repository', 'full_name')`. [3](#0-2) [4](#0-3) 

Because the attacker constructs the JSON body themselves, nothing forces `repository.owner.login` (used to pick the verifying secret) to match `repository.full_name`'s owner (used to pick the affected stack). An attacker who legitimately controls (or knows the webhook secret of) *their own*, low-privilege GitHub organization/repo registered in Shipit can sign a payload with that secret while setting `repository.full_name` to `victim-org/victim-repo`, causing Shipit to act on the victim's stack as if the event genuinely came from GitHub for that repository.

### Finding Description
The equality that should hold is: *the organization whose secret authenticated the request* == *the repository/organization whose stack is mutated by the request*. This binding is never enforced:

1. `verify_signature` computes `repository_owner` from the payload and looks up `Shipit.github(organization: repository_owner)`, then validates the raw body's HMAC against that organization's `webhook_secret` via `GitHubApp#verify_webhook_signature`. [5](#0-4) 
2. If verification succeeds, `WebhooksController#create` hands the *whole* raw payload to the registered handlers (`push`, `status`, `check_suite`, `membership`, `pull_request/*`), with no re-derivation or cross-check of `repository_owner`. [3](#0-2) 
3. `Handler#stacks`/`#repository_name` locates the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`, an independent field of the same attacker-supplied JSON body. [4](#0-3) 
4. `Repository.from_github_repo_name` performs a straightforward lookup by `owner`/`name` parsed out of `full_name`, without any comparison to the organization used for signature verification. [6](#0-5) 

This is the direct structural analog of the reported Uniswap V3 AMO bug: a value that is *trusted for one purpose* (price/oracle presence, here "the org that produced a valid signature") is silently substituted for a *different, unverified value* (collateral units at face value, here "the repo/org actually acted upon"), because the code never checks that the two should be the same entity.

### Impact Explanation
Concretely, `StatusHandler#process` writes GitHub commit statuses into Shipit for any `sha` present in `Commit` regardless of which org signed the request: [7](#0-6) 
and `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` for the stacks resolved from the forged `repository.full_name`: [8](#0-7) 

An attacker who owns a low-privilege repo/org configured in the same multi-tenant Shipit instance can therefore forge `status`/`push`/`check_suite`/`pull_request` events for a victim's stack that they do not control, potentially:
- Injecting fabricated commit statuses that satisfy `ci.require` checks used to gate merges/deploys in the victim stack, moving it toward an unauthorized merge/deploy decision.
- Forcing spurious `sync_github` calls or check-run refresh jobs against a repository they don't own.

This crosses the "escalation into authorization" / "unauthorized deploy or merge" bar because the write is scoped to a repository the attacker was never authenticated for — the signature only proves membership of *some* configured organization, not the one being mutated.

### Likelihood Explanation
This requires the host application to run Shipit in the documented multi-organization configuration (`secrets.github` keyed by multiple orgs) and for the attacker to control (or know the secret of) at least one of those configured organizations' repos — a realistic scenario for shared/hosted Shipit instances serving multiple teams/orgs, which is an explicit supported configuration (`Shipit.github_organizations`, `TOP_LEVEL_GH_KEYS`). [9](#0-8) 
No GitHub App private key, `api_clients_secret`, or Shipit session is needed — only a webhook secret for *any one* onboarded organization, which is inherently distributed to (and visible in) that organization's own GitHub webhook settings.

### Recommendation
- **Short term**: After signature verification, re-derive `repository_owner`/`organization` strictly from the same trust-anchored source used for verification, and reject (422) any event where the target `repository.full_name`'s owner does not match the organization whose secret validated the signature.
- **Long term**: Bind each `Repository`/`Stack` to the specific GitHub App/organization configuration it belongs to at lookup time, and require that this binding be checked against the verified signer for every incoming webhook, not just at signature-selection time.

### Proof of Concept
1. Shipit is deployed with multi-org config: `secrets.github` contains `orgA` (attacker-controlled, webhook secret known to attacker) and `orgB` (victim, hosts `orgB/victim-repo`).
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` extracts `repository_owner = "orgA"`, loads `Shipit.github(organization: "orgA")`, and the HMAC matches → request is accepted (`head(:ok)` never triggered, request passes to `create`). [10](#0-9) 
5. `StatusHandler#process` runs and looks up `Commit.where(sha: params.sha)` — which includes commits from `orgB/victim-repo` — and calls `create_status_from_github!`, injecting an attacker-forged "success" status for a check Shipit's merge/deploy gating in `orgB` relies on, despite the signature only proving control of `orgA`. [7](#0-6)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
