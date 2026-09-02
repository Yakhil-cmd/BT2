### Title
Webhook signature is verified against an organization/repo taken from the unauthenticated payload, letting any onboarded organization forge deploy-status webhooks for a different organization's commits - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects *which organization's* webhook secret to validate the HMAC against by reading `repository_owner`/`organization.login` straight out of the still-unverified JSON body. Handlers that consume the verified payload (in particular `StatusHandler`) then act on data (a commit `sha`) that is not scoped to that same organization/repository at all. This breaks the binding "organization that authenticated == repository/stack that is written," letting a legitimate but unprivileged tenant of a shared Shipit instance forge commit statuses for commits belonging to a completely different organization's stack.

### Finding Description
`Shipit.github(organization:)` supports one `webhook_secret` per onboarded GitHub organization [1](#0-0) . The controller picks which organization's secret to check the HMAC against using a field taken from the raw, not-yet-verified request body:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

So the signature check only proves "this payload was signed with *some organization X's* secret, where X is whatever the payload itself claims." It never proves that the rest of the payload (in particular the target commit/repository being mutated) actually belongs to organization X.

Once verification succeeds, `create` dispatches the full parsed body to handlers [3](#0-2) . Most handlers do scope their side effects to the repository named in the payload via `Handler#repository_name`/`#stacks`, which look up `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` [4](#0-3) . But `StatusHandler`, which drives CI/deploy-readiness state, does not scope by repository/organization at all — it looks up commits globally by SHA across the entire installation:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

This is exactly the class of bug in the report: a value that is checked/authenticated for one purpose (`repository_owner`, used only to pick the HMAC key) is not the same value that is actually acted upon downstream (an arbitrary commit `sha`, unscoped to any repository), so verifying one does not guarantee the other is legitimate — mirroring how `toReset` addresses were validated as "contract addresses" but never validated as "tapped addresses," the actual invariant `openTrading` depended on.

### Impact Explanation
Any organization legitimately onboarded to a shared/multi-tenant Shipit instance (and therefore in possession of its own, correctly-provisioned webhook secret) can forge a `status` event: sign it with their own organization's secret (so `verify_signature` passes, since the payload's `repository.owner.login` names their own org) but set `sha` to a commit SHA belonging to a different organization's tracked repository/stack. `StatusHandler` will create a fabricated commit status (e.g. `state: "success"`, `context: "ci/required-check"`) attached to that foreign commit [5](#0-4) . If that status satisfies a stack's `ci.require`/`ci.blocking` gates, it can enable an unauthorized deploy of a commit that never actually passed the victim organization's real CI, i.e., a cross-repository write / unauthorized deploy trigger — Critical impact per the listed criteria.

### Likelihood Explanation
Requires only that the attacker controls (or is) one of the other organizations already onboarded to the same multi-tenant Shipit instance — no repository write access, GitHub App private key, or `ApiClient`/session token to the victim's stack is needed, only knowledge of their own organization's `webhook_secret` and the target commit SHA (visible on GitHub/PR pages). This is a realistic scenario for any shared/multi-org Shipit deployment as evidenced by first-class support for multiple orgs in `github_app_config`/`github_organizations` [6](#0-5)  and the dedicated fixture `test/dummy/config/secrets_double_github_app.yml` used to test multi-org webhook handling.

### Recommendation
Do not derive the HMAC-verification organization from the unauthenticated payload alone; after verifying with an organization key, re-derive the target repository from a trusted association (e.g. `Repository.from_github_repo_name(payload['repository']['full_name'])`) and require that its owning organization matches the organization whose secret validated the signature — rejecting the event otherwise. Additionally, `StatusHandler#process` should scope its `Commit` lookup to commits belonging to repositories owned by the verified organization instead of matching `sha` globally.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` (per `TOP_LEVEL_GH_KEYS`/`github_app_config` in `lib/shipit.rb`), and `orgB` has a tracked stack with a commit `C` awaiting a required CI status.
2. Attacker, who legitimately administers `orgA`'s GitHub App/webhook integration, knows `orgA`'s `webhook_secret`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "orgA" } },
  "sha": "<sha of commit C in orgB>",
  "state": "success",
  "context": "ci/required-check"
}
```
signed with `orgA`'s secret in `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` to `orgA`, fetches `orgA`'s `GitHubApp`, and the HMAC check passes [7](#0-6) .
5. `StatusHandler#process` finds commit `C` purely by `sha` (no ownership check) and writes a forged "success" status onto it [5](#0-4) , potentially unblocking a deploy of `C` in `orgB`'s stack despite the attacker having no access to `orgB`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
