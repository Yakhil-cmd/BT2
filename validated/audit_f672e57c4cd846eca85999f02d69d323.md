## Title
Webhook signature is verified against the organization derived from the payload, but the `repository.full_name` used to select the target Stack is taken from that same unauthenticated payload — allowing a webhook signed by one organization's secret to act on another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
The external report's root cause is a verification gap: a value used to make a trust decision (the L2 block number backing the storage proof) is never checked against the value that was actually authorized/expected (the latest known L2 block at fetch time), because the signed proof binds to a claim the caller controls. The structural analog here is in Shipit's multi-organization webhook handling: the *organization* whose HMAC secret is used to verify `X-Hub-Signature` is picked from attacker-supplied JSON fields (`repository.owner.login` / `organization.login`), and after that check passes, the handlers independently pick the *repository to act on* from another attacker-supplied field, `repository.full_name`, with no re-binding between the two. Nothing enforces `repository.full_name`'s owner equals `repository_owner`.

### Finding Description
In a multi-GitHub-App configuration, `Shipit.github(organization: org)` resolves to a distinct `GitHubApp` instance per configured organization, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks which organization's secret to verify against solely from the unauthenticated JSON body:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Once `verify_webhook_signature` returns true for that organization's secret, `create` dispatches the *entire* raw payload to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .

Handlers (e.g. `PushHandler`) then resolve the target `Stack`/`Repository` from a *different* field of the same unauthenticated payload:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

There is no assertion that `repository.full_name`'s owner segment matches `repository_owner` (the value that selected the signing secret). Because both fields live in the same request body and the signature only proves "this body was signed by organization X's webhook secret," nothing stops the body from declaring `organization.login` (or `repository.owner.login`) as org X while `repository.full_name` names a repository belonging to a *different* org Y that also has a Stack configured in this Shipit instance. If the two fields are decoupled (e.g. a `membership`/`organization`-scoped event carries `organization.login` but a different `repository.full_name`, or the attacker who controls org X's webhook secret crafts a body naming org Y's repo), the signature check binds to org X while the write/side-effect (queuing `GithubSyncJob`, updating commit statuses, creating check-run refreshes) is applied to org Y's stack — a cross-repository/cross-organization action authorized by the wrong credential.

This exactly mirrors the report's binding break: "the organization that authenticated" (verified via `repository_owner`/webhook secret) is not equal to "the repository that is written" (resolved via `repository.full_name` inside the handler).

### Impact Explanation
If exploitable, this allows an entity that only controls one organization's Shipit-configured GitHub App/webhook secret to inject webhook events (push, status, check_suite, membership, pull_request) that get applied to a *different* organization's Stack — e.g., forcing `GithubSyncJob` to run against another org's repository, injecting fabricated commit `Status` records that affect `deployable?` checks and downstream deploy gating, or manipulating `Team`/`User` membership records via the `membership` handler. This falls under "cross-repository writes" and "escalation into `Shipit.github_teams` authorization" surface named in the rules' Critical/High impact list, since commit statuses directly gate whether a deploy is permitted through `Commit#deployable?`, and forged CI-status or check-run data could induce an unauthorized deploy path.

### Likelihood Explanation
This requires the multi-organization GitHub App configuration (`secrets.github` keyed by org, per `docs/setup.md` and `lib/shipit.rb#github_app_config`) to be in use, and requires the attacker to possess a legitimately-issued webhook secret for *at least one* configured organization (e.g., a webhook secret for their own onboarded org, or one leaked/compromised for an org they control) — a much lower bar than needing GitHub write access to the target repository. Given the report's own suggested fix pattern is "verify the identifier used to authorize against the identifier the action is scoped to," and Shipit's handler layer never performs that cross-check, likelihood is moderate wherever multi-org mode is deployed.

### Recommendation
After `verify_signature` succeeds, thread the authenticated `repository_owner` (the org whose secret verified the signature) into the handler dispatch, and require that `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.owner` (case-insensitively) equals the verified `repository_owner` before any handler acts. Reject (422) events whose payload repository owner does not match the organization whose webhook secret validated the signature.

### Proof of Concept
Conceptual (not executed, requires a multi-org secrets.yml with two configured orgs "org-a" and "org-b", each having Stacks in this Shipit instance):
1. Attacker holds `webhook_secret` for `org-a` (e.g., as an authorized app owner/admin of org-a's GitHub App).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and a body where `repository.owner.login = "org-a"` (so `repository_owner` resolves to org-a and its secret verifies the HMAC) but `repository.full_name = "org-b/some-repo"`.
3. `verify_signature` passes because the HMAC matches org-a's `webhook_secret` computed over the raw body.
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name("org-b/some-repo")`, and `sync_github` is triggered on org-b's Stack — a write action taken on org-b's stack authorized only by org-a's credential.

I could not execute this against a running instance to confirm GitHub itself would deliver such a mismatched payload organically; the exploit path relies on the attacker directly crafting an HTTP POST to Shipit's `/webhooks` endpoint (not going through GitHub's webhook delivery), which is a standard analog-report assumption per the rules (payload field acted on but never bound to what was authenticated).

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
