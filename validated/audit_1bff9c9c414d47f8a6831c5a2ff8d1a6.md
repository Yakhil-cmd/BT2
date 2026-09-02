### Title
Webhook signature verification is keyed to the attacker-controlled `repository.owner.login` field while the mutated resource is selected from the equally attacker-controlled `repository.full_name` field, allowing cross-organization signature bypass in multi-org deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, a value read out of the *unverified* JSON body itself. [1](#0-0)  The handlers that actually mutate state (e.g. `PushHandler`) select the target `Repository`/`Stack` using a different field from the same unverified body: `repository.full_name`. [2](#0-1)  In a multi-organization deployment (`config/secrets.yml` `github:` keyed by org, as documented) these two fields are never cross-checked against each other, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization's `webhook_secret` is blank. [3](#0-2) 

### Finding Description
The engine supports configuring several GitHub organizations, each with its own `app_id`, `webhook_secret`, etc., resolved through `Shipit.github(organization:)` / `Shipit.github_app_config`. [4](#0-3)  The webhook signature check binds the verification key to the org name pulled straight out of `params.dig('repository', 'owner', 'login')` (or the `organization` sub-object) — a value inside the same JSON body the HMAC is supposed to protect: [5](#0-4) 

`GitHubApp#verify_webhook_signature` explicitly bypasses HMAC comparison entirely when that organization's `webhook_secret` is not configured:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

After the (bypassable) check, the controller dispatches the raw, still-unverified `params` hash directly to handlers: [6](#0-5) 

Handlers such as `PushHandler` resolve the affected `Stack`/`Repository` using a *different* field of the same payload — `repository.full_name` — never re-checked against the organization used for signature selection: [2](#0-1) [7](#0-6) 

Equality that should hold but does not: `organization used to authenticate the request == organization owning the repository being written to`. An unprivileged attacker who can reach the public `/webhooks` endpoint (no auth required, per `skip_before_action :verify_authenticity_token`) can submit a payload where:
- `repository.owner.login` (and/or top-level `organization.login`) = an organization configured in `secrets.yml` **without** a `webhook_secret` (e.g. a low-value/sandbox org an operator forgot to secure, or one intentionally left open for local/dev use, as shown in the example config where `webhook_secret:` is commented as optional/nil). [8](#0-7) 
- `repository.full_name` = the real target repository belonging to a *different*, properly-secured organization.

Since `verify_signature` only ever looks at `repository_owner` to pick the `GitHubApp` config, it will resolve the org lacking a secret, call `verify_webhook_signature` which returns `true` unconditionally, and let the request through with **no signature validation at all** — even though the payload's `full_name` targets a stack owned by a fully-secured organization.

### Impact Explanation
This breaks the authentication boundary the signature check is meant to enforce (unauthenticated read/write of stack state). Concretely, an attacker can forge `push`, `status`, `check_suite`, `membership`, or `pull_request` webhook events for any stack whose repository belongs to an org other than the one they abuse for verification bypass, as long as any org in the install lacks a `webhook_secret`. This can trigger `GithubSyncJob` (`PushHandler`), fabricate commit statuses (`StatusHandler`), or manipulate team membership (`MembershipHandler`), all without possessing the real secret for the targeted organization. This maps to the High-severity category "unauthenticated read of stack state, task streams or deploy output" and can escalate toward unauthorized deploy triggering through continuous-delivery-eligible commits being injected via forged push/status events.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly documented/supported), and (2) at least one configured organization without a `webhook_secret`. This is a realistic operational misconfiguration risk explicitly enabled by the schema (`webhook_secret` is optional per the example config), and nothing in the code ties the org used for verification to the org that actually owns the mutated repository. No privileged credentials, session, or GitHub App key are needed — only network access to the public `/webhooks` endpoint.

### Recommendation
After resolving the signing organization and verifying the signature, re-derive `repository_owner` from the same value used to build the `GitHubApp`, and additionally verify that `repository.full_name`'s owner segment matches `repository_owner` before dispatching to handlers. Alternatively, require `webhook_secret` to be present for every configured organization in a multi-org deployment (fail closed instead of returning `true` when absent), and reject payloads whose `repository.full_name` owner does not match the organization resolved for signature verification.

### Proof of Concept
1. Deploy Shipit with two orgs configured in `secrets.yml`: `orgA` (no `webhook_secret`) and `orgB` (`webhook_secret: real-secret`), with a real stack tracking `orgB/private-repo`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "orgB/private-repo",
    "owner": { "login": "orgA" }
  }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required.
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the actual header value.
4. `PushHandler` resolves `repository_name = "orgB/private-repo"` and enqueues `GithubSyncJob` for that stack, effectively forging a signed webhook event for `orgB`'s repository without ever presenting `orgB`'s secret. [7](#0-6)

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** config/secrets.development.example.yml (L8-11)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
```
