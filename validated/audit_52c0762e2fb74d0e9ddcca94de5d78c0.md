### Title
Webhook signature verification is keyed off `repository.owner.login` while event processing acts on `repository.full_name`, allowing cross-organization webhook forgery when any configured GitHub App has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and therefore which `webhook_secret`) to validate an inbound webhook against using the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON payload, while the handlers that actually act on the webhook (e.g. `PushHandler`, status/commit handlers) operate on the full `repository` object of that same, unauthenticated-by-that-field payload. The binding the engine relies on — "the organization whose secret validated this payload" == "the repository the payload will mutate" — is never enforced. In any multi-tenant install where at least one configured GitHub organization has no `webhook_secret` set (an explicitly supported configuration), an unprivileged attacker can post a forged webhook that claims to originate from that unsecured organization while carrying a `repository.full_name` that points at a totally different, secured organization's stack.

### Finding Description
The controller derives the org used for verification purely from payload content: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`verify_signature` then looks up that organization's `GitHubApp` and asks it to verify the signature: [3](#0-2) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the organization's `webhook_secret` is blank: [4](#0-3) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

A nil/blank `webhook_secret` per-organization is an explicitly supported configuration shape (seen in the multi-org fixture `test/dummy/config/secrets_double_github_app.yml`, where `OrgTwo` is configured with `webhook_secret: # nil`), and `Shipit.github(organization:)` resolves per-organization config via `github_app_config`: [5](#0-4) 

Once `verify_signature` passes (trivially, because the claimed org has no secret), `WebhooksController#create` dispatches the *entire, unmodified* payload to the event handlers: [6](#0-5) 

Handlers such as `PushHandler` never re-check `repository.owner.login`; they act on whatever repository/stack the payload's own `repository`/`ref` fields identify, e.g. triggering a resync: [7](#0-6) 

Because the field used to select the verification secret (`repository.owner.login`) and the field(s) used to select the target Stack for mutation (`repository.full_name`, `ref`, etc., inside the same JSON body) are independent and both attacker-supplied, there is no requirement that they refer to the same repository. This is the same class of bug as the WatchPug finding: an owner/authorizer field (`_rewardOwner`/`repository.owner.login`) is checked, but a different field actually receiving the effect (`_borrower`/the real target repository) is never bound to it.

### Impact Explanation
On a multi-tenant Shipit deployment (multiple entries under `secrets.github`), if any one configured organization has no `webhook_secret`, an unauthenticated internet client can:
1. Send a POST to `/webhooks` (or whatever path mounts `WebhooksController`) with `X-Github-Event: push` (or `status`, `check_suite`, `pull_request`, etc.).
2. Set `repository.owner.login` (or `organization.login`) to the unsecured org's name so `verify_signature` trivially passes.
3. Populate the rest of the payload (`repository.full_name`, `ref`, `after`, commit SHAs, PR numbers, statuses) to target a Stack that actually belongs to a *different*, secured organization.

This lets an unprivileged attacker forge events against a protected repository's Stack, without ever knowing that organization's real `webhook_secret`. Depending on which event/handler is abused, this can drive `GithubSyncJob`/`RefreshCheckRunsJob`, forge commit statuses, or manipulate merge-queue/pull_request state for a repository the attacker has no legitimate access to — i.e., cross-repository/cross-organization writes into stack state that should only be reachable by that organization's real GitHub App, satisfying the "cross-repository writes" / unauthorized-deploy-adjacent impact bar (e.g., forged `status` events feeding a `continuous_deployment: true` stack can trigger an actual auto-deploy).

### Likelihood Explanation
Requires only that the Shipit install is multi-tenant (multiple `github` orgs configured) and that at least one configured org has no `webhook_secret` — a state the engine's own config schema and test fixtures treat as valid/supported rather than a documented hard requirement to always set secrets. No GitHub App private key, `ApiClient` token, or session is needed; the request is a plain unauthenticated HTTP POST to the public webhooks endpoint.

### Recommendation
- Require `repository.full_name`'s owner to match the `repository_owner` used for signature selection before dispatching to handlers, or better, verify against every configured organization's secret and only accept if the *matching* organization's secret validates, never allowing an unsecured org to "vouch" for a different org's repository.
- Consider making `webhook_secret` mandatory per-organization in multi-tenant configurations, rejecting requests for organizations without a configured secret rather than treating an absent secret as "verified".

### Proof of Concept
Given a Shipit deployment with `secrets.github` containing:
```yaml
OrgSecured:
  webhook_secret: "s3cr3t"
  ...
OrgOpen:
  webhook_secret: # nil, no secret configured
  ...
```
and a real Stack tracking `OrgSecured/protected-repo`:

```bash
curl -X POST https://shipit.example.com/webhooks \
  -H "X-Github-Event: push" \
  -H "X-Hub-Signature: sha1=irrelevant" \
  -d '{
        "repository": {
          "owner": {"login": "OrgOpen"},
          "full_name": "OrgSecured/protected-repo"
        },
        "ref": "refs/heads/master",
        "after": "deadbeefcafefeed0000000000000000000000ff"
      }'
```

`repository_owner` resolves to `OrgOpen`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally regardless of the bogus `X-Hub-Signature`. `PushHandler` then processes the payload using `repository.full_name` = `OrgSecured/protected-repo`, forcing a resync (`stack.sync_github(expected_head_sha: ...)`) of a Stack the attacker never had legitimate access to, entirely without knowledge of `OrgSecured`'s real webhook secret.

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
