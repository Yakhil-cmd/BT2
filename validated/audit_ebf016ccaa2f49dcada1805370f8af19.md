### Title
Webhook Signature Verification Selects the Signing Organization by an Unverified Payload Field, Allowing Cross-Organization Forged Webhook Delivery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to check the `X-Hub-Signature` HMAC against using the `repository.owner.login` (or `organization.login`) field taken straight out of the untrusted JSON body. Every downstream webhook handler, however, resolves the actual `Stack`/`Repository` to act on using a **different** field of the same untrusted body: `repository.full_name`. Because these two fields are never cross-checked, an attacker who is a legitimate, unprivileged customer/tenant of one organization configured in a multi-org Shipit install (and therefore knows that organization's own `webhook_secret`) can sign a payload as their own org while setting `repository.full_name` to point at a completely different organization's repository, causing Shipit to process the event as if it legitimately came from that other repository.

### Finding Description
In `verify_signature`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up per-organization secrets from `secrets.github`, a feature explicitly documented for "Using Multiple Github Applications", where each org has its own `webhook_secret`: [2](#0-1) [3](#0-2) 

Once the signature is accepted, `create` re-parses the raw body and dispatches it, unmodified, to every registered handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

Every handler resolves the target repository/stack from a *different* payload field, `repository.full_name`, with no relation to `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

For example, the push handler triggers a `sync_github` job purely based on that mismatched full name: [6](#0-5) 

and PR handlers create/archive/unarchive review stacks and update pull request state the same way: [7](#0-6) [8](#0-7) 

**The broken binding**: `Shipit.github(organization: repository_owner)` (the organization whose secret authenticated the request) is not equal to `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (the repository the handlers actually write to). The engine implicitly assumes these are the same repository, but nothing enforces it.

### Impact Explanation
This is a cross-tenant / cross-repository write: an entity that is only trusted (and only possesses a valid HMAC secret) for organization A's webhooks can forge events that are processed as belonging to organization B's repository, as long as B's repository/stack is also registered in the same Shipit instance. Depending on the event type this can:
- Trigger `GithubSyncJob`/deploy pipeline sync for a victim stack (`push`),
- Forge commit statuses (`status`),
- Create/archive/unarchive review stacks and alter pull request state tracked by Shipit for a repository the attacker does not own (`pull_request`),
- Create teams/memberships (`membership`).

This matches the "cross-repository writes" Critical-impact category, since Shipit's authorization boundary for webhooks (the per-organization signature) does not correspond to the resource boundary actually mutated (the per-repository record via `full_name`).

### Likelihood Explanation
This requires:
1. A Shipit instance configured with the documented multi-organization GitHub App schema (a supported, documented configuration, not a deviation).
2. The attacker to be a legitimate/unprivileged party for at least one configured organization (e.g., knows or controls that org's own `webhook_secret`, as happens when different tenants/customers each set up their own GitHub App against the same Shipit instance).
3ructive: The victim repository/organization must also be tracked in the same Shipit instance.

Given multi-org support is a first-class, documented feature intended for exactly this "several organizations share one Shipit instance" scenario, likelihood is realistic wherever that feature is used.

### Recommendation
In `WebhooksController#verify_signature`/`#create`, after verifying the signature, re-derive and cross-check that the organization used to select the webhook secret (`repository_owner`) matches the owner embedded in `repository.full_name` (and any `organization.login`) before dispatching to handlers; reject the request (422) on mismatch. Alternatively, resolve the target repository/stack once and use its own configured organization consistently for both the signature check and the handler dispatch, rather than trusting two independently-controlled fields of the same unauthenticated payload.

### Proof of Concept
1. Configure Shipit with two organizations, `AttackerOrg` and `VictimOrg`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. Both orgs have repositories tracked as Shipit `Repository`/`Stack` records (e.g., `attackerorg/attacker-repo` and `victimorg/victim-repo`).
3. Attacker, who legitimately knows `AttackerOrg`'s `webhook_secret` (e.g., because they are the tenant admin who installed that GitHub App), crafts a `push` payload:
```json
{
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "victimorg/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(AttackerOrg_webhook_secret, raw_body)>` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` as `"AttackerOrg"`, fetches `AttackerOrg`'s secret via `Shipit.github(organization: "AttackerOrg")`, and the HMAC checks out — the request passes.
6. `create` dispatches the same payload to `PushHandler`, which resolves the target via `payload.dig('repository', 'full_name')` = `"victimorg/victim-repo"` and enqueues a `GithubSyncJob`/deploy sync for `VictimOrg`'s stack, despite the request never having been authenticated by `VictimOrg`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
