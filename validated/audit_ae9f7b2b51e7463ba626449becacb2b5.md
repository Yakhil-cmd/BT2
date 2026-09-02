### Title
Cross-organization webhook forgery via mismatched signature-selection key and repository-resolution key - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which GitHub App / `webhook_secret` to verify an inbound webhook's HMAC signature against using `repository.owner.login` from the JSON payload, but every webhook `Handler` resolves the `Repository`/`Stack` to act on using an entirely different payload field, `repository.full_name`. Because these two fields are never cross-validated against each other, a customer/tenant who legitimately knows their own organization's `webhook_secret` (a normal, expected credential for a multi-tenant Shipit installation with per-organization GitHub Apps) can forge a payload whose `owner.login` matches their own org (so it authenticates) while `full_name` points at a completely different tenant's tracked repository, causing Shipit to act on that other organization's stacks.

### Finding Description
`Shipit.github(organization:)` and `Shipit.github_app_config` (`lib/shipit.rb`) support configuring one `webhook_secret` per GitHub organization when using the multi-app schema: [1](#0-0) 

`WebhooksController#verify_signature` picks which of these per-organization secrets to verify against solely from the payload's `repository.owner.login` (or `organization.login`), then verifies the raw HMAC over the whole request body: [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` only proves that *some* body was signed with the secret associated to whatever `repository_owner` claims — it establishes nothing about which repository the body's other fields describe: [4](#0-3) 

Once the signature check passes, `create` dispatches the *entire, attacker-controlled* JSON body to the event handlers: [5](#0-4) 

Every default handler, however, determines *which* `Repository`/`Stack` to mutate purely from `repository.full_name`, a field that is completely independent of `repository.owner.login`: [6](#0-5) 

For example, the push handler triggers a GitHub sync job (which schedules deploy-relevant work) on whichever stacks match `repository.full_name`: [7](#0-6) 

The same pattern (`Repository.from_github_repo_name(params.repository.full_name)`) is used by the pull-request handlers to archive/unarchive Review Stacks belonging to whatever repository `full_name` names, again with no relationship enforced to the organization whose secret authenticated the request: [8](#0-7) [9](#0-8) 

The trust binding that the engine implicitly relies on is: `organization authenticated by verify_signature (repository.owner.login) == organization owning the repository acted on (owner prefix of repository.full_name)`. For genuine GitHub-generated payloads these are always equal because both fields come from the same GitHub `repository` object. But since the entire JSON body is attacker-supplied prior to signing, an attacker who legitimately administers Organization A's GitHub App (and therefore legitimately knows Organization A's `webhook_secret`, exactly as intended by Shipit's multi-tenant design) can set `repository.owner.login = "orgA"` (so `verify_signature` picks and validates against Org A's secret) while setting `repository.full_name = "orgB/some-tracked-repo"` (a repository belonging to a different tenant, Org B, also hosted on the same Shipit instance). The HMAC still validates because it is computed over the exact bytes sent, and nothing downstream re-checks that `full_name`'s owner segment equals the authenticated `repository_owner`.

### Impact Explanation
This breaks Shipit's multi-tenant isolation between organizations that each run their own GitHub App against a shared Shipit deployment. A tenant possessing only their own webhook secret can trigger cross-organization writes/state changes normally gated behind another organization's GitHub webhook trust boundary: forcing `GithubSyncJob`s on another org's stacks, archiving/unarchiving/creating that org's PR-based review stacks, or injecting `membership`/`status` events attributed to a different organization's repositories — all without any credential belonging to that other organization. This matches the "cross-repository writes" / authorization-escalation class of impact.

### Likelihood Explanation
Likelihood is high in any Shipit deployment that uses the documented multi-organization GitHub App configuration (`config/secrets.*.yml` `github: <org>: webhook_secret: ...`), which is a first-class, documented feature. Any tenant onboarded with their own GitHub App inherently possesses the one piece of information (their own `webhook_secret`) needed to mount the attack; no additional privilege, session, or stolen secret is required beyond what every legitimate tenant is issued.

### Recommendation
Cross-validate that the organization used to select the verifying `webhook_secret` matches the organization implied by every repository-identifying field the handlers subsequently use (e.g., require `repository.full_name.split('/').first == repository_owner`, or bind each `Repository`/`Stack` record to the organization key that authenticated it and reject/ignore events where they disagree) before dispatching payloads to `Shipit::Webhooks` handlers.

### Proof of Concept
1. Deploy Shipit with two GitHub Apps configured under `secrets.github`, one for `orgA` (attacker-controlled, webhook secret known to attacker) and one for `orgB` (victim, with tracked repository `orgB/victim-repo`).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(orgA_webhook_secret, body)>` using their own known Org A secret and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` to `"orgA"`, fetches Org A's `GitHubApp`, and validates the signature successfully (`lib/shipit/github_app.rb:76-83`).
5. `create` dispatches the parsed body to `PushHandler`, which resolves the target purely via `repository.full_name` = `"orgB/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), scheduling a `GithubSyncJob` against Org B's stack even though the request was never signed by Org B's secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L55-62)
```ruby
    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
