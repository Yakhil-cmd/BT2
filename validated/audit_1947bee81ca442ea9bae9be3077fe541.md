## Title
Webhook signature check binds only to the claimed organization, not to the repository the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple GitHub Apps/organizations, each with its own `webhook_secret`, keyed by organization in `secrets.github`. [1](#0-0)  `WebhooksController#verify_signature` picks which secret to verify the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [2](#0-1)  The signature itself is a plain HMAC over the *entire* raw request body using that organization's secret. [3](#0-2) 

Because the organization used to *select* the secret and the repository that handlers subsequently act on both come from the same attacker-controlled JSON body, and the signature only proves "this body was signed with organization X's secret" (not "this body concerns organization X's repositories"), anyone who has learned/leaked the webhook secret for *one* configured organization can forge a signed payload whose `repository.full_name` points at a completely different repository/stack, and it will pass `verify_signature`.

### Finding Description
`repository_owner` is derived from the raw, unauthenticated payload:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

This value is used only to look up which `GitHubApp`/secret to validate against:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
``` [5](#0-4) 

`verify_webhook_signature` simply HMACs the *whole raw body* with the secret belonging to whichever organization was named in `repository_owner`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [3](#0-2) 

Once verification passes, the `push` event handler resolves the target stacks/repository from `repository.full_name` in the same body — a field never separately checked against `repository_owner`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
...
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) [7](#0-6) 

`Stack#sync_github` enqueues `GithubSyncJob`, which pulls state from GitHub using the App's own installation credentials and can also feed the continuous-delivery pipeline (`Stack.schedule_continuous_delivery` / `trigger_continuous_delivery`) that automatically triggers deploys once commits carry successful CI statuses. [8](#0-7) [9](#0-8) 

**The broken binding:** `organization authenticated (via webhook_secret lookup) == repository/stack actually written (via `repository.full_name`)`. The signature only proves knowledge of *an* org's secret; it never proves that the org whose secret was used owns the repository named elsewhere in the same payload. In a single-org deployment this is moot because there is only one secret/org, but in the documented multi-org configuration (`secrets.github` keyed by organization, see `github_app_config`) [10](#0-9)  it is a genuine cross-tenant authentication bypass: possession of Org A's webhook secret is sufficient to forge events for Org B's/any other configured repository.

### Impact Explanation
This escalates into unauthenticated write access to stack state for repositories outside the org whose secret the attacker possesses: it can force `GithubSyncJob` runs, poison commit/status caches, and — since `sync_github_if_necessary`/`trigger_continuous_delivery` are wired off of synced commit state — can lead to an unauthorized deploy being scheduled for a stack the attacker has no legitimate relationship with. This falls under the "unauthorized deploy" / cross-repository-write High-impact category defined in the rules.

### Likelihood Explanation
Requires the attacker to already know one organization's `webhook_secret` (e.g., leaked from that org's own third-party integration, compromised CI, or a previous incident) in a Shipit deployment that hosts multiple GitHub organizations/Apps. It does not require any Shipit session, `ApiClient` token, or GitHub App private key — only a single leaked webhook secret from any one tenant. Likelihood is moderate: it depends on multi-tenant configuration and a leaked secret, but the actual forgery step (crafting an arbitrary payload naming another org's repository) is trivial once that precondition is met.

### Recommendation
After computing `repository_owner` and verifying the signature, additionally assert that the resolved GitHub App/organization actually owns the repository referenced elsewhere in the payload (e.g., look up the `Repository`/`Stack` by `full_name` and confirm its configured organization matches `repository_owner`/the app used for verification) before dispatching to any handler. Alternatively, bind webhook secrets to specific repositories/stacks rather than only to organizations, so a leaked secret cannot be replayed against unrelated repositories.

### Proof of Concept
1. Deploy Shipit configured with two GitHub Apps/orgs in `secrets.github`: `orgA` (secret `SECRET_A`) and `orgB` (secret `SECRET_B`), each with stacks configured.
2. Obtain `SECRET_A` (e.g. via a leak unrelated to Shipit itself, such as a misconfigured CI secret store at Org A).
3. Craft a `push` JSON payload with:
   - `repository.owner.login = "orgA"` (so `repository_owner` resolves to `orgA`, and hence `SECRET_A` is used for verification)
   - `repository.full_name = "orgB/some-repo"` and `ref`/`after` pointing at an attacker-chosen SHA for a stack that belongs to Org B.
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(SECRET_A, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` succeeds because it only checked the HMAC against `SECRET_A` for the raw body; it never checked that `orgB/some-repo` is actually owned by `orgA`. [2](#0-1) 
6. `PushHandler#process` resolves stacks from `repository.full_name = "orgB/some-repo"` and calls `stack.sync_github(expected_head_sha: ...)`, forcing a GitHub sync (and potentially a continuous-delivery deploy trigger) for a stack the attacker has no legitimate relationship to. [7](#0-6) 

Note: I was unable to fully verify in the index whether any additional downstream check (outside `app/**`/`lib/shipit/**`, e.g. in `GithubSyncJob`) re-validates that the synced repository belongs to the same organization as the webhook secret used; if such a check exists it would mitigate this finding, but no such check was found in the reviewed webhook/controller/model code path.

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

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```
