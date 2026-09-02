### Title
Webhook signature check authenticates the payload's `organization`/`repository.owner`, but event handlers act on an unrelated `repository.full_name` field, letting a webhook signed for one GitHub org write to another org's stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), a field taken from the untrusted, attacker-controlled webhook body itself. [1](#0-0)  The event handlers that subsequently act on the same payload identify the target `Stack`/`Repository` using a *different* field, `repository.full_name`, which is never checked for consistency with the field used to select the signing secret. [2](#0-1)  This breaks the implicit binding "the organization whose secret authenticated the request" == "the repository that gets written to."

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and uses it to pick the GitHub App/secret: `Shipit.github(organization: repository_owner)`. [1](#0-0) 

Additionally, `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatically valid:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 
In a multi-organization configuration (`Shipit.github_organizations` / `github_app_config`), each organization can independently define (or omit) its own `webhook_secret`. [4](#0-3)  If any onboarded organization has no `webhook_secret` configured, requests whose `repository.owner.login`/`organization.login` names that organization bypass HMAC verification entirely — no signature, secret, or credential is required at all.

Once past `verify_signature`, `WebhooksController#create` dispatches to handlers unconditionally: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [5](#0-4)  `Handler#stacks`/`#repository_name` resolve the target purely from `payload.dig('repository', 'full_name')`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`repository.owner.login` (used to select/bypass the secret) and `repository.full_name` (used to select the stack that is mutated) are two independent JSON fields inside the same attacker-supplied body — nothing cryptographically or logically ties them together. `PushHandler` triggers `stack.sync_github(expected_head_sha:)` on whatever stack `repository.full_name` resolves to, [6](#0-5)  and `StatusHandler` writes a GitHub commit status straight onto matching commits from `Commit.where(sha: params.sha)` for any stack, again located independently of `repository.owner.login`. [7](#0-6) 

### Impact Explanation
An attacker who crafts a webhook body where `organization.login`/`repository.owner.login` names any organization onboarded to this Shipit instance without a configured `webhook_secret` (or an organization whose secret they happen to know) can set `repository.full_name` to an entirely different, victim organization's repository. Because the target-resolution logic never re-checks the owner/organization field, the forged event is processed against the victim stack:
- A forged `status` event can mark arbitrary commits on a victim's stack as `success`, satisfying CI-status gating and enabling an **unauthorized deploy** through Shipit's merge/deploy pipeline.
- A forged `push` event can force `GithubSyncJob` to run against a victim stack, causing Shipit to fetch and register commits/refs unexpectedly for that stack.

This matches the "unauthorized deploy" / cross-repository-write class of impact, achievable without a Shipit session, `ApiClient` token, or any organization's genuine webhook secret when one onboarded organization omits `webhook_secret`.

### Likelihood Explanation
Requires only network access to `POST /webhooks` (mounted unauthenticated by design, per `WebhooksController < ActionController::Base` with no `before_action` requiring a session) and knowledge of any organization name onboarded to the instance that lacks a configured `webhook_secret`, or possession of a legitimately obtained secret for one's own low-value org while targeting an unrelated org's repository. No repository write access, GitHub App private key, or Shipit account is needed.

### Recommendation
Bind the authenticated organization to the field actually used for routing: after `verify_signature` succeeds, require that `repository.owner.login` (or `organization.login`) used for secret selection equals the owner segment of `repository.full_name` before invoking any handler, and reject the request otherwise. Additionally, make `webhook_secret` presence mandatory (fail closed) for every configured organization rather than defaulting to `return true unless webhook_secret`.

### Proof of Concept
1. Configure two organizations in `secrets.github`: `victim-org` (with a `webhook_secret`) and `attacker-org` (onboarded but with `webhook_secret` left blank/unset), both referenced through `Shipit.github_organizations`.
2. POST to `/webhooks` with header `X-Github-Event: status` and no (or arbitrary) `X-Hub-Signature`, and body:
```json
{
  "organization": { "login": "attacker-org" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success"
}
```
3. `verify_signature` resolves `repository_owner` to `attacker-org`, whose missing `webhook_secret` makes `verify_webhook_signature` return `true` unconditionally. [3](#0-2) 
4. `StatusHandler#process` then looks up `Commit.where(sha: params.sha)` and marks it `success` regardless of the fact that the request was only "authenticated" for `attacker-org`, not `victim-org`. [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
