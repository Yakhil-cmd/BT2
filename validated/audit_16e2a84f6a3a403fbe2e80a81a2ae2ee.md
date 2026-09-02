### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while event handlers dispatch on `repository.full_name` from the same untrusted payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate the incoming webhook against using `repository_owner`, derived from the attacker-supplied JSON body (`repository.owner.login` or `organization.login`). [1](#0-0) [2](#0-1)  Once the signature check passes, the actual event handler resolves the target `Repository`/`Stack` using a *different* field pulled from the very same payload: `repository.full_name`. [3](#0-2)  Nothing ties the organization whose secret authenticated the request to the repository that the handler actually acts on.

### Finding Description
The controller picks the GitHub App configuration to verify against like this:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

`Shipit.github(organization:)` looks up a per-organization app config (`app_id`, `webhook_secret`, `private_key`, etc.) from `secrets.github`, one entry per configured GitHub org. [5](#0-4)  `GitHubApp#verify_webhook_signature` explicitly treats an unset `webhook_secret` as automatically verified: `return true unless webhook_secret`. [6](#0-5) 

Once `create` proceeds, every `Handler` subclass (push, pull_request, etc.) resolves its target repository/stack independently, from `payload.dig('repository', 'full_name')` — not from `repository_owner`:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

Handlers such as `PushHandler` then act directly on whatever stacks match that `full_name`, e.g. triggering `stack.sync_github(expected_head_sha: params.after)`. [7](#0-6)  Pull-request handlers similarly resolve `repository` purely from `params.repository.full_name` and then archive/unarchive stacks, update pull-request state, etc. [8](#0-7) [9](#0-8) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository) are two independently attacker-controlled fields of the same unauthenticated JSON body, an attacker who has access to **any** configured GitHub organization's webhook secret (e.g. because they administer their own low-trust org that is also onboarded into this Shipit instance, or because that org was configured with a blank `webhook_secret` as the setup docs show is a valid/default configuration) can:

1. Set `X-Github-Event` and craft a body signed with (or requiring no) secret for organization `org-with-secret`, i.e. `repository.owner.login = "org-with-secret"`.
2. Set `repository.full_name = "victim-org/victim-repo"` in the same body.
3. `verify_signature` authenticates the request against `org-with-secret`'s (possibly blank) secret and passes.
4. The dispatched handler (`push`, `pull_request`, `status`, etc.) resolves the actual `Repository`/`Stack` via `repository.full_name`, which points at `victim-org/victim-repo` — an entirely unrelated, higher-trust organization/stack the attacker has no legitimate relationship with.

This breaks the intended binding: **organization whose secret authenticated the webhook == organization/repository that the handler writes to**. The two are decoupled because verification and dispatch consult different fields of the same unauthenticated JSON.

### Impact Explanation
This lets an attacker who controls (or has the leaked/blank secret of) one onboarded GitHub organization forge events against a stack belonging to a completely different, victim organization also configured on the same Shipit instance — e.g. forcing `PushHandler` to call `stack.sync_github`, injecting fake commit `status`/`check_suite` events that flip `deployable?`/CI gating and can trigger continuous deployment (`ContinuousDeliveryJob`), or manipulating pull-request-driven review-stack archival/provisioning for a repository they don't own. This is an escalation into deploy/CD state for a repository the attacker was never granted write access to, matching the "unauthorized deploy" / cross-repository-write class of impact.

### Likelihood Explanation
Requires the Shipit instance to host multiple GitHub organizations (a documented, supported configuration — see `config/secrets.development.example.yml`'s multi-org schema) and for at least one of them to have a weak/blank `webhook_secret` or for the attacker to otherwise possess a valid secret for one onboarded org. Given `GitHubApp#verify_webhook_signature` explicitly permits blank secrets, and multi-tenant onboarding is an advertised feature, this is a realistic misconfiguration-adjacent but code-enabled condition rather than a purely theoretical one.

### Recommendation
After successfully verifying the webhook signature for `repository_owner`, re-derive and enforce that `repository_owner` matches the owner segment of `repository.full_name` (and any `organization.login`) before dispatching to handlers, or better, have `Handler#stacks`/`repository_name` explicitly scope lookups to the authenticated organization rather than trusting `full_name` in isolation. Additionally, consider rejecting webhooks for organizations without a configured `webhook_secret` rather than treating a blank secret as automatically verified.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `org-a` (attacker-controlled, blank `webhook_secret`) and `org-b` (victim, tracked stack `org-b/app`).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/app" }
}
```
3. `repository_owner` resolves to `org-a`; `verify_webhook_signature` returns `true` because `org-a`'s `webhook_secret` is blank.
4. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("org-b/app")`, matching the victim stack, and calls `stack.sync_github(expected_head_sha: ...)` — an action on `org-b`'s stack triggered by a request authenticated only against `org-a`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
