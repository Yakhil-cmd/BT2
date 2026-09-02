### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login` while every event handler acts on `repository.full_name`, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`). But every `Shipit::Webhooks::Handlers::Handler` subclass (used for `push`, `pull_request`, `membership`, `status`, `check_suite`, etc.) resolves the target `Repository`/`Stack` from a completely different field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')`. In a multi-organization Shipit deployment (`config/secrets.*.yml` supports one `webhook_secret` per organization), the field used to pick the verification secret is not the field used to determine which repository/stack is acted upon, breaking the equality "organization whose secret authenticated the request == repository that gets written to."

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
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

This selects the `webhook_secret` from `Shipit.github(organization: repository_owner)`, i.e. `lib/shipit.rb#github_app_config`, keyed strictly by `repository_owner` (org A's login). [2](#0-1) 

However, the base `Handler` class (used by all registered event handlers) resolves the affected repository/stacks from a **different** JSON key of the same request body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

The same divergence exists in the pull-request handlers, which independently re-derive the repository from `params.repository.full_name` rather than the verified `owner.login`: [4](#0-3) 

Because the request body is entirely attacker-controlled (this endpoint is reachable over HTTP and only gated by an HMAC computed over the raw body, not by any structural/consistency check tying `repository.owner.login` to `repository.full_name`), an attacker who knows (or controls) the `webhook_secret` configured for **one** organization in a multi-tenant Shipit install can craft a payload where:
- `repository.owner.login` = `"org-attacker-controls"` (used only to pick the verification secret)
- `repository.full_name` = `"victim-org/victim-repo"` (used by every handler to select the actual `Repository`/`Stack` acted upon)

The HMAC is computed over the full raw body, so the signature will validate correctly against `org-attacker-controls`'s secret even though the payload's semantic content targets `victim-org`'s repository. `verify_signature` never checks that `repository.full_name`'s owner segment matches `repository_owner`.

### Impact Explanation
This breaks the trust boundary between organizations in a multi-tenant Shipit deployment: possession of a valid webhook secret for organization A is treated as authorization to submit events targeting organization B's repositories/stacks. Depending on which handler processes the event, this can:
- Trigger `GithubSyncJob`/`CacheDeploySpecJob` on a victim stack via `PushHandler` (`Stack#sync_github`) [5](#0-4) .
- Archive/unarchive review stacks belonging to a victim repository via `PullRequest::UnlabeledHandler` [6](#0-5) .
- Trigger provisioning of a new review stack (`find_or_create!`) for an arbitrary victim repository via `PullRequest::OpenedHandler` [7](#0-6) .

This is an unauthorized cross-repository/cross-organization write (state mutation triggered on a repository outside the authenticating organization's boundary), matching the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Requires the attacker to control or know a valid `webhook_secret` for at least one configured GitHub organization in the Shipit instance (a normal, lower-privilege tenant in a multi-org deployment) and to send a crafted raw HTTP POST directly to the `/github_hooks` (webhooks) endpoint rather than going through GitHub. No `ApiClient` token, session, or GitHub App private key is required — only knowledge of one organization's `webhook_secret`, which is a value the tenant itself configured/knows for their own GitHub App. This is realistic in shared/multi-tenant Shipit deployments as documented in `docs/setup.md`'s multi-organization `github:` config schema.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the HMAC, additionally validate that the organization used to select the secret matches the owner embedded in `repository.full_name` (and `organization.login` for org-level events), rejecting the request (422) on mismatch. Alternatively, have handlers resolve the repository/stack strictly from the same `repository_owner` value that was cryptographically verified, rather than independently trusting `repository.full_name` from the unauthenticated portion of the payload.

### Proof of Concept
Assume a Shipit instance configured with two GitHub orgs, `attacker-org` (secret known to the attacker) and `victim-org` (target). The attacker (who only needs to know `attacker-org`'s webhook secret) sends:
```
POST /github_hooks
X-Github-Event: pull_request
X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>

{
  "action": "opened",
  "number": 1,
  "pull_request": { "id": 1, "number": 1, "url": "...", "title": "x", "state": "open",
                     "additions": 1, "deletions": 0,
                     "head": {"sha": "aaa", "ref": "feature"},
                     "user": {"login": "attacker"}, "assignees": [], "labels": [] },
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "sender": { "login": "attacker" }
}
```
- `verify_signature` computes `Shipit.github(organization: "attacker-org")` and validates the HMAC against `attacker-org`'s known secret → passes.
- `PullRequest::OpenedHandler#repository` resolves `Repository.from_github_repo_name("victim-org/victim-repo")`, and if that repository has review stacks provisioning enabled, `ReviewStackAdapter#find_or_create!` provisions/acts on a stack under `victim-org`, entirely outside the attacker's authenticated organization boundary.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```
