### Title
Webhook signature verification keys off an attacker-controlled `repository.owner.login`/`organization.login` field that is decoupled from the `repository.full_name` actually acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App configuration (and therefore which `webhook_secret`) is used to validate the HMAC signature based on `repository_owner`, a value read directly out of the unverified JSON body. Every webhook handler, however, resolves the actual `Repository`/`Stack` to act on from a *different* JSON field, `repository.full_name`. Because the raw body is fully attacker-controlled prior to verification, these two fields can be made to disagree, exactly analogous to the Uniswap report's core flaw: a value trusted for one purpose (reserve state / which secret authorizes the call) is not the same value the privileged action actually consumes (the pair's real reserves / the real target repository).

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:

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

`repository_owner` selects the `GitHubApp` instance (and thus the `webhook_secret`) used to compute the expected HMAC, via `Shipit.github(organization:)`:

```ruby
def github(organization: github_default_organization)
  if github_default_organization.nil?
    config = secrets.github
  else
    config = github_app_config(organization)
    raise GithubOrganizationUnknown, organization if config.nil?
  end
  @github[organization] ||= GitHubApp.new(organization, config)
end
``` [2](#0-1) 

In `GitHubApp#verify_webhook_signature`, if that organization's config has no `webhook_secret` set, verification is a no-op that always returns `true`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

The setup docs explicitly describe `webhook_secret` as *optional*, so in real multi-organization deployments (`docs/setup.md`'s "Using Multiple Github Applications" section) it is plausible that at least one configured organization omits it.

Meanwhile, every handler that performs a privileged, state-changing action resolves the *actual* repository/stack independently, from `repository.full_name`, a completely separate JSON path that GitHub itself keeps consistent with `repository.owner.login` but that an attacker forging the raw POST body does not have to:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

For example `PushHandler` uses this to trigger `stack.sync_github`:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

And PR handlers use `params.repository.full_name` to archive/unarchive/create review stacks: [6](#0-5) 

**Binding broken:** `organization authenticated by verify_signature` (derived from `repository.owner.login`/`organization.login`) **≠** `repository whose Stack/ReviewStack state is written` (derived from `repository.full_name`). Before the attacker's request, only webhooks whose HMAC matches the target repo's real organization secret can trigger these actions. After a crafted request where `repository.owner.login` names an organization with no `webhook_secret` configured while `repository.full_name` names a victim repository belonging to a different, properly-secured organization, `verify_webhook_signature` short-circuits to `true`, and the handler proceeds to sync/archive/create state for the victim's stack — with no valid signature from the victim organization ever presented.

### Impact Explanation
This lets an unauthenticated attacker forge GitHub webhook events (push, pull_request opened/closed/labeled, status, check_suite, membership) that act on stacks belonging to a fully-secured GitHub organization, as long as any other organization configured in the same Shipit instance has no `webhook_secret` set. Consequences include: triggering `sync_github` (forcing arbitrary revision sync) and provisioning/archiving/unarchiving review stacks — an unauthorized manipulation of deploy-relevant state — which maps to the "unauthorized deploy" / authentication-bypass class of impact called out by the rules, since it bypasses the intended per-organization webhook authentication boundary entirely.

### Likelihood Explanation
Requires only that a Shipit deployment configures multiple GitHub organizations (`docs/setup.md`'s documented multi-org scheme) and that at least one of them leaves `webhook_secret` unset (explicitly documented as optional). No credentials, session, or repository write access are needed — only knowledge of one lax organization's name and the ability to POST to the public `/webhooks` endpoint.

### Recommendation
Verify the webhook signature using a secret keyed by the same field the handlers use to resolve the acted-upon repository (`repository.full_name`'s owner), not a separately-read field, and reject events where `repository.owner.login`/`organization.login` disagree with the owner segment of `repository.full_name`. Additionally, do not allow `verify_webhook_signature` to trivially return `true` for organizations lacking a `webhook_secret` when other configured organizations do have one — require all configured organizations to set a secret, or fail closed.

### Proof of Concept
1. Shipit is configured with two organizations: `victim-org` (has `webhook_secret` set) and `no-secret-org` (has no `webhook_secret`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "organization": {"login": "no-secret-org"},
  "repository": {"owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo"},
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. `repository_owner` resolves to `"no-secret-org"`; `Shipit.github(organization: "no-secret-org")` returns a `GitHubApp` with no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. `PushHandler` looks up `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `victim-org`'s stack — a forged, unauthenticated action against an organization the attacker never proved a valid signature for.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
