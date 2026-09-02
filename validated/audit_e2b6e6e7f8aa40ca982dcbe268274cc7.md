### Title
Webhook signature verification is keyed off an attacker-controlled organization field that is decoupled from the repository the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify the inbound HMAC signature against using an attacker-supplied field in the unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`), while every event `Handler` resolves the repository/stack to mutate from a *different* field in the same body: `repository.full_name` [1](#0-0) [2](#0-1) [3](#0-2) . This is structurally the same class of bug as the PixelSwap report: a field that gates the "cost"/security-check (which secret authorizes the message) is not the same field that determines the "target" the operation is executed against, so an attacker can point the authorized field at a low/no-security context while pointing the acted-upon field at a fully protected one.

### Finding Description
`Shipit::GitHubApp#verify_webhook_signature` explicitly treats an unconfigured webhook secret as an automatic pass: `return true unless webhook_secret` [4](#0-3) . In the documented multi-organization configuration, each organization has its own independent GitHub App config, and `webhook_secret` is explicitly called out as optional per app: "Webhook secret (optional): Fill it with some randomly generated string..." [5](#0-4) , and the multi-org schema shows a `webhook_secret:` key per organization that can be left blank [6](#0-5) .

`WebhooksController#verify_signature` picks the GitHub App instance to verify against using `repository_owner`, which is read straight out of the unauthenticated POST body before any signature check occurs: `github_app = Shipit.github(organization: repository_owner)` and `repository_owner` = `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) . `Shipit.github` resolves that organization's independent config via `github_app_config(organization)` [7](#0-6) .

Once `verify_signature` passes, the raw `params` are dispatched unchanged to the registered handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [8](#0-7) . Every handler resolves the target repository/stack via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` - a completely independent field from the one used for signature-org selection [3](#0-2) . This is used by, e.g., `PushHandler#process` to sync a stack's git state [9](#0-8) , `CheckSuiteHandler#process` to schedule check-run refreshes [10](#0-9) , and `PullRequest::ClosedHandler#process` to archive review stacks via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [11](#0-10) .

**Binding broken (as an equality):** the engine implicitly assumes
`organization used to authenticate the webhook (repository.owner.login / organization.login)` == `organization owning the repository the handlers mutate (repository.full_name)`.
Before the attacker's request, in legitimate GitHub-delivered traffic these two are always consistent because GitHub itself populates and signs the whole payload atomically. After the attacker's crafted request, they diverge: the attacker sets `repository.owner.login` (or `organization.login`) to any organization configured in `Shipit.secrets.github` that has `webhook_secret` unset/blank (an explicitly supported, documented configuration), which makes `verify_webhook_signature` return `true` unconditionally, while setting `repository.full_name` to the full name of a *different*, fully protected organization/repository that has real stacks configured in Shipit.

### Impact Explanation
This is an authentication bypass: the raw-body/signature check in `WebhooksController#verify_signature` [12](#0-11)  can be defeated for any repository in the Shipit instance as long as any one organization in a multi-org deployment omits its `webhook_secret`. Once bypassed, an unauthenticated network attacker can inject forged `push`, `check_suite`, `status`, `pull_request`, and `membership` events (`Shipit::Webhooks::EVENTS`-equivalent handlers registered) targeting arbitrary protected repositories/stacks, e.g. forcing `Stack#sync_github` (push events), fabricating commit statuses (`StatusHandler`), archiving review stacks (`PullRequest::ClosedHandler`), or manipulating team membership (`MembershipHandler`). Depending on continuous-deployment configuration and the exact handler chain reached, this can escalate to triggering deploys/merges against a protected stack without any credential — matching the "unauthenticated read of stack state" / "unauthorized deploy or merge" High/Critical impact bar.

### Likelihood Explanation
Likelihood is contingent on the operator running the documented multi-organization configuration (`docs/setup.md`, "Using Multiple GitHub Applications") with at least one organization's `webhook_secret` left blank — which the setup guide explicitly presents as an acceptable/optional field, so it is a realistic real-world configuration, not a contrived edge case. Given that configuration, no credentials, tokens, or GitHub access are required at all — the attacker only needs to `POST` a crafted JSON body to the public `/webhooks` endpoint, which is unauthenticated by design (this is the very endpoint that must be internet-reachable to receive GitHub webhooks).

### Recommendation
- Never treat a missing `webhook_secret` as "signature verification passes"; require an explicit secret per configured GitHub App/organization, or reject the webhook with a `422`/log alert if none is configured, rather than silently trusting it (`return true unless webhook_secret` in `lib/shipit/github_app.rb`).
- Do not select the verification key from unauthenticated payload content. Bind webhook routes to a fixed, statically-configured organization at the routing/controller level (or verify the signature against *all* configured secrets and reject unless one matches) so the value used to authorize the message cannot diverge from the value later used to select the mutated repository.
- After verifying the signature, cross-check that `repository.owner.login` (used for authentication) and `repository.full_name`'s owner segment (used by `Handler#repository_name`) refer to the same organization before dispatching to handlers.

### Proof of Concept
Preconditions: Shipit configured with the multi-org schema, e.g.:
```yaml
production:
  github:
    open-org:
      app_id: 1
      installation_id: 1
      webhook_secret:      # left blank, per docs "(optional)"
    victim-org:
      app_id: 2
      installation_id: 2
      webhook_secret: "s3cr3t"
```
`victim-org/victim-repo` has a Shipit stack configured with continuous deployment or review stacks.

Attacker sends, with no `X-Hub-Signature` (or an arbitrary garbage one), directly to `POST /webhooks`:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "open-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
with header `X-Github-Event: push`.

Trace:
1. `repository_owner` resolves to `"open-org"` [2](#0-1) .
2. `Shipit.github(organization: "open-org")` loads the `open-org` config, whose `webhook_secret` is blank [13](#0-12) .
3. `verify_webhook_signature` returns `true` immediately because `webhook_secret` is blank, regardless of the actual signature header [4](#0-3) .
4. The request is dispatched to `PushHandler`, which resolves the target via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` [14](#0-13) , and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's real, protected stack [9](#0-8)  — with zero valid authentication for `victim-org`.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L188-209)
```markdown
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
