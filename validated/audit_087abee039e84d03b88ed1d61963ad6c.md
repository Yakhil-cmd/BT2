### Title
Webhook signature verification is keyed to `repository.owner.login`/`organization.login` while every event handler acts on the independent `repository.full_name` field, allowing forged events for any tracked stack once any configured GitHub App lacks a `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` config (and thus which `webhook_secret`) to validate a request against using `repository_owner`, derived from `params.dig('repository','owner','login')` or `params.dig('organization','login')` [1](#0-0) . Every downstream event handler, however, resolves the actual `Repository`/`Stack` to act on from a completely different field in the same attacker-suppliable JSON body: `payload.dig('repository', 'full_name')` [2](#0-1) . `GitHubApp#verify_webhook_signature` trivially returns `true` when the resolved org's `webhook_secret` is blank/unset: `return true unless webhook_secret` [3](#0-2) . Shipit explicitly supports multi-organization GitHub App configuration where `webhook_secret` is optional per org [4](#0-3) , and the setup docs mark `webhook_secret` as optional [5](#0-4) .

### Finding Description
The binding that should hold is: **organization authenticated by the signature check == organization/repository actually written by the handler**. It does not.

- `verify_signature` picks the verifying secret using `repository.owner.login` (or `organization.login`) taken from the unauthenticated `request.raw_post` before any cryptographic check has occurred [6](#0-5) .
- If that particular org entry in the (potentially multi-tenant) GitHub App config has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, regardless of the `X-Hub-Signature` header's validity [3](#0-2) .
- After "verification" passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers against the same JSON body, but they never re-check `repository.owner.login`; they look up the target repo purely via `repository.full_name` [7](#0-6) [2](#0-1) .

Consequently, an unprivileged, unauthenticated network attacker who knows (from the installation's own public setup, e.g. a low-security demo/staging org in a multi-org deployment) that one configured organization has no `webhook_secret`, can craft a raw POST to `/webhooks` where `repository.owner.login`/`organization.login` = the no-secret org (to sail through `verify_signature`) while `repository.full_name` = any other tracked repository entirely unrelated to that org (e.g. a security-sensitive production stack protected by a real, secret-bearing GitHub App). Every registered handler — `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, `MembershipHandler` — will act on the forged event as if it legitimately originated from GitHub for that target repository [8](#0-7) .

### Impact Explanation
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matching branch [9](#0-8) , letting the attacker force a `GithubSyncJob` against an arbitrary stack.
- `StatusHandler` writes arbitrary CI status (`state`, `description`, `context`) onto any commit by SHA via `commit.create_status_from_github!(params)` [10](#0-9) . On stacks using Continuous Delivery, forging a passing status on a malicious/unreviewed commit can drive `ContinuousDeliveryJob` to trigger an unauthorized deploy, matching the Critical-impact criterion ("unauthorized deploy").
- Because the field used for cryptographic authentication (`repository.owner.login`) is disjoint from the field used to select the write target (`repository.full_name`), this is a genuine break of the required equality: "an organization authenticated versus the repository that is written."

### Likelihood Explanation
Exploitability requires only that at least one organization entry in the deployment's GitHub App configuration have no `webhook_secret` configured — an explicitly supported and documented option, not a misconfiguration outside the app's design [5](#0-4) . No credentials, GitHub App keys, `ApiClient` tokens, or session are needed; the attacker only sends a crafted, unsigned HTTP POST to the public `/webhooks` endpoint. This is fully reachable by an unprivileged external attacker.

### Recommendation
Bind the field used to select the verification secret to the field used by handlers to resolve the target repository — verify the signature using the actual repository's owning organization derived consistently (e.g., resolve `Repository.from_github_repo_name(repository.full_name)` first, then use *that* repository's known/owning organization to pick the `webhook_secret`), and require a non-blank `webhook_secret` for every organization (removing the `return true unless webhook_secret` bypass) rather than allowing per-organization signature verification to be silently skipped.

### Proof of Concept
1. Deploy Shipit with a multi-organization GitHub config: `OrgA` (a low-value/demo org with no `webhook_secret` set) and `OrgB` (the real org owning the tracked production `Repository`/`Stack`), per the supported schema in `lib/shipit.rb#github_app_config` [11](#0-10) .
2. Attacker sends, with no `X-Hub-Signature` header value validity required:
```
POST /webhooks
X-Github-Event: push

{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/production-repo"
  }
}
```
3. `verify_signature` resolves `repository_owner` = `"OrgA"`, loads `OrgA`'s `GitHubApp`, and since `OrgA.webhook_secret` is blank, `verify_webhook_signature` returns `true` immediately regardless of signature [3](#0-2) .
4. `PushHandler` resolves the stack via `payload.dig('repository','full_name')` = `"OrgB/production-repo"` [12](#0-11)  and enqueues `stack.sync_github(expected_head_sha: ...)` for `OrgB`'s production stack, entirely bypassing `OrgB`'s actual, properly-configured webhook secret.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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
