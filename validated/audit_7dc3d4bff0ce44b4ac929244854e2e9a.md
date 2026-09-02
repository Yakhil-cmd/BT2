### Title
Cross-organization webhook signature confusion allows unauthorized writes to another org's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC `webhook_secret`) to verify a webhook against using a field (`repository.owner.login`, falling back to `organization.login`) taken directly from the unauthenticated, attacker-supplied JSON body. Separately, the event handlers (e.g. `PushHandler`) resolve the `Repository`/`Stack` to mutate using a *different* field of the same attacker-supplied body: `repository.full_name`. Because these two lookups are not cryptographically bound to each other, an attacker who can produce a validly-signed payload for one configured GitHub organization can point the write-side lookup at a repository belonging to a completely different organization.

### Finding Description
In a multi-organization Shipit deployment (`Shipit.github_organizations`, `Shipit.github_app_config`), each organization has its own `GitHubApp` instance and its own `webhook_secret`: [1](#0-0) 

The webhook controller determines which organization's secret to check with using only the raw JSON body, before any signature has been validated: [2](#0-1) 

`verify_webhook_signature` explicitly treats a blank `webhook_secret` as automatically valid: [3](#0-2) 

and the setup docs confirm the webhook secret is documented as optional per-organization: [4](#0-3) 

Meanwhile, the actual repository/stack that gets written to is resolved from a *different* JSON field of the same untrusted body: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is: `organization whose signature verified == organization owning the repository/stack that gets mutated`. Because `repository_owner` (used for auth) and `repository.full_name` (used for the write) are two independently-controlled fields of the same forged POST body, this equality is never enforced. An attacker who obtains (or is issued, e.g. as a bot/webhook operator) valid credentials for *any* configured organization that has `webhook_secret` blank/nil — or who otherwise can produce a signature for organization A — can craft a body whose `repository.owner.login`/`organization.login` is A (satisfying `verify_signature`) but whose `repository.full_name` is `B/some-repo`, targeting stack B, which they have no legitimate access to.

### Impact Explanation
This crosses the "organization authenticated versus repository written" trust boundary described in scope. A successful forgery lets an attacker fire arbitrary webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) against a stack belonging to a different, better-protected GitHub organization/repository hosted on the same Shipit instance — e.g. triggering `GithubSyncJob`/`stack.sync_github` (`PushHandler`), fabricating commit statuses (`StatusHandler`), or manipulating check-run/PR-driven review-stack workflows for a repository the attacker does not control. This is a cross-repository write achieved without possessing that repository's real webhook secret, matching the "cross-repository writes" Critical-impact category.

### Likelihood Explanation
Exploitability depends on the deployment having more than one GitHub organization configured (`Shipit.github_organizations`) and at least one of them having `webhook_secret` unset (explicitly documented as optional), or on the attacker otherwise possessing a valid signature for some org. This is a realistic multi-tenant Shipit configuration, since the docs advertise the webhook secret as optional and multiple orgs are a first-class supported feature (`test/dummy/config/secrets_double_github_app.yml`, `Shipit.github_app_config`). No repository write access, session, or `ApiClient` token is required — only the ability to reach the public `/webhooks` endpoint.

### Recommendation
Do not let the same untrusted payload field set determine both which secret is used for verification and which repository/stack is mutated. Concretely: after selecting the GitHub App by `repository_owner`, re-derive/validate that `repository.full_name`'s owner segment matches the same verified organization (or, better, key the app-secret lookup off `installation_id`/`X-GitHub-Hook-Installation-Target-ID`, which GitHub sends and which is not attacker-writable in the way the JSON body is) before dispatching to handlers such as `PushHandler`/`Handler#stacks`.

### Proof of Concept
1. Shipit is configured with two GitHub App organizations in `secrets.github`: `orgA` (no `webhook_secret` set) and `orgB` (protected, has a real repo/stack tracked in Shipit, e.g. `orgB/secret-app`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/secret-app" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
No `X-Hub-Signature` header is required (or any arbitrary value works) because `Shipit.github(organization: "orgA").verify_webhook_signature` returns `true` unconditionally when `orgA`'s `webhook_secret` is blank: [8](#0-7) 
3. `WebhooksController#create` proceeds to dispatch to `Shipit::Webhooks.for_event('push')`, which invokes `PushHandler`, which resolves the target stack via `Repository.from_github_repo_name("orgB/secret-app")` — not `orgA` — and calls `stack.sync_github(expected_head_sha: ...)`, mutating `orgB`'s stack despite verification only having authenticated `orgA`.

**Uncertainty**: I could not fully verify from the indexed files whether GitHub's `X-GitHub-Hook-Installation-Target-ID` header (an alternative, non-payload-controlled identifier) is used anywhere else in this codebase as a cross-check; the current implementation as shown relies solely on JSON body fields for organization selection. A Devin session with full repository access would be needed to confirm there is no additional binding check elsewhere (e.g. in `Shipit::Webhooks` dispatch) that this scan may have missed.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
