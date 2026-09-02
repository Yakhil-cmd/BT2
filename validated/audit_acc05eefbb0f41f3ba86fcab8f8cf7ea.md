## Analysis

This confirms a valid analog. In a multi-organization Shipit deployment (`Shipit.github_organizations` / `github_app_config`, documented in `docs/setup.md`), each organization has its own GitHub App with its own `webhook_secret` [1](#0-0) . The webhook signature is verified against the organization derived from `repository.owner.login` (falling back to `organization.login`) — a field taken directly from the unverified/pre-verification JSON body [2](#0-1) [3](#0-2) . However, once the signature check passes, the actual event handler that mutates state resolves the target `Repository`/`Stack` using a *different* field from the same payload: `repository.full_name` [4](#0-3) .

Because `repository.owner.login` (used to select which org's secret verifies the signature) and `repository.full_name` (used to select which repository's Stack is acted upon) are two independent, attacker-controlled fields inside the same signed JSON body, an attacker who legitimately controls one organization's GitHub App/webhook secret in the deployment can forge a signature for a payload whose `owner.login` names their own org, while `full_name` names a victim organization's repository. This breaks the intended equality binding **"organization that authenticated" == "repository that is written."**

### Title
Webhook signature verification binds to `repository.owner.login`/`organization.login` while handlers act on the independently-controlled `repository.full_name`, allowing cross-organization forged events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the HMAC secret) used to validate `X-Hub-Signature` based on `repository.owner.login` (or `organization.login`) taken straight from the JSON body [5](#0-4) [3](#0-2) . All downstream `Webhooks::Handlers::Handler` subclasses (push, status, membership, check_suite, pull_request) instead resolve the target `Repository`/`Stack` using `repository.full_name` from the same body [4](#0-3) . Nothing enforces that `full_name`'s owner segment matches `owner.login`, so the field that authorizes the request and the field that determines its effect are decoupled.

### Finding Description
In a multi-org configuration (`config/secrets.yml` keyed per organization, each with its own `webhook_secret`) [6](#0-5) , `Shipit.github(organization:)` looks up the app/secret for the org named in the payload [7](#0-6) . The controller uses this org purely to fetch the secret for HMAC validation of the raw body [8](#0-7) , but the *handler* that performs the actual action (creating commit statuses, syncing pushes, managing team memberships, etc.) trusts `repository.full_name` from that same body to pick which `Repository`/`Stack` is mutated [4](#0-3) . Since `owner.login` and `full_name` are independent JSON keys inside one payload, and the entire payload is signed as a single blob, a party that legitimately controls organization A's webhook secret can still produce a payload where `owner.login = "org-A"` (to pass signature verification) and `full_name = "org-B/victim-repo"` (to target another organization's stack entirely).

### Impact Explanation
This crosses the "authenticated org vs. written repository" boundary called out as in-scope: an attacker who administers their own GitHub App installation in a shared multi-org Shipit instance can forge webhook events (push, status, membership, check_suite) against another organization's stacks — e.g., injecting fake commit statuses via `StatusHandler#process` that satisfy CI-gating checks before a deploy [9](#0-8) , or triggering `sync_github` on a victim stack via `PushHandler#process` [10](#0-9) . Forged/soft-passing CI statuses can feed into merge-queue/deploy gating decisions, constituting an unauthorized deploy/rollback pathway — meeting the Critical impact bar.

### Likelihood Explanation
Requires the deployment to run Shipit's documented multi-org configuration and requires the attacker to control one organization's own legitimate GitHub App webhook secret in that shared instance (not privileged access to Shipit itself, nor to the victim org) — a realistic scenario for shared/managed Shipit installs serving multiple client orgs.

### Recommendation
After signature verification, re-derive the organization from `repository.full_name` (or `organization.login`) that the handler will actually act on, and reject the request (422) if it does not match the organization whose secret validated the signature, i.e., enforce `verified_organization == repository_full_name_owner` before dispatching to `Shipit::Webhooks.for_event(event)`.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `org-A` and `org-B`, each with distinct `webhook_secret`s (per `docs/setup.md` multi-org schema).
2. As an operator/owner of `org-A`'s installed GitHub App, compute a valid `X-Hub-Signature` for a `status` (or `push`) JSON payload using `org-A`'s known `webhook_secret`, but set:
   - `repository.owner.login = "org-A"`
   - `repository.full_name = "org-B/victim-repo"`
3. POST to `/webhooks` with `X-Github-Event: status` and the forged signature.
4. `verify_signature` looks up `Shipit.github(organization: "org-A")` and validates successfully against `org-A`'s secret [2](#0-1) .
5. `StatusHandler#process` resolves commits/stacks via `Repository.from_github_repo_name("org-B/victim-repo")` [4](#0-3)  and writes a forged commit status on `org-B`'s stack, despite the request never having been signed by `org-B`.

### Citations

**File:** lib/shipit.rb (L76-83)
```ruby

  def task_execution_strategy
    @task_execution_strategy ||= Shipit::TaskExecutionStrategy::Default
  end

  self.timeout_exit_codes = [].freeze
  self.respect_bare_shipit_file = true

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

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
