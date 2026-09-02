### Title
Webhook organization used for signature verification is not bound to the repository being written to, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the HMAC `webhook_secret`) used to validate an inbound webhook based on `repository.owner.login` (or `organization.login`), while the handlers that actually act on the payload (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`) resolve the target `Repository`/`Stack` from `repository.full_name` — a separate, independently attacker-controlled field in the same unauthenticated JSON body. Nothing ties these two values together, so in a multi-organization Shipit deployment an attacker who owns a legitimate GitHub App installation (and thus knows its `webhook_secret`) can sign a payload as their own organization while pointing `repository.full_name` at a completely different, victim-owned repository/stack.

### Finding Description
`verify_signature` computes the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

It then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, which only checks that the HMAC matches the secret configured for that org: [3](#0-2) 

`Shipit.github` looks the app config up purely by the organization name embedded in the very payload being verified: [4](#0-3) 

Once signature verification passes, `create` dispatches the *entire raw payload* to event handlers unchanged: [5](#0-4) 

Those handlers (e.g. `PushHandler`, registered for the `push` event) resolve the `Repository`/`Stack` to act on using `repository.full_name`/owner+name, via `Repository.from_github_repo_name`: [6](#0-5) [7](#0-6) 

The broken binding is: **the organization whose secret authenticated the request (`repository.owner.login`) must equal the organization/repository the handler actually writes to (`repository.full_name`)**. The controller never enforces this — `repository_owner` and `repository.full_name` are read from two independent JSON paths in the same attacker-supplied body, and only the former is checked against a secret.

This is a direct structural analog to the reported `SuperPositions.onlyMinter()` bug: the code authenticates against one identifier (`formImplementationId` / `repository.owner.login`) but the security-relevant action is performed against a different, unchecked identifier (the state registry ID for the actual superform / the actual repository being mutated).

### Impact Explanation
In Shipit's documented multi-organization configuration (`docs/setup.md`, "Using Multiple GitHub Applications" — top-level keys per organization, each with its own `webhook_secret`), any organization/app owner already onboarded to the same Shipit instance can forge webhooks that are attributed to and act on repositories/stacks belonging to a different organization on that instance:
- A forged `status` event can mark an arbitrary commit SHA in a victim stack as `success`, defeating CI-gating checks used before deploys.
- A forged `check_suite` event can trigger `RefreshCheckRunsJob` for a victim stack.
- A forged `push` event can enqueue `GithubSyncJob` with an attacker-chosen `expected_head_sha` for a victim stack, influencing what Shipit considers the deployable HEAD.

Together these primitives can be chained to make Shipit believe an attacker-chosen, non-reviewed commit in a victim's repository has passing CI status, directly undermining the safety checks that gate an "unauthorized deploy" — matching this program's High-severity criterion.

### Likelihood Explanation
Exploitability requires: (1) the instance uses the multi-organization GitHub App configuration (a documented, supported setup), and (2) the attacker controls at least one of the configured organizations/apps (i.e., knows one org's `webhook_secret`) while a victim stack for a different org exists on the same instance. This is a realistic scenario for shared/hosted Shipit deployments serving multiple organizations, which is exactly the use case the multi-org feature exists for.

### Recommendation
Bind the authenticated organization to the resource being mutated: after computing `repository_owner`/verifying the signature, require that the repository/stack resolved by any handler (via `repository.full_name` or `organization.login`) belongs to that same authenticated organization, rejecting the webhook (422) on mismatch. Concretely, pass the verified `repository_owner` into `Webhooks.for_event(event)` handlers (or re-derive and compare `repository['owner']['login']` against `repository['full_name'].split('/').first`) before any `Repository`/`Stack` lookup is performed.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `attacker-org` (attacker controls the GitHub App/installation and therefore knows its `webhook_secret`) and `victim-org` (has a tracked stack, e.g. `victim-org/victim-repo`).
2. Attacker crafts a `status` (or `push`/`check_suite`) webhook JSON body where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `sha` = the victim commit the attacker wants to fake CI status for, `state = "success"`
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` as `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and successfully verifies the signature using the attacker's own known secret — see `app/controllers/shipit/webhooks_controller.rb#L24-L30` and `lib/shipit/github_app.rb#L76-L83`.
5. `StatusHandler` (registered under `'status'`) processes the payload and records the status against `victim-org/victim-repo`'s commit using `repository.full_name`, unaware that the request was authenticated for `attacker-org`, not `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks.rb (L6-22)
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
```
