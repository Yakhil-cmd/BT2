## Analysis

Found a valid analog. The bug-class hint (verification claims a binding it doesn't actually enforce) maps cleanly onto Shipit's webhook signature verification: **the GitHub organization used to select the verifying secret is never cross-checked against the repository/commit that the webhook payload actually mutates.**

### Title
Webhook signature verification binds only the claimed organization, not the repository/commit acted upon, enabling cross-organization status/stack forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to verify a webhook against using `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`). Once the signature check passes, every event handler acts on a *different* field of the same payload — `repository.full_name` (push, pull_request, check_suite handlers) or, worse, a completely unscoped `sha` (status handler) — without ever verifying it matches the organization that the signature was actually validated for.

### Finding Description [1](#0-0) 
`verify_signature` resolves the signing secret via `repository_owner`: [2](#0-1) 

Once verified, `create` dispatches the raw parsed payload to handlers: [3](#0-2) 

Every handler resolves the target repository from a *different* payload field, `repository.full_name`, with no comparison to the `owner.login` used during signature verification: [4](#0-3) 

The `StatusHandler` is the most severe instance: it doesn't scope to a repository at all, it just matches any commit in the entire instance by raw `sha`: [5](#0-4) 

That status is fed straight into deployability logic: [6](#0-5) [7](#0-6) 

In a multi-organization Shipit deployment (explicitly supported and documented), each organization has its own GitHub App and its own `webhook_secret`, set up by whoever administers that org's GitHub App installation: [8](#0-7) [9](#0-8) 

This is the exact binding break the report class describes: the **organization that authenticated** (`repository_owner` → org's webhook secret) is not the same as **the repository/commit that is written** (`repository.full_name` / bare `sha`, unchecked). Any org onboarded onto a shared Shipit instance — i.e., anyone who legitimately knows their own org's `webhook_secret` — can sign an arbitrary payload with their own secret while claiming `repository.owner.login` = their own org (so verification passes), but set `repository.full_name` (or, for `status`, just any `sha`) to point at a stack/commit belonging to a completely different, unrelated organization/repository hosted on the same Shipit instance.

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy" bar explicitly listed as Critical impact:
- Via `StatusHandler`, an attacker can forge a `success` CI status for any commit sha in any stack on the instance (matched purely on `sha`, with zero repository scoping), which flips `Commit#deployable?` and can trigger `ContinuousDeliveryJob` for a stack the attacker has no access to, i.e., an unauthorized deploy of a victim's stack.
- Via `PushHandler`/`CheckSuiteHandler`, an attacker can spoof `repository.full_name` to force a `GithubSyncJob` or check-run refresh against another org's repository/stack, since `Handler#repository_name` is trusted without cross-checking it belongs to the signing org.

### Likelihood Explanation
Any tenant/organization legitimately onboarded to a shared, multi-org Shipit instance already possesses their own valid `webhook_secret` (they configured the GitHub App). No token, session, or repo write access on the *target* org is required — only a POST directly to the webhook endpoint with a payload signed by their own secret but referencing a foreign `repository.full_name`/`sha`. This is a low-effort, unprivileged-relative-to-the-victim-org attack.

### Recommendation
After computing `repository_owner` and verifying the signature, re-derive the acted-upon repository from the same trusted field (or, better, use one canonical field consistently) and reject/ignore any event where `repository.full_name`'s owner segment (or `organization.login`) does not match the organization whose secret validated the signature. For `StatusHandler`, scope the `Commit` lookup by the verified repository/stack rather than a bare global `sha` match.

### Proof of Concept
1. Operator configures two orgs on one Shipit instance: `OrgA` (attacker-administered) and `OrgVictim`, per `docs/setup.md` multi-app config.
2. Attacker, as `OrgA`'s GitHub App admin, knows `OrgA`'s `webhook_secret`.
3. Attacker computes `sha256`/`sha1` HMAC over a crafted JSON body using `OrgA`'s secret, with body:
   - `event: status`, `sha: <victim commit sha>`, `state: success` — no repository field needed at all since `StatusHandler` never checks it, only `repository_owner` (`repository.owner.login`) needs to be `OrgA` to select the right verifying secret.
4. POST directly to `/webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
5. `verify_signature` passes because `repository_owner` resolves to `OrgA` and the signature matches `OrgA`'s secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and marks the victim's commit `success`, potentially triggering an unauthorized continuous deploy of `OrgVictim`'s stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

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
