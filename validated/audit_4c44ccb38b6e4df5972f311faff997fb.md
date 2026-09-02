### Title
Cross-organization CI status forgery via webhook signature/repository binding mismatch enabling unauthorized deploy - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The reported bug class is "value acted on doesn't match the value that was verified" (LP tokens tracked vs. collateral actually deposited). The analogous flaw in Shipit is that the webhook signature verification is bound to the `repository.owner.login` (or `organization.login`) field of the payload, used solely to pick which GitHub App/`webhook_secret` validates the HMAC — but the code that actually *acts* on the payload (`StatusHandler`) never re-checks that the commit/repository being mutated belongs to that same, verified organization. This breaks the equality that should hold: `organization that authenticated == organization/repository whose state is written`.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config (and thus the `webhook_secret` used for HMAC verification) purely from the attacker-controlled `repository_owner` field of the JSON payload: [1](#0-0) [2](#0-1) 

This only proves the request was signed with *some* organization's configured secret — it does not, and cannot, prove which repository/commit the payload's other fields refer to. Shipit explicitly supports multiple, independently-configured GitHub Apps/organizations sharing this single `/webhooks` endpoint: [3](#0-2) 

Downstream, `StatusHandler#process` acts on the payload's `sha` field with **no scoping to the verified organization or even to `repository.full_name`** — it queries commits globally across the entire Shipit installation: [4](#0-3) 

Contrast this with the base `Handler` class, which does have a `repository_name`/`stacks` scoping helper used by other handlers (e.g. `PushHandler`, `CheckSuiteHandler`), but `StatusHandler` bypasses it entirely: [5](#0-4) 

The created `Status` record directly feeds `Commit#deployable?`, which is the safety gate used by manual deploys, the deploy API, and continuous delivery: [6](#0-5) [7](#0-6) 

**Equality broken:** `organization whose webhook_secret authenticated the request` should equal `organization/repository whose commit status (and therefore deployability) is mutated`. Because `StatusHandler` never checks `repository.full_name`/organization ownership of the target commit, any organization configured in Shipit can forge a `success` status for a commit belonging to a *different* organization's stack.

### Impact Explanation
An attacker who controls (or is an admin of) any one GitHub organization/App configured in a multi-org Shipit instance (and therefore knows that org's `webhook_secret`) can forge a signed `status` webhook event naming their own org in `repository.owner.login` (to pass `verify_webhook_signature`) while specifying an arbitrary `sha` belonging to a completely different organization's stack, with `state: "success"`. This injects a fabricated passing CI status onto a victim commit they do not control, potentially making it `deployable?` and triggering continuous delivery or allowing a legitimate operator to unknowingly ship an unvetted commit — an unauthorized cross-organization write into deploy-readiness state, satisfying the Critical "unauthorized deploy" bar.

### Likelihood Explanation
This requires the attacker to control at least one organization's webhook secret already configured in the shared Shipit instance (a realistic operating condition for any multi-tenant/multi-org Shipit deployment as documented in `docs/setup.md`'s "Using Multiple Github Applications" section), but no `ApiClient` token, no Shipit session, and no access to the victim organization at all. The `sha` value is guessable/discoverable via public GitHub APIs for the target repo.

### Recommendation
In `StatusHandler` (and generally in the webhook pipeline), scope commit/status lookups to `payload.dig('repository','full_name')` via the existing `stacks`/`Repository.from_github_repo_name` helper, and additionally verify that the resolved repository's owning organization matches the organization whose secret validated the signature (`repository_owner` used in `verify_signature`). Reject the webhook if the two do not match.

### Proof of Concept
1. Shipit is configured with two orgs, `OrgA` and `OrgB`, each with its own GitHub App/`webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker administers `OrgA`'s GitHub App and thus knows `OrgA`'s `webhook_secret`.
3. Attacker crafts a `status` event payload: `{"sha": "<OrgB victim commit sha>", "state": "success", "repository": {"owner": {"login": "OrgA"}}}`, and signs it with `OrgA`'s secret via `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the `OrgB` commit (unrelated to `OrgA`), and calls `commit.create_status_from_github!(params)`, marking it `success` in `OrgB`'s stack — despite the attacker having no relationship to `OrgB` at all.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```
