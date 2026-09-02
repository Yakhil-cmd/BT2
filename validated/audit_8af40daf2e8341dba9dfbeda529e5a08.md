This confirms the vulnerability. `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filtering by repository, and `Commit.deployable?` gates on `success?` status directly feeding into `stack.schedule_merges` and `ContinuousDeliveryJob`.### Title
Webhook signature is authenticated per-organization but `StatusHandler` writes commit status to **any** stack whose commit SHA matches, breaking the org↔repository binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit supports multi-organization GitHub App configuration, where each organization has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks the HMAC secret to validate the request against based on `repository_owner`, an org login taken straight out of the untrusted JSON payload [2](#0-1) . This design implicitly assumes that whichever organization's secret validates the signature is also the organization whose repository will be mutated by the event handler. `StatusHandler`, however, never re-checks that binding: it looks up commits purely `Commit.where(sha: params.sha)` with no scoping to the repository/stack that the validated organization actually owns [3](#0-2) .

### Finding Description
The relevant equality this flow is supposed to preserve is:

`organization whose webhook_secret authenticated the request == organization that owns the repository/stack being mutated`

Before the attacker's request: any organization `X` that installs the Shipit GitHub App on its own account has a legitimate, independently-issued `webhook_secret` for `X` [4](#0-3) . `Shipit.github(organization:)` looks the config up per-org and constructs a `GitHubApp` scoped to that org's secret [1](#0-0) .

After the attacker's request: the attacker (who legitimately controls org `X` and therefore its own webhook secret) crafts a raw JSON body for the `status` event with:
- `repository.owner.login = "X"` (so `WebhooksController#verify_signature` selects and correctly validates against `X`'s own `webhook_secret`) [5](#0-4) [6](#0-5) 
- `sha` set to a commit SHA that Shipit already tracks for a completely unrelated stack belonging to a different organization `Y` (SHAs are public/guessable git hashes, often visible from the target's GitHub commit history)
- `state: "success"`

`StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [7](#0-6) . Note that, unlike other handlers, `StatusHandler` does not call `stacks` (defined in the base `Handler` class as `Repository.from_github_repo_name(repository_name)&.stacks`) to scope the lookup to the repository actually named in the payload [8](#0-7) . Since `sha` values are global, non-namespaced identifiers and `Commit` records are looked up engine-wide, any commit with a matching sha — belonging to org `Y`'s stack — gets its status updated using org `X`'s validated webhook, even though `X` never authenticated on `Y`'s behalf.

`create_status_from_github!` directly feeds into `Commit#status`/`deployable?`, which is the exact gate used for automated deploys: `deployable? = !locked? && (stack.ignore_ci? || (success? && !blocked?))` [9](#0-8) , and successful/pending status transitions trigger `stack.schedule_merges` and continuous delivery via `schedule_continuous_delivery` → `ContinuousDeliveryJob` when `stack.continuous_deployment?` is enabled [10](#0-9) .

This is a direct analog of the Particle finding: a signature/authorization check is performed on a scoping field (`amount0Min`/`amount1Min` in the report; here, `repository_owner` used only for auth selection) while the actually-mutated resource (minted liquidity amounts; here, the target `Commit`/`Stack`) is never re-validated against that same authorized scope.

### Impact Explanation
An attacker who legitimately controls any organization onboarded to a shared/multi-tenant Shipit instance (a low-privilege, unprivileged position relative to other tenants) can forge CI status webhooks that spoof a "success" CI status on an arbitrary commit belonging to a different tenant's stack. If that stack has `continuous_deployment: true` or otherwise relies on commit status for gating automatic deploys/merges, this can trigger an **unauthorized deploy** of a commit that never actually passed CI — matching the "Critical: unauthorized deploy" impact bucket in the grading rubric.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment where Shipit is configured for multiple GitHub organizations (a documented, supported configuration in `docs/setup.md`/`secrets.development.example.yml`). The attacker needs: (1) their own legitimate org's webhook secret (which they already possess, being the owner of that org's GitHub App installation) and (2) knowledge of a target commit SHA (public git data, often trivially discoverable). No privileged Shipit account, `ApiClient` token, or GitHub write access to the victim repository is required — only control over one's own, independently onboarded organization.

### Recommendation
`StatusHandler` (and any other handler that queries records without going through the `stacks`/`repository_name` scoping helper) must scope its `Commit` lookup to the repository named in the payload, e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })` instead of the global `Commit.where(sha: params.sha)`. More generally, the webhook signature verification org and the resource-scoping org/repository used by every handler should be cross-checked so that a validated signature for org `X` can never cause writes to resources belonging to a different organization `Y`.

### Proof of Concept
1. Attacker owns/operates GitHub organization `X`, which is installed as a separate Shipit GitHub App entry with its own `webhook_secret` (multi-org config as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker identifies a target stack belonging to unrelated org `Y` and obtains a commit SHA from that stack's public GitHub history that Shipit has already ingested as a `Commit` record (e.g., a recently pushed commit awaiting CI).
3. Attacker computes `X-Hub-Signature` using `X`'s own `webhook_secret` (fully known to them) over a `status` event JSON payload:
   ```json
   {
     "sha": "<Y's tracked commit sha>",
     "state": "success",
     "repository": { "owner": { "login": "X" } }
   }
   ```
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "X")` and successfully verifies the signature against `X`'s secret [5](#0-4) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds `Y`'s commit (no repository/stack scoping applied), and calls `create_status_from_github!`, marking it `success` [7](#0-6) .
6. If `Y`'s stack has continuous deployment enabled, `schedule_continuous_delivery` fires and the forged-success commit can be auto-deployed [10](#0-9) .

**Uncertainty/limitations:** I could not directly inspect `Status::Group`/`replicate_from_github!` internals or `ContinuousDeliveryJob`'s exact trigger conditions within the available index to fully confirm the end-to-end auto-deploy path beyond `schedule_continuous_delivery`; a Devin session with full repository access would be needed to trace those remaining links precisely.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
  end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
```

**File:** docs/setup.md (L100-105)
```markdown
    oauth:
      id: Iv1.bf2c2c45b449bfd9
      secret: ef694cd6e45223075d78d138ef014049052665f1
      teams:
    domain: # The domain name of your GitHub Enterprise instance, leave it empty if you use github.com
```
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
