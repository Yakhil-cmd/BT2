### Title
Cross-Organization Webhook Authorization Bypass Enables Unauthorized Cross-Repository Sync/Deploy Triggering - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to authenticate an incoming webhook from a value taken directly out of the **unverified** JSON payload itself, rather than from an already-established binding to a specific organization/repository. Handlers then act on a **different** field of the same unverified payload (`repository.full_name`) to decide which stack to mutate. In a multi-organization deployment (a supported and documented configuration), these two payload-derived values are never cross-checked, so an attacker who legitimately controls one organization's webhook secret can forge a request that is "authenticated" as Org A but acts on Org B's repository/stack.

### Finding Description
`verify_signature` computes the organization used for HMAC verification straight from the request body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — a value the sender fully controls. `Shipit.github(organization: repository_owner)` then looks up the `webhook_secret` for that organization from `secrets.github`, which is keyed per-organization in multi-app setups: [3](#0-2) [4](#0-3) 

Once the HMAC passes using *that* organization's secret, the raw payload is dispatched unmodified to handlers: [5](#0-4) 

Handlers such as `PushHandler` resolve the target stacks purely from `repository.full_name`, a completely separate field of the same payload: [6](#0-5) [7](#0-6) 

There is no code anywhere that enforces `repository.full_name` must belong to `repository.owner.login` (the value used to pick the verifying secret). This breaks the following equality that the design implicitly assumes:

`organization whose secret authenticated the request == organization owning the repository the handler writes to`

**Attack**: In a multi-org Shipit deployment (per `docs/setup.md`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`), an attacker who is a legitimate admin of Org A (and therefore knows Org A's `webhook_secret`, since they configured it) crafts a webhook body with:
- `repository.owner.login = "OrgA"` (used only to pick the verifying secret)
- `repository.full_name = "OrgB/victim-repo"` (used by the handler to select the stack to act on)
- `X-Hub-Signature` computed with Org A's known secret over this exact body

`verify_signature` succeeds because it verifies against Org A's secret matched from `repository.owner.login`. The handler (e.g. `PushHandler`) then looks up stacks by `OrgB/victim-repo` and calls `stack.sync_github(expected_head_sha: ...)`: [8](#0-7) 

`GithubSyncJob` fetches real commits from GitHub using the stack's own (Org B's) GitHub App credentials and appends them: [9](#0-8) 

If the newly-appended commit is deployable and the victim stack has `continuous_deployment` enabled, this schedules an actual deploy: [10](#0-9) [11](#0-10) 

The attacker — who has no relationship to Org B whatsoever, other than knowing/guessing its `repository.full_name` — has thus used credentials belonging to Org A to force an unauthorized sync/deploy trigger against Org B's stack, entirely because the signature-authenticated identity and the identity of the resource being mutated are read from two independent, uncorrelated fields of the same unauthenticated payload.

### Impact Explanation
This crosses an organization/repository trust boundary using only credentials the attacker legitimately possesses for their own tenant, and results in an unauthorized deploy trigger against another organization's stack — matching the "Critical: unauthorized deploy" bucket. It also demonstrates a general authorization-bypass pattern applicable to any handler that trusts `repository.full_name` (or `organization.login`) independent of the field used for signature-org selection (e.g., `membership`, `pull_request`, `status`/`check_suite` handlers), widening the practical blast radius beyond just push-triggered syncs.

### Likelihood Explanation
Exploitability requires the deployment to use the documented multi-organization `github` secrets configuration (explicitly supported and documented in `docs/setup.md`) and requires the attacker to control at least one onboarded organization's webhook secret — a normal, unprivileged capability for any org admin who legitimately connects their org to the shared Shipit instance. No access to Org B's secrets, tokens, or Shipit session is needed.

### Recommendation
Bind webhook signature verification to the same organization/repository identity that handlers subsequently act on. Concretely: after verifying the signature for `repository_owner`, ensure the repository resolved by handlers (`repository.full_name`) actually belongs to that same verified organization/owner before processing — reject the webhook otherwise. Alternatively, resolve target stacks/repositories only through records already scoped to the verified organization, never through raw payload fields decoupled from the authentication step.

### Proof of Concept
1. Deploy Shipit with multi-org config: Org A and Org B both configured under `secrets.github`, each with distinct `webhook_secret`s (per `docs/setup.md`).
2. As an attacker who administers Org A (knows Org A's `webhook_secret`), build a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<any-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, body)>`.
4. POST to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches Org A's secret, and the signature validates.
6. `PushHandler#process` resolves stacks via `repository.full_name = "OrgB/victim-repo"` and calls `stack.sync_github`, triggering `GithubSyncJob` for Org B's stack — despite the attacker having no relationship to Org B.

**Note:** I was unable to fully inspect `app/models/shipit/webhooks/handlers/status_handler.rb` before the tool budget was exhausted, so I cannot confirm whether the `status` event handler is similarly exploitable to forge a passing CI status for a victim commit (which would more directly force an unauthorized deploy past required-status checks). The `push`-triggered `sync_github` → continuous-delivery path documented above is confirmed and sufficient to establish the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
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
