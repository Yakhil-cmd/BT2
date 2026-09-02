Good — this confirms `GithubSyncJob#perform` fetches commits via `stack.github_api` (the victim stack's own actual GitHub App token via `stack.github_app` → `Shipit.github(organization: repository.owner)`), so the attacker cannot inject fake commits, but they *can* force a sync/resync of the victim's stack on demand and steer `expected_head_sha` retry behavior, and — more importantly for review-stack/PR handlers — trigger `ReviewStackAdapter` archive/unarchive/provisioning actions against a victim's stack using a signature that was never actually issued by the victim's GitHub organization.

### Title
Webhook signature verification keys off `repository.owner.login` while event handlers act on the separately-controlled `repository.full_name`, letting any onboarded organization forge webhooks for another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an inbound webhook against using `repository_owner`, a field read directly out of the unauthenticated JSON body (`params.dig('repository', 'owner', 'login')`) [1](#0-0) [2](#0-1) . Once the HMAC check passes, every event handler (`PushHandler`, `PullRequest::OpenedHandler`, `LabeledHandler`, `ClosedHandler`, etc.) resolves the actual target `Stack`/`Repository` using a *different* body field, `repository.full_name`, via `Repository.from_github_repo_name` [3](#0-2) [4](#0-3) . Nothing binds these two fields together, and nothing re-derives `repository.full_name`'s owner from the same source used for signature selection.

### Finding Description
Shipit explicitly supports onboarding multiple independent GitHub organizations into a single instance, each with its own `webhook_secret`, configured under `secrets.github.<org>` [5](#0-4) [6](#0-5) . `Shipit.github(organization:)` looks up the app/secret purely by organization name, with no cross-check against which repository the event actually concerns [7](#0-6) .

The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository the handler acts on`

But the code computes these from two independently-editable JSON fields in the same attacker-supplied body:
- Authentication org: `params.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) 
- Acted-upon repo: `payload.dig('repository', 'full_name')` [8](#0-7) 

Because `verify_webhook_signature` computes the HMAC over the entire raw request body using whichever secret belongs to `repository.owner.login` [9](#0-8) , an organization admin who legitimately possesses **their own** onboarded org's `webhook_secret` can craft an arbitrary payload, set `repository.owner.login` (and/or `organization.login`) to their own org so the correct secret is selected and the signature validates, while setting `repository.full_name` to `victim-org/victim-repo`. The signature check passes (it's a validly-HMAC-signed request, just self-signed by the attacker's own org secret), and the handler then dispatches against the victim's `Stack`.

### Impact Explanation
This is a cross-tenant authorization bypass in a multi-organization Shipit deployment: an org that is only entitled to control its own stacks can act as if it authenticated for another org's repository. Concretely reachable handlers include:
- `PushHandler`, which calls `stack.sync_github(expected_head_sha:)` on the victim's stack for any branch the attacker names [10](#0-9) , forcing on-demand resyncs and retry-loop behavior against a stack the attacker doesn't own.
- Pull-request handlers (`OpenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ClosedHandler`) which create, archive, or unarchive **review stacks** on the victim's repository based purely on `repository.full_name`, `pull_request.head.ref`, and label state supplied in the forged body [11](#0-10) [12](#0-11) .

While `GithubSyncJob` re-fetches actual commit data from GitHub through the victim's own installation token (so the attacker cannot inject arbitrary commit content) [13](#0-12) [14](#0-13) , the attacker can still trigger unauthorized state-changing operations (forced syncs, review-stack creation/archival/provisioning) on a repository/stack that does not belong to their organization — an unauthorized action taken against another tenant's stack without ever holding a Shipit session, API token, or the victim's webhook secret.

### Likelihood Explanation
Requires only that: (1) the target Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration) [5](#0-4) , and (2) the attacker administers one of those onboarded organizations and thus knows the `webhook_secret` for their own GitHub App (which they themselves created/configured, per the multi-app setup flow). No access to the victim org's secret, private key, or Shipit credentials is needed — the attacker POSTs directly to the public `/webhooks` endpoint [15](#0-14) .

### Recommendation
After verifying the signature, re-derive the organization strictly from the same field(s) used for signature selection and require the handler's repository resolution to be constrained to that same organization (e.g., reject/short-circuit if `repository.full_name`'s owner segment doesn't match `repository_owner`/`organization.login` used to select the webhook secret). Alternatively, scope `Repository.from_github_repo_name` lookups by the authenticated organization rather than trusting `full_name` in isolation.

### Proof of Concept
1. Shipit instance configured with two onboarded orgs: `attacker-org` (attacker is admin, knows its `webhook_secret`) and `victim-org` (has a stack tracking `victim-org/victim-repo`), per `secrets.github.<org>` schema [5](#0-4) .
2. Attacker builds a push-event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(attacker-org's webhook_secret, body)>` and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, loads `attacker-org`'s `GitHubApp`, and `verify_webhook_signature` succeeds because the attacker legitimately knows that secret [1](#0-0) [9](#0-8) .
5. `PushHandler` is invoked with the full parsed body; `repository_name` resolves to `"victim-org/victim-repo"` [8](#0-7) , so `stacks` matches the victim's stack, and `stack.sync_github` is enqueued for it [10](#0-9)  — despite the request never being signed by `victim-org`.

**Note on confidence/limitations:** I could not fully trace whether `continuous_deployment` auto-deploy paths or merge-queue paths could be reached this same way (only `PushHandler`/`sync_github` and the PR review-stack handlers were verified directly); a full audit of every handler under `app/models/shipit/webhooks/handlers/**` would be needed to enumerate the complete blast radius. Additionally, real-world exploitability depends on the Shipit operator having actually configured the multi-organization schema and having onboarded an org controlled by an adversarial actor — this is a supported, documented configuration, not a misconfiguration, so it remains in scope.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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

**File:** app/models/shipit/stack.rb (L434-440)
```ruby
    def github_api
      github_app.api
    end

    def github_app
      Shipit.github(organization: repository.owner)
    end
```
