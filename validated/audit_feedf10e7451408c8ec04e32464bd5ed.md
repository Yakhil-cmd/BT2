I have enough evidence to confirm the finding. Let me verify the `Shipit.github` lookup and `GithubOrganizationUnknown` behavior to solidify the analysis.### Title
Webhook signature is verified against a GitHub organization chosen from a mutable/query-overridable `params` field while the actually-processed payload is re-parsed independently from `request.raw_post` - allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the `X-Hub-Signature` against using `repository_owner`, which reads from Rails' merged `params` object (`params.dig('repository','owner','login') || params.dig('organization','login')`). This is a *different* data source than the one actually processed as the webhook payload: `create` independently does `params = JSON.parse(request.raw_post)` and hands that hash straight to the event handlers. Because Rails' `ActionController` `params` merges query-string parameters over the request body for identical keys, an attacker can supply `?repository[owner][login]=<org-with-no-or-known-secret>` in the URL while the signed JSON body actually targets a completely different, victim organization/repository. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The equality that should hold is: **organization whose secret authenticated the request == organization/repository the request's payload actually mutates**. This binding is broken:

- `verify_signature` calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)`. The signature itself is validated over the full raw body, so the signature must have been produced with the secret of *some* configured organization. `repository_owner`, however, is derived from `params`, not from the JSON that is actually parsed and dispatched. [4](#0-3) 
- `create` re-parses the body a second time via `JSON.parse(request.raw_post)` and passes that hash directly to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, completely bypassing the `params` object used during signature verification. [5](#0-4) 
- Handlers extract the target repository purely from this independently-parsed payload, e.g. `Handler#repository_name` uses `payload.dig('repository', 'full_name')`, and `PushHandler` uses `params.after`/`params.ref` to enqueue `stack.sync_github(expected_head_sha: params.after)`. [6](#0-5) [7](#0-6) 
- Rails' standard `ActionDispatch::Http::Parameters#parameters` builds `params` as `request_parameters.merge(query_parameters)` (then merges `path_parameters`), meaning query-string values silently override same-named JSON body keys for the purposes of `params`, without affecting `request.raw_post` (what is actually signed and later re-parsed). This engine's `verify_signature` is the only consumer of `params` in this flow, and it uses exactly the kind of field (`repository.owner.login` / `organization.login`) that an attacker fully controls via the query string.
- `Shipit.github(organization:)` looks up the GitHub App configuration keyed by that organization name and instantiates a `GitHubApp` scoped to whatever `webhook_secret` is configured for it (multi-org deployments are explicitly supported and documented). [8](#0-7) 
- `GitHubApp#verify_webhook_signature` further weakens this: if the selected organization has no `webhook_secret` configured (documented as *optional* per `docs/setup.md`), verification is *auto-approved* regardless of the header/body. [9](#0-8) 

Putting this together: an attacker who knows (or who benefits from) the `webhook_secret` of *any one* configured GitHub organization on a multi-org Shipit instance - or who targets an organization whose secret is left blank, which the docs explicitly allow - can send a POST to `/webhooks?repository[owner][login]=<low-security-org>` with a JSON body forging a `push`/`status`/`pull_request` event whose `repository.full_name` (and other content) targets a *different, higher-value* organization/repository hosted on the same Shipit instance. `verify_signature` will authenticate the request against the low-security org's secret (or trivially, if blank), while the actual handler processes the payload as if it legitimately came from GitHub for the victim repository.

### Impact Explanation
This breaks the organization-that-authenticated vs. repository-that-is-written binding explicitly called out as in-scope. Concretely reachable impacts through existing handlers:
- Forged `push` events feed `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)`, enqueuing `GithubSyncJob` to fetch and append commits for the victim stack based on an attacker-chosen `expected_head_sha`. [10](#0-9) [11](#0-10) 
- Forged `status`/`check_suite` events can inject `CommitStatus`/check-run state for a victim commit, which feeds mergeability/deployability gating used by the merge queue (`MergeRequest#reject_unless_mergeable!`), potentially causing an unauthorized merge/deploy to proceed. [12](#0-11) 

This satisfies the "Critical: unauthorized deploy, rollback, or merge" bar defined in scope, since it lets an unprivileged remote attacker with a foothold in one (even low-value) configured GitHub organization inject signed-looking events that are processed as if authoritative for a victim organization/repository.

### Likelihood Explanation
Requires a multi-org Shipit deployment (explicitly documented and supported) and either: (a) knowledge of a `webhook_secret` for any one configured, lower-value org, or (b) an org configured with no `webhook_secret` at all (documented as optional). Given the query-parameter override behavior of standard Rails `params` merging is not something engine authors evidently accounted for in `repository_owner`, this is a plausible, low-effort exploitation path once one weak organization exists on the instance.

### Recommendation
- Derive `repository_owner` (and any other value used to select the verifying `webhook_secret`) exclusively from the same `JSON.parse(request.raw_post)` hash that is used for the rest of processing - never from ActionController's merged `params`.
- Require `webhook_secret` to be present for every configured GitHub organization, refusing to boot/serve webhooks for orgs without one, removing the automatic `true` return in `GitHubApp#verify_webhook_signature`.
- After signature verification, re-validate that the same organization/repository identified during verification matches the one embedded in the payload ultimately dispatched to handlers.

### Proof of Concept
1. Configure Shipit with two organizations: `low-org` (attacker-known/blank `webhook_secret`) and `victim-org` (target, hosts a real stack).
2. Craft JSON body B representing a legitimate-looking `push` event but with `"repository": {"owner": {"login": "victim-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen-sha>"`.
3. Compute `X-Hub-Signature: sha1=<hmac>` using `low-org`'s webhook secret over the raw body B (or omit/leave signature arbitrary if `low-org` has no secret configured).
4. POST to `/webhooks?repository[owner][login]=low-org` with header `X-Github-Event: push`, the above signature, and body B.
5. `repository_owner` resolves to `low-org` (from the query string, overriding `victim-org` from the body in Rails' merged `params`), `verify_signature` succeeds using `low-org`'s (weak/absent) secret, and `create` re-parses body B and dispatches it to `PushHandler`, which processes it as a legitimate push against `victim-org/victim-repo`.

Note: I was not able to execute this against a running instance to observe live Rails parameter-merge precedence in this exact version/environment; the merge-order behavior (`request_parameters.merge(query_parameters)`) is standard, well-documented Rails/Rack behavior, but I could not find engine-specific code overriding it, so this should be confirmed experimentally before relying on it as conclusive proof.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L21-38)
```ruby
        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-23)
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

**File:** app/models/shipit/merge_request.rb (L155-162)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end
```
