This confirms the exact rounding-down analog: the webhook signature is bound to `repository_owner` (`params.dig('repository','owner','login')`), but the code path that actually acts on the payload uses `repository_name` (`payload.dig('repository','full_name')`) via `Handler#repository_name`/`#stacks`, a field never covered by the signature-selection check.

### Title
Webhook signature verified against `repository.owner.login`'s org secret while handlers act on the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), then verifies the raw body's signature against that org's secret [1](#0-0) . Once verification passes, `Shipit::Webhooks.for_event(event)` handlers are invoked with the full, unsanitized `params` hash [2](#0-1) . Handlers such as `PushHandler` resolve the target `Stack`/`Repository` using `payload.dig('repository', 'full_name')`, a completely different field of the same payload than the one used to select the verifying secret [3](#0-2) .

### Finding Description
The binding that should hold is: `organization whose secret signed the request == organization that owns the repository being acted upon`. In practice the engine only enforces: `organization derived from repository.owner.login (or organization.login) == organization whose webhook_secret produced a valid HMAC`. The `repository.full_name` field used by `Handler#repository_name` (and therefore `Repository.from_github_repo_name`) is never cross-checked against `repository.owner.login`.

Since the HMAC covers the raw POST body as a byte string, the *signature* itself is valid proof that "some app config for org X produced this exact JSON," but Shipit only reads `owner.login` out of that JSON to pick which org's secret to check against, and reads `full_name` out of the very same JSON to decide which repository/stack to mutate. Nothing prevents these two fields from disagreeing. This is directly analogous to the Tapioca `removeAsset` bug: the check ("does this signature validate for org X derived from one field") and the action ("operate on repository derived from a different, unchecked field") are decoupled, so satisfying the check does not guarantee the actor is authorized for the object acted upon.

Concretely, an attacker who legitimately owns/administers **any** GitHub organization/App configured in `Shipit.secrets.github` (multi-org config, `config/secrets.*.yml` "github: <org>: webhook_secret") knows that org's `webhook_secret` (it's their own installation) and can freely POST to `/github/auth/...`/the webhooks endpoint. They can craft a `push` (or `status`, `check_suite`, etc.) payload where:
- `repository.owner.login` = their own org (so `verify_signature` picks their own org's `webhook_app` and the HMAC — computed with their own known secret — validates), while
- `repository.full_name` = a victim repository/stack hosted under a different organization also configured in Shipit.

`PushHandler#stacks` will look up `Repository.from_github_repo_name(repository_name)` using the victim's `full_name` and call `stack.sync_github(expected_head_sha: params.after)` [4](#0-3) , feeding an attacker-chosen `expected_head_sha` into `GithubSyncJob`, which fetches commits via `stack.github_commits` and creates commits/records for the victim stack based on attacker-controlled sync parameters [5](#0-4) . Other handlers (`status`, `check_suite`, `membership`, etc.) follow the same `Handler#repository_name`/`#stacks` pattern and are equally reachable cross-organization.

### Impact Explanation
This lets an attacker who controls one configured GitHub organization (an unprivileged actor with respect to any *other* org/repo in the same Shipit instance) forge webhook events attributed to a victim repository/stack in a different organization, without ever obtaining that victim org's `webhook_secret`. This can trigger unintended `GithubSyncJob` runs, commit-status writes on the victim stack, membership/team churn (`membership` handler creates/removes `Membership`/`Team`/`User` records), and check-run refreshes for repositories the attacker does not own — a cross-organization write via a webhook whose signature check was scoped to the wrong entity. This matches the "authenticated organization vs. the repository actually written" trust-binding break called out in the rules.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (`Shipit.github_organizations` with more than one entry, each with its own `webhook_secret`), and (2) attacker legitimate control of at least one configured org so they can compute a valid signature with their own known secret and freely send arbitrary payloads. No access to the victim org's secret, no Shipit session, and no privileged Shipit account are needed — only knowledge of one's own org's `webhook_secret`, which by design an org admin possesses. This is a realistic configuration for shared Shipit instances serving multiple GitHub orgs.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), after signature verification, assert that the organization used to select the signing secret matches the owner of the repository the handler is about to act on — i.e., verify `payload.dig('repository', 'full_name')`'s owner segment equals `repository_owner` before dispatching to handlers, and reject (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` strictly by an ID/owner combination that was itself covered by the same signature-selection field, not by a separate unchecked field.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (per `config/secrets.*.yml` `github:` block, matching `Shipit.github_app_config`) [6](#0-5) .
2. Attacker, an admin of `attacker-org`, knows `attacker-org`'s `webhook_secret`.
3. Attacker builds a `push` event JSON body where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`, and computes `X-Hub-Signature: sha1=<hmac(attacker-org secret, body)>`.
4. POST to the webhooks endpoint with `X-Github-Event: push`. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (using the attacker's own known secret) [7](#0-6) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` [3](#0-2)  and calls `stack.sync_github(expected_head_sha: <attacker-controlled sha>)`, triggering `GithubSyncJob` against the victim stack the attacker never authenticated for [4](#0-3) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
