## Title
Webhook signature verification is keyed to an attacker-controlled `repository.owner.login`/`organization.login` field that is never bound to the `repository.full_name` the handlers actually act on - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, a value read straight out of the untrusted, unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Every downstream handler, however, resolves the repository/stack to act on using a completely different field from the same untrusted body: `payload.dig('repository','full_name')` (`Handler#repository_name`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`). Because the field used to select the signing secret is never cryptographically bound to the field used to select the acted-upon repository, an attacker who can produce *any* validly-signed webhook (e.g. one for an org configured with a blank `webhook_secret`) can freely set `repository.full_name` to point at an unrelated, protected stack and have it processed as if it came from GitHub for that repository.

### Finding Description
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from the raw JSON body and calls `Shipit.github(organization: repository_owner)` to fetch the `GitHubApp` config used for HMAC verification.
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) explicitly returns `true` unconditionally `unless webhook_secret` — i.e. if the org resolved for signature checking has no `webhook_secret` configured, **any** payload passes verification.
- After `verify_signature` succeeds, `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) parses the same raw body again and dispatches it to `Shipit::Webhooks.for_event(event)` handlers, passing the *entire* attacker-controlled JSON.
- Every handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`) resolves the target repository/stack via `Handler#stacks` → `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which reads `payload.dig('repository','full_name')` — a **different key** than the one used for signature routing (`repository.owner.login` / `organization.login`).
- Because the same request body supplies both values, and only one of them (`owner.login`/`organization.login`) is used to pick the verification secret while the other (`full_name`) is used to pick the acted-upon stack, an attacker can:
  1. Set `repository.owner.login` (or `organization.login`) to an organization configured in `secrets.github` with no `webhook_secret` (common in multi-org configs per `docs/setup.md`/`config/secrets.development.shopify.yml`, where `webhook_secret:` is frequently left blank), causing `verify_signature` to pass trivially.
  2. Set `repository.full_name` to `victim-org/victim-repo`, an entirely different, properly-secured stack.
  3. The webhook is accepted (`head(:ok)`) and dispatched to handlers with the forged `full_name`, which look up and mutate state for the victim stack (e.g. `GithubSyncJob` for `push`, `Status` creation for `status`, membership/team mutation for `membership`, PR label/merge-queue state for `pull_request`).

This is the same trust-binding break pattern as the CLOB report: a field that is authorized/checked (`bidTree` limit / signature scope) is not the same field that is acted upon (arbitrary price/order placement / arbitrary `repository.full_name`), letting the attacker choose the acted-upon target independently of what was verified.

### Impact Explanation
This crosses the "unauthenticated read/write of stack state" and potentially "unauthorized deploy" boundary: an attacker with no GitHub credentials, no `ApiClient` token, and no session can inject fabricated GitHub events (pushes, statuses, membership changes, PR events) against any stack in the installation as long as at least one configured organization in the multi-org `secrets.github` block has a blank/unset `webhook_secret` (which the docs show as an explicitly supported/common configuration — `# nil`). This can trigger `GithubSyncJob` for arbitrary stacks, forge CI `Status` records that gate merge/deploy eligibility, or manipulate `Team`/`Membership` records (which directly feed `Shipit.github_teams` authorization checks in `app/controllers/concerns/shipit/authentication.rb:26-30` and `User#authorized?`), escalating into the authorization system itself.

### Likelihood Explanation
No credentials, tokens, or GitHub access are required — only network reachability to the public `/webhooks` endpoint and knowledge that a multi-org Shipit deployment has at least one organization entry with `webhook_secret` unset (a documented, non-exotic configuration; see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`, both of which show `webhook_secret: # nil`). This is a config-dependent but realistic and unprivileged attack path, not a theoretical one.

### Recommendation
Bind the field used to select the verification secret to the field used to resolve the acted-upon repository: derive `repository_owner` from `repository.full_name` (splitting on `/`) rather than from the separate `owner.login`/`organization.login` keys, or verify that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login` before proceeding. Additionally, do not allow a webhook_secret-less organization to implicitly authorize signature checks for payloads whose declared repository belongs to a different, secured organization.

### Proof of Concept
1. Configure `secrets.github` with two orgs: `weak-org` (no `webhook_secret`) and `victim-org` (stack `victim-org/victim-repo`, `webhook_secret` set).
2. POST to `/github/webhooks` (or engine-mounted equivalent) with header `X-Github-Event: push`, body:
```json
{
  "organization": { "login": "weak-org" },
  "repository": { "owner": { "login": "weak-org" }, "full_name": "victim-org/victim-repo" },
  "after": "<attacker-chosen sha>"
}
```
No `X-Hub-Signature` header is required to be valid because `verify_webhook_signature` returns `true` for `weak-org` (blank `webhook_secret`).
3. `WebhooksController#verify_signature` succeeds; `PushHandler` (or relevant handler) processes the payload, resolving `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueuing `GithubSyncJob` for the victim stack — despite the request never being cryptographically verified against `victim-org`'s secret. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
