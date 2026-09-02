### Title
Webhook signature verification org can diverge from the org that owns the acted-upon Stack, letting a cross-org push payload trigger `GithubSyncJob` on a victim's Stack - ([File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to check against using `params.dig('repository','owner','login')`, while `PushHandler` (via `Handler#stacks`/`#repository_name`) selects which `Stack` to mutate using the unrelated field `params.dig('repository','full_name')`. Nothing enforces that these two fields refer to the same organization, so a webhook that is "verified" against one org's (weak/unset) secret can act on a completely different org's `Stack`.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`organization used in verify_signature` (`repository.owner.login`, or fallback `organization.login`) == `organization owning the Stack acted upon` (derived from `repository.full_name`, via `Repository.from_github_repo_name`).

Code path:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (fallback `organization.login`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no `webhook_secret` configured: `return true unless webhook_secret`. [2](#0-1) 
- Once verification passes, the raw parsed JSON body is dispatched unmodified to `PushHandler.call(params)`. [3](#0-2) 
- `PushHandler#process` resolves the target `Stack`(s) via `Handler#stacks`, which uses `payload.dig('repository', 'full_name')` — a completely different field than the one used for signature verification — to look up `Repository.from_github_repo_name` and then filters `not_archived.where(branch:)`, finally calling `stack.sync_github(expected_head_sha: params.after)`. [4](#0-3) [5](#0-4) 

Root cause: `repository.owner.login` (used for auth) and `repository.full_name` (used for the DB lookup that decides which Stack is affected) are independent, attacker-controlled fields in the same unsigned/weakly-signed JSON body. An attacker who can get a push webhook accepted for *any* organization configured in `Shipit.github` with no `webhook_secret` set (a documented, valid configuration state per `docs/setup.md` and the sample `secrets*.yml` files showing `webhook_secret: # nil`) can set `repository.owner.login = 'attacker-org'` (so verification trivially returns true) while setting `repository.full_name = 'victim/repo'` (so `Handler#stacks` resolves the real victim `Stack`). This decouples "who signed/authorized the request" from "whose data gets acted on."

Why existing guards don't stop it: `verify_signature` only checks that *some* recognized organization's secret matches (or is absent) — it never checks that the org used for verification matches the org embedded in `repository.full_name`. `drop_unhandled_event` and the `ExplicitParameters` schema (`requires :ref`, `requires :after`) do not perform any ownership cross-check either; they only validate presence/shape of `ref` and `after`. [6](#0-5) 

### Impact Explanation
The victim's real `Stack` (looked up by `repository.full_name`) has `sync_github(expected_head_sha: <attacker-chosen sha>)` invoked, which enqueues `GithubSyncJob` with `stack_id` belonging to the victim and an attacker-chosen `expected_head_sha` [7](#0-6) . Note that `GithubSyncJob#perform` itself fetches commits from GitHub through the *stack's own* legitimate GitHub App/installation (`stack.github_commits`), so the attacker cannot inject arbitrary commit content — the job only decides whether to proceed, retry, or mark the stack accessible/inaccessible based on the forged `expected_head_sha`. The concrete, unauthorized action is that an attacker-controlled request — verified under an org they don't own the target repo in — causes a job to run against a Stack it has no business touching, matching "a payload for one repository mutating another's stack." This is repeatable against any repository whose `full_name` the attacker knows, for as long as at least one organization in `Shipit.github` config lacks a `webhook_secret` (or the attacker can otherwise get a "verified" request routed under a different org than the target). It is not itself an RCE or credential-exfiltration path, since the job's data comes from the real GitHub API using the real stack's own credentials — the mutation is limited to job-triggering/state (`mark_as_inaccessible!`/`mark_as_accessible!`, redundant sync scheduling), not to forging deploys, commits, or credentials.

### Likelihood Explanation
Exploitability depends entirely on operational configuration: there must exist at least one organization entry in `Shipit.github` with no `webhook_secret` set (or one whose secret the attacker can otherwise satisfy) for the "verifying org" side of the equation to be defeatable without any secret. This is a real, documented configuration state (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets.yml` both show `webhook_secret: # nil` as a supported pattern), but it is not guaranteed to exist on every deployment — a fully-locked-down production Shipit instance with `webhook_secret` set for every org would not be exploitable this way, since then the attacker would need a valid secret for at least one org to get past `verify_signature` at all. Given that precondition, the attacker's cost is a single unauthenticated HTTP POST to `/webhooks` with a crafted `X-Github-Event: push` header and a body naming a mismatched `repository.owner.login` vs `repository.full_name` — fully repeatable and scriptable.

### Recommendation
Enforce that the organization used to verify the webhook signature matches the organization embedded in `repository.full_name` (or better, resolve the owning organization/App strictly from `repository.full_name`'s owner segment and verify the signature under that same App/secret) before any handler is invoked, rejecting (422) any payload where they diverge. Concretely, in `WebhooksController#verify_signature`, derive `repository_owner` consistently from `repository.full_name`'s owner segment rather than `repository.owner.login`/`organization.login`, or add a check that `params.dig('repository','owner','login').downcase == params.dig('repository','full_name').split('/').first.downcase` before proceeding.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "cross-org push payload should not sync a stack it did not authenticate for" do
  victim_stack = shipit_stacks(:shipit) # belongs to org "shopify" per fixtures, e.g. repo "shopify/shipit-engine"
  attacker_after_sha = "a" * 40

  # Configure an org with no webhook_secret so verify_webhook_signature trivially returns true
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', { webhook_secret: nil })
  )

  request.headers['X-Github-Event'] = 'push'
  payload = JSON.parse(payload(:push_master))
  payload['repository']['owner']['login'] = 'attacker-org'          # org used for verify_signature
  payload['repository']['full_name'] = victim_stack.repository.full_name # org whose Stack actually gets acted on
  payload['ref'] = 'refs/heads/' + victim_stack.branch
  payload['after'] = attacker_after_sha

  assert_enqueued_with(
    job: GithubSyncJob,
    args: [stack_id: victim_stack.id, expected_head_sha: attacker_after_sha]
  ) do
    post :create, body: payload.to_json, as: :json
  end
  assert_response :ok
end
```
This demonstrates that a payload "verified" under `attacker-org` (no `webhook_secret`) still results in `GithubSyncJob` being enqueued against the victim stack's `stack_id` with the attacker-chosen `expected_head_sha`, confirming the broken binding.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
