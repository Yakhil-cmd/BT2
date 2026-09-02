### Title
StatusHandler applies GitHub commit-status webhooks to any commit sha across all repositories, regardless of the organization/repository that authenticated the webhook - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook using the HMAC secret configured for the organization derived from the payload's `repository.owner.login` (or `organization.login`) [1](#0-0) . That verified organization/repository identity is expected to bound the scope of what the webhook is allowed to affect. However, `StatusHandler#process` never checks that binding: it looks up commits by `sha` across the entire `Commit` table with no repository or stack scoping at all, unlike `PushHandler` and `CheckSuiteHandler`, which both scope their writes through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`) before touching any record [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) .

### Finding Description
The trust binding that should hold is: **organization authenticated by `verify_signature` == organization/repository whose commit records are written by the handler**. `StatusHandler` breaks this equality:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

This query is global — it is not scoped by `stacks`/`repository_name` the way `PushHandler#process` (`stacks.not_archived.where(branch:)...`) and `CheckSuiteHandler#process` (`stacks.where(branch: ...)`) are [4](#0-3) [5](#0-4) . The `Handler` base class even provides a `stacks` helper built from `repository_name` (`payload.dig('repository', 'full_name')`) precisely for this purpose [6](#0-5) , but `StatusHandler` does not use it.

Because `Shipit` supports multiple GitHub organizations each with independent app credentials/webhook secrets (`Shipit.github(organization: ...)`) [7](#0-6) , and `verify_signature` selects the secret used for HMAC validation purely from the attacker-supplied `repository.owner.login`/`organization.login` field in the JSON body [8](#0-7) , a webhook that is validly signed for **organization A** (e.g., because the requester controls a GitHub App installation, or a repository, within organization A, and legitimately triggers a `status` event there) is processed with no further check that the `sha` referenced belongs to a commit tracked under organization A's repositories. `StatusHandler` will happily write a `Status` on **any** `Commit` row in the database whose `sha` matches, including commits that belong to Stacks under a completely different, unrelated organization/repository (e.g., commits shared across forks/mirrors, or commits that happen to be pushed to multiple tracked repositories with identical SHAs, which is common with mirrored/forked repos or subtree-shared history).

### Impact Explanation
`Commit#create_status_from_github!` directly feeds `Commit#deployable?`, which is the gate for automated deploys via `schedule_continuous_delivery` and `Stack#continuous_deployment?` [9](#0-8) [10](#0-9) . An attacker who can get a signed `status` webhook accepted for their own (unrelated) organization/repository, but where the `sha` in the payload matches a commit tracked in a victim's Stack in a different organization, can inject a fabricated `success` status. If that commit becomes the tip of an undeployed range on the victim stack with `continuous_deployment: true`, this can trigger an **unauthorized deploy** of the victim stack — matching the "unauthorized deploy" Critical impact criterion, since the write crosses an organization/repository boundary that the webhook signature was supposed to enforce.

### Likelihood Explanation
Exploitability depends on the attacker being able to get a validly-signed webhook accepted for some organization configured in Shipit (e.g. by owning/administering their own onboarded organization, or by pushing/triggering CI in a repository under an org they control) while referencing a `sha` that also exists as a tracked `Commit` in a different, victim stack. This is realistic in monorepo/fork/mirror setups where identical commits are shared across multiple GitHub repositories tracked by the same Shipit instance, and requires no compromise of Shipit sessions, `ApiClient` tokens, or GitHub App private keys — only the ability to trigger a legitimately-signed webhook in *some* onboarded organization. This satisfies the "unprivileged attacker" bar (an org/repo the attacker legitimately controls, not the victim's).

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries records directly by attacker-supplied identifiers) to the repository/organization verified by the webhook signature, mirroring `PushHandler`/`CheckSuiteHandler`'s use of the `stacks` helper:

```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

This ensures the commit being written to belongs to a repository under the same organization/repository whose webhook secret validated the request, restoring the `authenticated organization == written repository` invariant.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` (attacker-controlled) and `org-b` (victim), each with its own `webhook_secret` per `config/secrets.yml` [11](#0-10) .
2. Both organizations happen to have a Stack tracking a repository that shares a commit `sha` (e.g., a shared vendored commit, mirrored repo, or subtree merge) — call it `SHA_X`, which is undeployed on `org-b`'s continuously-deployed stack.
3. Attacker triggers (or crafts, since they know `org-a`'s webhook secret from having legitimately installed the GitHub App there) a `status` event payload: `{"sha": "SHA_X", "state": "success", "repository": {"owner": {"login": "org-a"}}}`, signs it with `org-a`'s `webhook_secret`, and POSTs it to `/webhooks`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-a")` and successfully verifies the signature [1](#0-0) .
5. `StatusHandler#process` executes `Commit.where(sha: "SHA_X")` unscoped, finds the commit belonging to `org-b`'s stack, and calls `create_status_from_github!`, marking it "success" [2](#0-1) .
6. If `org-b`'s stack has `continuous_deployment: true` and this commit is now the newest "deployable" undeployed commit, `Commit#schedule_continuous_delivery` enqueues a deploy [10](#0-9) , resulting in an unauthorized deploy triggered entirely from `org-a`'s credentials.

**Uncertainty**: I could not verify from the indexed code how commonly commit SHAs are shared across distinct tracked repositories in real deployments (this depends on operator configuration/topology), so likelihood is somewhat scenario-dependent; the root-cause code defect (missing repository/organization scoping in `StatusHandler`) is confirmed directly from the source.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** docs/setup.md (L63-72)
```markdown
production:
  secret_key_base: some-long-string
  host: example.com
  redis_url: "redis://redis-host"
  github:
    app_id: 42
    installation_id: 43
    bot_login: "my-app[bot]"
    webhook_secret: some-secret-value
    private_key: |
```
