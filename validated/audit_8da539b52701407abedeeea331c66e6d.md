### Title
Cross-tenant Commit status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to check purely from `params.dig('repository','owner','login')` in the unsigned JSON body, then verifies the raw body HMAC against that org's secret. Once verified, `Shipit::Webhooks::Handlers::StatusHandler#process` performs a completely unscoped `Commit.where(sha: params.sha)` lookup, with no re-check that the resolved commit's `stack`/`Repository` matches the org/repo whose secret authenticated the request, unlike `PushHandler`/`CheckSuiteHandler` which restrict mutations through the `stacks` helper (`Repository.from_github_repo_name(repository_name)`).

### Finding Description
The intended binding is: `org whose webhook_secret verified the signature (params.dig('repository','owner','login'))` == `org owning stack of the Commit row mutated by the handler`.

Trace:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) picks `Shipit.github(organization: repository_owner)` from the attacker-controlled, unverified JSON body, then calls `github_app.verify_webhook_signature(signature, raw_post)` (lib/shipit/github_app.rb:76-83), an HMAC-SHA1 comparison against that org's `webhook_secret`.
- If the attacker legitimately owns a GitHub App/`webhook_secret` for their own org ("attacker-org"), they can sign an arbitrary raw body containing `"repository":{"owner":{"login":"attacker-org"}}` and pass this check trivially — this is expected, since it is their own secret authenticating their own claimed org.
- `WebhooksController#create` then dispatches to `Shipit::Webhooks.for_event(event)` handlers with the parsed `params`, without re-validating that any handler-specific fields (e.g. `sha`) belong to the org that was just authenticated.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-23) does:
  ```ruby
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
  ```
  This is a **global**, unscoped `ActiveRecord` query against the entire `commits` table — it never derives or checks `repository_name`/`stacks` the way `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17, using `stacks.not_archived.where(branch:)`) or `CheckSuiteHandler#process` (app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-16, using `stacks.where(branch:)`) do via the shared `Handler#stacks` helper (app/models/shipit/webhooks/handlers/handler.rb:32-34), which scopes strictly to `Repository.from_github_repo_name(repository_name)` derived from the same `repository.full_name` that was authenticated.
- Because `sha` is a 40-hex-char value with a unique index only on `(sha, stack_id)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`, confirmed in `test/dummy/db/schema.rb:63-87`), the same sha string can legitimately exist under multiple different stacks/repos, and `Commit.where(sha:)` (no `stack_id` filter) will match all of them regardless of which org's key was checked.
- `commit.create_status_from_github!(params)` invokes `add_status`, which creates a `Status` scoped to `commit.stack_id` and can flip commit `state` to `success`/`failure`, which (per `Commit#schedule_continuous_delivery`, app/models/shipit/commit.rb:281-287, and confirmed by `test/models/commits_test.rb` CD-triggering tests) can enqueue `ContinuousDeliveryJob` and trigger an actual deploy on the victim stack if it has `continuous_deployment: true`.

Attacker request: `POST /webhooks` with header `X-Github-Event: status`, `X-Hub-Signature` computed with the attacker's own legitimately-held `webhook_secret` over a body such as:
```json
{"sha":"<victim commit sha, e.g. from public GitHub API>","state":"success","repository":{"owner":{"login":"attacker-org"}}}
```
`repository_owner` resolves to `attacker-org`, the signature verifies against the attacker's real secret, and `StatusHandler#process` writes a `Status` for `commit.sha == params.sha` for whichever stack(s) contain that sha — potentially a victim's stack in an entirely different, unrelated repository/org. Victim commit shas are not secrets; they are public/content-derived and obtainable via GitHub's public API/UI for public repositories, or by any collaborator/watcher for private ones the attacker can otherwise observe.

No existing guard catches this: `verify_signature` only authenticates that the caller possesses *some* valid `webhook_secret` for the org named in the body, not that the mutated record belongs to that org; `drop_unhandled_event` and `check_if_ping` are irrelevant; the `ExplicitParameters` schema for `StatusHandler` only validates types (`requires :sha, String`), not ownership; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` in this webhook path at all since it is machine-to-machine.

### Impact Explanation
An attacker who owns any GitHub App/webhook_secret pair (their own org, own repo) can write `Status` rows against `Commit`s belonging to any other tenant's stack, by supplying that victim commit's sha. This can flip a targeted commit's aggregate `state` to `success`, and for any victim stack configured with `continuous_deployment: true`, can trigger an unauthorized `ContinuousDeliveryJob`/deploy — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The write is repeatable against any commit sha the attacker can observe, across arbitrary repositories/orgs configured on the same Shipit instance (`config/secrets.yml`/`secrets_double_github_app.yml`-style multi-org setups are explicitly supported per `docs/setup.md`), so the blast radius spans every tenant hosted on the instance.

### Likelihood Explanation
Preconditions: the attacker needs (a) their own valid `webhook_secret` for a GitHub App they legitimately control (trivial — install a free GitHub App on their own repo/org, which is exactly the attacker capability granted by the prompt), and (b) knowledge of a target commit's 40-char sha, which is public/observable metadata, not a secret. No Shipit session, API token, or GitHub org membership is required. The request is a single `POST /webhooks` with a correctly HMAC-signed body — low cost, fully scriptable, and repeatable indefinitely against any known sha.

### Recommendation
Scope `StatusHandler#process` (and any other handler that queries `Commit`/`Status`/`CheckRun` by sha alone) through the same `Handler#stacks` helper used by `PushHandler`/`CheckSuiteHandler`, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or equivalently restrict to `Commit.where(sha: params.sha, stack: stacks)`, so a write can only land on a stack whose `Repository` matches `repository.full_name` in the same payload that was authenticated by the org-specific `webhook_secret`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, non-live):
1. Configure two `GitHubApp` fixtures/orgs, e.g. via `secrets_double_github_app.yml`-style config: `OrgA` with `webhook_secret_a`, `OrgB` with `webhook_secret_b`.
2. Create `stack_a` under `Repository` owned by `OrgA` with no commits matching target sha; create `stack_b` under `Repository` owned by `OrgB` with `commit_b = stack_b.commits.create!(sha: "deadbeef...")`.
3. Build a status payload: `{"sha" => commit_b.sha, "state" => "success", "repository" => {"owner" => {"login" => "OrgA"}}}.to_json`.
4. Compute `signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", webhook_secret_a, body)`.
5. `assert_difference "commit_b.statuses.count", 1 do post :create, body:, as: :json end` with `X-Github-Event: status` and `X-Hub-Signature: signature`.
6. Assert `commit_b.reload.state == 'success'`, i.e. `Assert org_whose_secret_verified == "OrgA"` while `Assert org_owning(commit_b.stack) == "OrgB"` — the two sides of the binding diverge, and the write still succeeds, proving the vulnerability. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
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
