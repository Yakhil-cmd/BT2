### Title
Cross-repository commit-status forgery via unscoped `StatusHandler` lookup falsifies `Deploy#ignored_safeties` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Webhooks::Handlers::StatusHandler#process` looks up commits by `sha` alone across the entire database, with no check that the webhook's `repository.full_name` matches the repository owning the target commit/stack. Every other GitHub webhook handler (`PushHandler`, `CheckSuiteHandler`, all `PullRequest::*Handler`s) scopes its lookups through `stacks` / `Repository.from_github_repo_name(repository_name)`, but `StatusHandler` does not, letting a validly-signed webhook from a different repository under the same GitHub App installation write a `Status` onto a victim commit whose SHA happens to match (e.g., via a fork sharing commit history).

### Finding Description
The broken binding: `Status.create!.stack_id` (and the commit it attaches to) **should** equal the stack of the repository named in `payload['repository']['full_name']`, i.e. `status.commit.stack.repository.full_name == payload['repository']['full_name']`. Instead, `StatusHandler#process` does: [1](#0-0) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

This queries `Commit` globally by `sha`, ignoring `repository_name`/`stacks` entirely. Compare with `CheckSuiteHandler`, which correctly scopes through `stacks`: [2](#0-1) 

and the base `Handler` class, which provides exactly this scoping helper (unused by `StatusHandler`): [3](#0-2) 

`WebhooksController#verify_signature` only proves the payload was HMAC-signed by *a* valid GitHub App installation for the claimed `repository_owner`; it does not prove that the named `repository.full_name` is the same repository that owns the target `Commit` record: [4](#0-3) 

Exploit flow:
1. Victim repository `org/app` is tracked as a Shipit `Stack`; commit `C` (sha `abcd...`) currently has a real, failing CI status (`Commit#deployable?` false).
2. The GitHub App for `org` is installed org-wide (standard per `docs/setup.md`). Attacker is an ordinary org member (not a maintainer of `org/app`, not a Shipit operator) who owns/administers a different repository in the same org — e.g. a personal fork `org/app-attacker-fork` — that happens to contain the identical commit `C` (forks/cherry-picks share SHA1s deterministically).
3. Attacker calls the GitHub Status API on their own repo (`org/app-attacker-fork`) to post `state: success` for sha `abcd...`. GitHub signs and delivers a genuine `status` webhook to Shipit's endpoint with `repository.full_name = "org/app-attacker-fork"`.
4. `verify_signature` succeeds (correct org secret, since it's a real GitHub-delivered webhook).
5. `StatusHandler#process` runs `Commit.where(sha: "abcd...")`, finds the victim's `Commit` (belonging to `org/app`'s stack) and calls `create_status_from_github!`, creating a `success` `Status` via `Status.replicate_from_github!` / `Commit#add_status`: [5](#0-4) [6](#0-5) 

6. `Commit#deployable?` on the victim commit now returns `true`: [7](#0-6) 

7. When `Stack#build_deploy`/`#trigger_deploy` runs for that commit, `ignored_safeties` is computed as `force || !until_commit.deployable?`, which is now `false`, permanently mis-recording that safety checks were honored: [8](#0-7) 

Existing guards do not stop this: `verify_signature` validates the signer org, not the specific repository named in the payload against the commit being mutated; `ExplicitParameters` only validates shape (`sha`, `state`, etc.), not repository ownership; there is no `stacks.where(...)`/repository check anywhere in `StatusHandler`.

### Impact Explanation
A party controlling any repository within the same GitHub App installation as the victim stack — without any Shipit privilege, session, API token, or repository-maintainer role on the victim repo — can inject a forged `success`/`failure` `Status` onto a victim stack's commit purely by owning a same-org repository that shares a commit SHA (trivial via forking). This flips `Commit#deployable?`, which falsifies `Deploy#ignored_safeties` (and can also unblock `blocked?`/`ProcessMergeRequestsJob` merges, and continuous-delivery auto-deploys), letting an unsafe deploy proceed while the persisted audit trail claims safety checks passed. This is a cross-repository payload mutating another repository's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). It is repeatable against any pair of stacks/commits in the instance that share a SHA, and scales to every stack tracked by the same GitHub App installation.

### Likelihood Explanation
Requires: (a) the target Shipit instance tracks the victim repository, (b) the GitHub App is installed at the org level (common per the documented setup) so a second, attacker-controlled repository in the same org can produce genuinely-signed webhooks, and (c) a shared commit SHA between attacker's repo and the victim commit (guaranteed for forks/cherry-picks of common history, e.g. attacker forks `org/app` and syncs it — an action requiring no special privilege, no Shipit secrets, no maintainer role). No `webhook_secret`, `api_clients_secret`, or session is needed. This is inexpensive and repeatable — one API call per forged status.

### Recommendation
Scope `StatusHandler#process` (and any similar handler) by repository, mirroring the other handlers: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` first, then only update commits belonging to those stacks, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, no live GitHub — payload injected directly to mirror the controller flow):
```ruby
test "status from a different repository must not update another stack's commit" do
  victim_stack = shipit_stacks(:shipit) # tracks e.g. "shopify/shipit-engine"
  victim_commit = shipit_commits(:fifth)
  victim_commit.statuses.destroy_all
  assert_equal false, victim_commit.reload.deployable? # real (simulated) CI state: failing/unknown

  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'shopify/attacker-fork' } # different repo, same org
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)

  # Binding under test: status.commit's stack repository == payload's repository
  assert_not_equal 'shopify/attacker-fork', victim_stack.repository.full_name
  refute victim_commit.reload.deployable?, "status from a foreign repository must not make the victim commit deployable"

  deploy = victim_stack.trigger_deploy(victim_commit, AnonymousUser.new)
  assert_predicate deploy, :ignored_safeties?, "ignored_safeties must remain true since real CI state was failing"
end
```
Before the fix this test fails: the forged cross-repo status flips `deployable?` to `true` and `deploy.ignored_safeties?` becomes `false` despite the victim repository's real CI state being failure.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```
