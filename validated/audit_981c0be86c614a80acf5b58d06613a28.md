### Title
Cross-repository commit status forgery via `StatusHandler` — authenticated organization binding is not enforced against the target repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook is authenticated per-organization (via `repository.owner.login` in the payload, matched against that organization's `webhook_secret`), but `StatusHandler#process` writes the resulting commit status to **any** `Commit` row in the entire database whose `sha` matches the payload, with no scoping to the repository/organization that was actually authenticated. This breaks the binding `organization authenticated == repository written`, letting a party who legitimately controls the webhook for one configured GitHub org/repo forge a CI status on a commit belonging to a completely different stack/organization managed by the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to check using only the `repository.owner.login` (or `organization.login`) field of the payload: [1](#0-0) 
This authenticates "who owns the org this webhook claims to be from," but it does not verify that the rest of the payload (in particular the specific commit `sha` the handler will act on) is actually scoped to that organization/repository.

Other handlers correctly scope their side effects to the repository named in the payload via `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)`: [2](#0-1) 
For example `PushHandler` only touches stacks belonging to the named repository: [3](#0-2) 

`StatusHandler`, however, never calls `stacks`/`repository_name` at all — it looks up commits globally by SHA across the whole `commits` table and mutates them: [4](#0-3) 

Because a git SHA is only unique within a single repository's object graph — not globally across all repositories tracked by a shared Shipit instance — an authenticated webhook for Organization A's repository can carry a `sha` value that happens to also be a commit tracked under Organization B's stack. `StatusHandler` will happily attach the forged `state`/`context`/`description` to that foreign commit, even though the signature verification only proved the sender controls Organization A's webhook secret, not anything about Organization B's repository.

This directly matches the required binding-break pattern: **the organization that authenticated (A) ≠ the repository that is written (B)**.

### Impact Explanation
Commit statuses gate real, credentialed GitHub write operations performed by the Shipit app:
- `MergeRequest#all_status_checks_passed?` / `#any_status_checks_failed?` read exactly the statuses attached to `head` via `StatusChecker`: [5](#0-4) 
- When checks pass, `ProcessMergeRequestsJob` calls `merge_request.merge!`, which performs an actual GitHub merge using the app's own installation credentials: [6](#0-5) 
- Required/blocking CI status names are also used to decide whether a commit is CI-deployable, gating the `require_ci` deploy path (`app/models/shipit/deploy_spec.rb`, `blocking_statuses`/`required_statuses`), so a forged "success" status can similarly enable an "otherwise-blocked" deploy.

Therefore, an attacker who is authorized to configure/trigger webhooks for one Shipit-managed organization can forge a passing (or failing) CI status on a commit belonging to a *different* organization's stack in the same Shipit install, which can cause an **unauthorized merge** (Critical impact per the given rubric) or unblock an **unauthorized deploy**, without ever holding credentials, an `ApiClient` token, or write access to the victim repository/organization.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (explicitly supported and documented in `config/secrets.development.example.yml` and `docs/setup.md`) where the attacker legitimately controls the webhook configuration/secret for at least one tenant organization. Colliding SHAs across independent repositories is not guaranteed by default, but nothing in the code prevents it, and an attacker who also has any visibility into the target repository's commit history (e.g., it is public) can pick/target a known SHA. The root cause — `StatusHandler` performing an unscoped, cross-tenant lookup by SHA — is present regardless of collision likelihood and is a clear architectural authorization gap: the webhook signature authenticates an org, but the write path ignores that org boundary entirely.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` and the pull-request handlers are scoped: resolve commits only within `stacks` (i.e., filter by `Repository.from_github_repo_name(repository_name)`/its associated stacks) rather than querying `Commit` globally by `sha`. Concretely, change:
```ruby
Commit.where(sha: params.sha).each do |commit|
```
to restrict to commits belonging to `stacks` (or their repository), e.g. `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or an equivalent scoped ActiveRecord query, ensuring the authenticated organization's repository membership is enforced before any commit status write.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker-controlled webhook secret) and `org-b` (victim, tracked stack with a known commit SHA `deadbeef...`).
2. As the administrator of `org-a`'s GitHub App/webhook, craft a `status` event payload:
   ```json
   {
     "sha": "<victim commit sha in org-b's stack>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "full_name": "org-a/some-repo", "owner": { "login": "org-a" } }
   }
   ```
3. Sign the payload with `org-a`'s configured `webhook_secret` and POST it to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` as `org-a`, verifies successfully using `org-a`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the victim commit belonging to `org-b`'s stack (unscoped), and calls `commit.create_status_from_github!(params)`, attaching a forged `success` status.
6. If `org-b`'s merge/deploy CI requirements are satisfied by that forged status, `ProcessMergeRequestsJob`/deploy trigger paths will proceed to call the real GitHub API (`merge_pull_request`, etc.) against `org-b`'s repository, using the Shipit app's own credentials — an unauthorized merge/deploy triggered entirely from `org-a`'s webhook trust.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/merge_request.rb (L164-176)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
