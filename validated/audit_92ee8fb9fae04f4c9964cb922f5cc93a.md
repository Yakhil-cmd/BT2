### Title
Cross-repository status forgery flips `Commit#deployable?` for a foreign stack's commit - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits solely by `sha` (`Commit.where(sha: params.sha)`), with no scoping to the repository/stack that the incoming, correctly-signed webhook actually belongs to. A webhook genuinely signed for repository A (which the attacker owns/controls) can therefore create a `Status` record on a `Commit` belonging to a completely unrelated stack B whenever the two repos share a commit with the same sha (e.g. a not-yet-merged PR branch, a fork, or shared history), silently flipping `Commit#deployable?` to `true` for stack B without any CI having run against stack B's repository.

### Finding Description
The broken binding is: `commit.deployable? == true` should imply `commit's success Status was produced by CI running against commit.stack.repository`. Instead, the actual binding enforced by the code is only `Status.stack_id == commit.stack_id`, sourced from whatever `Commit` row happens to match the raw `sha` string, with no check that the webhook's own `repository.full_name` matches that commit's stack repository.

Path:
1. `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) verifies the signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled JSON payload (`params.dig('repository', 'owner', 'login')`). This check only proves the payload was signed by *some* GitHub organization/app matching that owner — for a repo the attacker legitimately owns, GitHub will produce a perfectly valid signature. It proves nothing about which `Commit`/`Stack` the sha inside the payload belongs to.
2. `Shipit::Webhooks::Handlers::StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This looks up commits by `sha` alone, globally across the entire `commits` table — it never calls the `stacks`/`repository_name` helpers already defined in the base `Handler` class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that other handlers (e.g. `PushHandler`, `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) do use to scope by the webhook's own `repository.full_name`.
3. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) creates the `Status` using the matched commit's own `stack_id` (`statuses.replicate_from_github!(stack_id, github_status)`), i.e. whichever stack that pre-existing `Commit` row belongs to — not the stack tied to the webhook's `repository` field.
4. `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) is `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, so a newly attached `success` `Status` flips it to `true`.
5. `Shipit::Api::DeploysController#create` trusts `commit.deployable?` directly when `require_ci: true` is passed, short-circuiting with `param_error!(:require_ci, ...)` only if it's false.

Exploit flow: the attacker controls a repository (their own fork or an independent repo they own) that is registered as an independent Shipit stack, or simply owns a GitHub repo capable of emitting a genuinely-signed `status` webhook. If a commit with a given `sha` is reachable in both the attacker's repository and the victim's tracked repository (a routine situation for PR branches — the commit object is identical/content-addressed and exists in both the fork and, once opened as a PR or merged, in the upstream repo Shipit tracks), the attacker triggers their own CI (or fabricates a status on their own repo, which they fully control) to post a `success` status for that sha. GitHub delivers a validly-signed `status` webhook naming the attacker's own repository. `StatusHandler#process` ignores the webhook's `repository` entirely and matches `Commit.where(sha: ...)`, attaching the forged `success` `Status` to the victim's stack's `Commit` row for that sha. Any authorized-but-unwitting team member with `deploy` permission on the victim stack who calls `POST /stacks/:id/deploys` with `require_ci: true`, trusting the green build, now passes the `commit.deployable?` check and an unverified commit is deployed.

Existing guards do not stop this: `verify_signature` only checks that the payload came from a legitimate GitHub org/app, not that its `repository` field matches the commit's actual stack; `StatusHandler`'s `ExplicitParameters` schema only validates payload shape (`sha`, `state`, etc.), not repository identity; and `DeploysController#create`'s `require_ci` check trusts `commit.deployable?` at face value.

### Impact Explanation
This is a payload for one repository (attacker's) mutating another repository's stack/commit state (`Status` row attached to the victim's `Commit`), which then causes an unauthorized deploy of code whose real CI state against the target repository was never verified — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). It is repeatable against any stack tracking a commit sha that also exists in a repository the attacker controls (a routine PR/fork scenario), and the blast radius spans any stack in the Shipit instance, not just one tenant.

### Likelihood Explanation
Preconditions: the attacker needs a repository they control that is wired to send/receive GitHub webhooks to the same Shipit instance (or any repo whose genuinely-signed `status` webhooks reach this Shipit deployment), and a commit sha that is shared with the victim's tracked repository — which is the normal case for forks and open PR branches before or during review. No Shipit secrets, sessions, or privileged roles are required by the attacker; only a legitimate low-privileged deploy-permission user needs to trust the (forged) green build and click deploy with `require_ci: true`. This makes the attack low-cost and realistic in any org using forks/PRs, though it depends on a legitimate deployer actually invoking `require_ci: true` deploy on the affected sha.

### Recommendation
Scope `StatusHandler#process` (and `Commit#create_status_from_github!`) by the webhook's own repository, mirroring `PushHandler`: resolve the target stacks via `Repository.from_github_repo_name(repository_name)` (already exposed by the base `Handler#stacks`), and only create/attach a `Status` for commits that belong to one of those repository's stacks — e.g. `stacks.not_archived.each { |stack| stack.commits.find_by(sha: params.sha)&.create_status_from_github!(params) }` — rather than a global `Commit.where(sha: ...)` lookup.

### Proof of Concept
Minitest controller test plan (`test/controllers/webhooks_controller_test.rb`), no live GitHub:
1. Create two stacks/repositories, `stack_a` (`owner/repo-a`) and `stack_b` (`owner/repo-b`), each with a `Commit` sharing the identical `sha` value (simulate the fork/PR sha-collision scenario by simply giving both `Commit` fixtures the same `sha`).
2. Stub `GithubHook.any_instance.stubs(:verify_signature).returns(true)` (as existing tests do) to represent a genuinely-signed webhook for `repo-a`.
3. POST to `/webhooks` with `X-Github-Event: status`, body `{ sha: <shared_sha>, state: 'success', repository: { full_name: 'owner/repo-a', owner: { login: 'owner' } } }`.
4. Assert: `stack_b`'s `Commit` (matched only by sha, belonging to `repo-b`) now has `commit.reload.deployable?` equal to `true` — the binding equality `commit.deployable? == (CI ran against commit.stack.repository)` is broken because no status/webhook ever named `repo-b`.
5. Follow with `Shipit::Api::DeploysController#create` test: `post :create, params: { stack_id: stack_b.to_param, sha: shared_sha, require_ci: true }` and assert `response :accepted` (instead of the expected `:unprocessable_entity`), proving the deploy is allowed based on a status that was never produced for `repo-b`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** test/controllers/api/deploys_controller_test.rb (L88-103)
```ruby
      test "#create refuses to deploy unsuccessful commits if the require_ci flag is passed" do
        Commit.any_instance.expects(:deployable?).returns(false)

        assert_no_difference -> { @stack.deploys.count } do
          post :create, params: { stack_id: @stack.to_param, sha: @commit.sha, require_ci: true }
        end
        assert_response :unprocessable_entity
        assert_json 'errors.require_ci', ["Commit is not deployable"]
      end

      test "#create deploys failing commits if the require_ci flag is not passed" do
        Commit.any_instance.expects(:deployable?).returns(false)

        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
        assert_response :accepted
      end
```
