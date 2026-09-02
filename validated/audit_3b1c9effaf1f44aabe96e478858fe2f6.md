## Analysis

This confirms the exploitable binding mismatch. This is important: `StatusHandler` matches purely on `Commit.where(sha: params.sha)` **globally across all stacks in the Shipit instance**, not scoped to the `repository_name`/`stacks` scope used by other handlers. So a commit SHA collision/match on any stack (even belonging to a different, unrelated organization) will receive a forged status.

### Title
Webhook signature verification is bound to the wrong field, allowing cross-organization commit status/CI forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, derived directly from attacker-controlled JSON body fields (`repository.owner.login` or `organization.login`). However, the event handlers that perform the actual writes (e.g. `Shipit::Webhooks::Handlers::StatusHandler`, `PushHandler`, `CheckSuiteHandler`) act on a *different* field of the same attacker-controlled body — `repository.full_name` (or, for `StatusHandler`, no repository scoping at all, just a bare commit `sha`). Because GitHub never checks that `owner.login` and `full_name`'s owner segment agree, an attacker who legitimately administers **any** GitHub organization/app connected to this Shipit instance (and thus legitimately knows that org's `webhook_secret`) can craft a payload that verifies under their own org's secret but whose `repository.full_name` (or bare `sha`) refers to a stack belonging to a completely different organization.

### Finding Description
`WebhooksController#verify_signature` computes the verifying `github_app` from `repository_owner`: [1](#0-0) 
and `repository_owner` is read straight from the JSON body: [2](#0-1) 

Once verification passes, `Shipit::Webhooks.for_event(event)` dispatches the *entire raw params hash* to handlers, unchanged: [3](#0-2) 

Handlers resolve the target `Stack`/`Repository` using a **different** field, `repository.full_name`: [4](#0-3) 

`StatusHandler` is worse: it doesn't even scope by repository — it matches purely by commit SHA across the whole database: [5](#0-4) 

`PushHandler` and `CheckSuiteHandler` scope through `stacks`, which again is derived from `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

**The broken binding, stated as an equality that the code assumes but never enforces:**
`organization used to select/verify the HMAC secret (repository.owner.login / organization.login)` == `organization/repository the handler actually writes to (repository.full_name)`.

Before the attack: for genuine GitHub-originated webhooks, GitHub always sets `repository.owner.login` and the owner segment of `repository.full_name` to the same value, so this equality happens to hold and the mismatch is invisible.

After the attack: the attacker POSTs directly to the public `/webhooks` endpoint (this is not GitHub-only; anyone can reach it) with a body where `repository.owner.login` = their own org "attacker-org" (whose `webhook_secret` they legitimately know, having configured it themselves in `config/secrets.yml` for their own GitHub App installation) but `repository.full_name` = "victim-org/victim-repo" — a stack registered under a different, unrelated organization in the same Shipit instance. `verify_signature` computes a valid signature using attacker-org's secret and passes. The handler then acts on victim-org's stack/commits.

### Impact Explanation
Concretely reachable, high-impact abuses of this cross-tenant confusion:
- `StatusHandler` lets the attacker inject arbitrary commit statuses (`state`, `context`, `description`, `target_url`) for *any* commit SHA in the database, regardless of which stack/org it belongs to, since it performs no repository/stack scoping at all. Commit status state feeds directly into `Commit#deployable?`, `blocked?`, and continuous-deployment gating (`schedule_continuous_delivery`), i.e. an attacker can mark a commit "success" on CI status they don't control, unlocking deploy/merge/continuous-delivery gates on a victim repository they have no access to. [8](#0-7) [9](#0-8) 
- This satisfies the "unauthorized deploy" criteria: forging a passing CI status can flip `deployable?` to true and, combined with `continuous_deployment`, trigger an actual deploy of a commit on a repository the attacker never had write access to.

### Likelihood Explanation
Likelihood is realistic but conditioned on the attacker legitimately operating at least one GitHub organization/App connected to the same multi-tenant Shipit instance (a common deployment pattern per `docs/setup.md`, which documents per-organization `webhook_secret` entries in `config/secrets.yml`). No Shipit session, API token, or GitHub write access to the victim's repo is required — only knowledge of one's own organization's webhook secret, which the attacker inherently possesses if they set up that org's GitHub App.

### Recommendation
Enforce the missing binding: after HMAC verification succeeds against the organization derived from the payload, cross-validate that the organization used for verification actually owns the repository/stack that handlers subsequently act on (e.g., compare `repository.owner.login` against the owner segment of `repository.full_name`, and reject on mismatch before dispatching to handlers). Additionally, scope `StatusHandler` to commits belonging to stacks whose repository owner matches the verified organization, rather than matching bare SHA globally.

### Proof of Concept
1. Configure/administer "attacker-org" as a legitimate GitHub App integration on this Shipit instance; know its `webhook_secret` (`secretA`).
2. Craft body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/irrelevant" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = "attacker-org", verifies successfully with `secretA`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit in an unrelated stack — and calls `create_status_from_github!`, injecting a forged "success" status, potentially flipping `deployable?`/triggering continuous delivery on the victim's stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
