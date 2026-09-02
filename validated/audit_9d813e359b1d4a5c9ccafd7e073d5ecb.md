Confirmed. `StatusHandler#process` scopes purely by `sha` with no repository/organization binding check, while `WebhooksController#verify_signature` authenticates the request only against the organization derived from `repository.owner.login` in the same payload. This is a concrete, in-scope analog: the org whose secret authenticated the webhook is never checked against the repository the status write actually touches.

### Title
Cross-Organization Commit Status Forgery via `StatusHandler` Missing Repository Scoping - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an incoming GitHub webhook against the GitHub App/organization inferred from the payload's `repository.owner.login` (or `organization.login`) field. However, `Shipit::Webhooks::Handlers::StatusHandler#process` writes commit statuses purely by matching `sha` across the entire `Commit` table, without ever checking that the commit belongs to a repository owned by the organization whose secret validated the request. This breaks the binding: `organization that authenticated == repository that is written`.

### Finding Description
The webhook signature check resolves which GitHub App/org secret to use from the request's own JSON body: [1](#0-0) [2](#0-1) 

Once the signature is verified for that org's secret, the handler dispatch simply hands the entire parsed payload to every registered handler for the event, with no re-check that the org matches the resource being mutated: [3](#0-2) 

`StatusHandler`, unlike `PushHandler` (which scopes to `stacks` derived from `payload.dig('repository', 'full_name')`), performs no repository/stack scoping at all — it looks up commits globally by `sha`: [4](#0-3) 

Compare with `Handler#stacks`, which is repository-scoped and available but unused by `StatusHandler`: [5](#0-4) 

Because Shipit supports multiple GitHub organizations each with their own webhook secret (a documented, supported configuration), an operator/attacker who legitimately controls one org's GitHub App installation (and thus knows that org's `webhook_secret`) can sign a `status` event whose `repository.owner.login` matches their own org (so `verify_signature` passes and resolves the correct secret), while the `sha` field references a commit belonging to a completely different organization's stack. `StatusHandler` will happily write the forged status for that unrelated commit because it never checks which repository/org actually owns the commit.

This directly written status feeds `Commit#create_status_from_github!` → `add_status`, which updates `Commit#state`/`deployable?` and can trigger `stack.schedule_merges` and continuous delivery: [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation
An attacker controlling only their own (unrelated, lower-privilege) GitHub organization's webhook secret can forge a `success` CI status for a commit SHA belonging to a victim organization's stack that they have no access to. Since `deployable?` depends on `success? && !blocked?`, this can mark an otherwise-untested or CI-failing commit as deployable, allowing it to be merged (`stack.schedule_merges`) or auto-deployed by continuous delivery on a stack the attacker does not control — an unauthorized deploy/merge crossing repository/organizational trust boundaries, satisfying the "cross-repository writes" / "unauthorized deploy, rollback, or merge" impact bar.

### Likelihood Explanation
Requires only that: (1) the Shipit instance is configured for multiple GitHub organizations (a documented supported topology), (2) the attacker legitimately controls one of those organizations' GitHub App webhook secret (no privileged Shipit account, `ApiClient` token, or GitHub App private key needed), and (3) the attacker knows or can guess/observe a target commit SHA in another tracked repository (SHAs are often public via GitHub). No collusion with Shipit operators or victim org required.

### Recommendation
`StatusHandler#process` (and any other handler that doesn't scope through `stacks`) must verify that the target `Commit`'s `stack.repository` matches the `repository.full_name`/organization that was actually authenticated by `verify_signature`, e.g. by scoping the lookup through `stacks.commits.where(sha: params.sha)` using the `Handler#stacks` helper (as `PushHandler` already does), rather than an unscoped, global `Commit.where(sha: ...)`.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (secret `S_v`) and `attacker-org` (secret `S_a`), both with tracked repositories/stacks.
2. Attacker controls `attacker-org`'s GitHub App and knows `S_a`.
3. Attacker crafts a `status` webhook body:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
   }
   ```
4. Attacker signs the raw body with `S_a` and sets `X-Hub-Signature`, `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, fetches `Shipit.github(organization: 'attacker-org')`, verifies successfully with `S_a`.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (owned by `victim-org`), and writes a forged `success` status via `create_status_from_github!`, potentially making it `deployable?` and triggering merges/deploys on the victim's stack.

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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
