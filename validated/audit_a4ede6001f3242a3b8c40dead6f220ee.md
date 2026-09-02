### Title
Webhook signature is bound to `repository.owner.login`, but event handlers act on data with no matching organization check — cross-organization commit-status forgery leads to unauthorized deploys (`app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to validate the HMAC signature from `params.dig('repository','owner','login')` (or `organization.login`), i.e. from attacker-suppliable JSON, not from any value cryptographically bound by GitHub. The signature only proves "whoever holds *some organization's* configured `webhook_secret` produced this exact body" — it does not prove the payload's other fields (`repository.full_name`, `sha`, etc.) actually belong to that organization. Several handlers, most notably `StatusHandler`, then act on those unchecked fields globally, across all stacks/organizations in the Shipit install.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` resolves the verification key like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the JSON body being verified. In a multi-organization Shipit deployment, each org has its own `github.<org>.webhook_secret` configured independently (`docs/setup.md` "Using Multiple Github Applications", `lib/shipit.rb#github_app_config`). Whoever controls the GitHub App installation for one org — call it `attacker-org` — knows/receives that org's `webhook_secret` and can sign arbitrary payload bodies with it. The controller trusts that a body signed with `attacker-org`'s secret is a valid webhook *only for the purpose of accepting the request*; nothing subsequently checks that the acted-upon resource in the body belongs to `attacker-org`.

The `status` handler processes `sha` globally, with no repository/organization scoping at all: [3](#0-2) 

It looks up commits by `sha` across the entire `Commit` table (`Commit.where(sha: params.sha)`), spanning every `Stack`/`Repository`/organization in the install, and calls `create_status_from_github!`, which persists a new `Status` and re-evaluates the commit's aggregate CI state: [4](#0-3) [5](#0-4) 

That aggregate status directly feeds `deployable?` and, when a stack has `continuous_deployment?` enabled, triggers `schedule_continuous_delivery`/`ContinuousDeliveryJob`: [6](#0-5) [7](#0-6) [8](#0-7) 

The binding that is broken as an equality:
`organization authenticated by verify_signature (params.repository.owner.login)` ≠ `organization that owns the commit/stack actually mutated by StatusHandler (looked up solely by sha, globally)`.

Other handlers (`PushHandler`, pull-request handlers) at least scope by `payload.dig('repository','full_name')` via `Handler#stacks`/`Handler#repository_name`: [9](#0-8) 
but that `full_name` field is likewise attacker-controlled and never checked against the signing organization (`repository_owner`) — the code trusts that GitHub always keeps `repository.owner.login` and `repository.full_name` consistent in genuine deliveries, but nothing in Shipit enforces that once an attacker can produce a validly-signed body for their own organization.

### Impact Explanation
This is High severity: it lets a party that legitimately controls one organization's GitHub App installation on a shared/multi-tenant Shipit instance (`app/controllers/shipit/webhooks_controller.rb`, config schema in `docs/setup.md:182-209`) forge CI statuses for **any commit in any other organization's stacks**. Because `Commit#deployable?` and `schedule_continuous_delivery` directly consume forged statuses, this can force a commit that never actually passed CI to be marked deployable and, on stacks with continuous deployment enabled, trigger an actual deploy — an unauthorized deploy driven entirely by cross-organization data that was never covered by any per-organization authorization check. It also lets the attacker corrupt another organization's commit-status history/audit trail.

### Likelihood Explanation
Likelihood is Low-to-Moderate: it requires the attacker to already control at least one organization's GitHub App / webhook secret registered on the same Shipit instance (i.e., be a legitimate tenant of a multi-org Shipit deployment), and requires the target stack to have `continuous_deployment?` enabled (or otherwise rely on commit status polling) for the deploy-triggering impact; forging/corrupting status records for other orgs' commits is possible unconditionally once that one signing capability is held.

### Recommendation
After signature verification, re-derive and enforce the organization/repository binding for every handler:
- In `WebhooksController`, pass the verified `repository_owner` (the organization whose secret validated the request) down to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and have `Handler#stacks`/`Handler#repository_name` reject/ignore any payload whose `repository.full_name` owner segment does not case-insensitively match the verified `repository_owner`.
- Specifically fix `StatusHandler` (and `CheckSuiteHandler`, `CheckRunHandler`, etc. if similarly unscoped) to filter `Commit.where(sha: params.sha)` by `stack.repository.owner == verified_organization`, not just by `sha` globally.
- Reject the request (422) if the payload's `repository`/`organization` owner does not match the organization whose secret produced a valid signature.

### Proof of Concept
Given a multi-org Shipit config where `attacker-org` and `victim-org` are both configured (`docs/setup.md:182-209`), and `attacker-org` legitimately knows its own `webhook_secret`:
1. Obtain the sha of a real, unmerged/failing commit on a `victim-org` stack (visible via the public Shipit UI or GitHub).
2. Craft a `status` event body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(attacker-org webhook_secret, body)>` and `X-Github-Event: status`, then `POST` to `/github/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature validates successfully.
5. `StatusHandler#process` runs `Commit.where(sha: "<victim commit sha>")` — matching the victim's commit regardless of organization — and calls `create_status_from_github!`, injecting a forged "success" status that can flip `deployable?` to true and, on a continuous-deployment stack, enqueue an actual deploy of that commit.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-25)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
