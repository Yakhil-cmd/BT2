### Title
`StatusHandler` writes commit CI status without verifying the commit's repository matches the webhook-authenticated organization - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by looking up the GitHub App/`webhook_secret` for the organization named in the payload itself (`repository.owner.login` or `organization.login`) and validating the HMAC against that secret. `Shipit::Webhooks::Handlers::StatusHandler`, which processes `status` events, never re-checks that binding: it looks up commits purely by `sha` (`Commit.where(sha: params.sha)`), globally, with no scoping to the repository/organization whose secret validated the request. This breaks the equality "organization that authenticated == repository that is written."

### Finding Description
The webhook entry point selects which GitHub App config (and therefore which `webhook_secret`) to verify the signature against using attacker-supplied payload fields: [1](#0-0) 

specifically: [2](#0-1) 

Once the signature is accepted, `WebhooksController#create` dispatches the event to `Shipit::Webhooks.for_event(event)` handlers, passing the raw parsed JSON body unchanged: [3](#0-2) 

Most handlers re-derive scope from `repository.full_name` via `Handler#stacks`/`repository_name` (e.g. `PushHandler`): [4](#0-3) [5](#0-4) 

However, `StatusHandler` does **not** use `stacks`/`repository_name` at all — it looks up commits solely by `sha`, across the entire `commits` table, regardless of which stack/repository/organization they belong to: [6](#0-5) 

`Commit#create_status_from_github!` then persists an attacker-supplied `state`/`context`/`description` as a real `Status` record on whatever `Commit` row(s) match that `sha`: [7](#0-6) 

This status directly feeds `Commit#deployable?` and the "blocking status" gating logic that Shipit uses to decide whether a commit may be deployed: [8](#0-7) 

and it also triggers `stack.schedule_merges` and `ContinuousDeliveryJob` for continuous-deployment stacks when the new status is `success`: [9](#0-8) [10](#0-9) 

**Root cause / broken binding:** `WebhooksController#verify_signature` authenticates "this payload was signed by Organization X's registered secret" (via `Shipit.github(organization: repository_owner)`), but `StatusHandler#process` writes to whichever `Commit` row in the entire Shipit instance shares the given `sha` — with no check that the commit's `stack.repository` belongs to Organization X. Before the fix such a binding would need: `verify_signature`'s org == the org owning the `Commit`(s) actually mutated. After: `StatusHandler` never enforces this, so the two can diverge for any multi-tenant Shipit deployment (the engine explicitly documents/supports configuring multiple GitHub organizations, each with its own `webhook_secret`, in `config/secrets.development.example.yml`).

An attacker who legitimately controls (or knows) the `webhook_secret` for their own registered organization/App — a routine, unprivileged capability for any org admin onboarding their own repos to this shared Shipit instance — can sign an arbitrary JSON body with that secret while forging `repository.owner.login`/`organization.login` = their own org (to pass `verify_signature`) and setting `sha` to any commit SHA tracked by *any other* stack in the same Shipit instance (e.g. a SHA shared through a fork, cherry-pick, or vendored history, or simply guessed/observed via other Shipit read endpoints). The forged `status` event then creates a "success" status on that foreign commit, bypassing the CI gating that the target stack's real GitHub organization relies on.

### Impact Explanation
This crosses the credential/repository-authentication boundary the "verify_signature" mechanism is meant to enforce and results in a cross-repository write: an actor authenticated only for their own organization can inject a fabricated CI status onto a commit belonging to a different organization's stack, which is consumed by `deployable?`/`blocking?` and can unlock or trigger an unauthorized/continuous deploy for that other stack. This matches the "Critical — cross-repository writes... or an unauthorized deploy" impact tier.

### Likelihood Explanation
Requires only that the attacker be a legitimate onboarding org/App admin for the shared Shipit instance (no privileged Shipit account, `ApiClient` token, or GitHub write access to the victim repo needed) plus knowledge of a target commit SHA tracked elsewhere in the same instance (obtainable via public commit history, forks, or Shipit's own commit-listing UI/API). No `webhook_secret`, `api_clients_secret`, or session compromise is required beyond the attacker's own legitimately-issued organization secret.

### Recommendation
In `Shipit::Webhooks::Handlers::StatusHandler#process`, scope the `Commit` lookup through the authenticated organization/repository, mirroring `Handler#stacks`/`repository_name` (i.e., resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and only update commits belonging to that repository's stacks), so a webhook accepted for organization X can never mutate state belonging to organization Y's stacks.

### Proof of Concept
1. Shipit is configured for multiple GitHub organizations (per `config/secrets.development.example.yml` multi-org schema), each with its own `webhook_secret`. Attacker legitimately administers OrgA and knows OrgA's `webhook_secret`.
2. OrgB has a Shipit stack tracking a commit with SHA `abcd123...` (learnable from the public GitHub repo or Shipit UI).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, and a body:
   ```json
   {
     "sha": "abcd123...",
     "state": "success",
     "context": "ci/attacker",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
   }
   ```
   signed with `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `github_app`, and the signature validates successfully.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: 'abcd123...')` — matching OrgB's commit — and calls `create_status_from_github!`, creating a `success` `Status` on OrgB's commit despite the request never being authenticated for OrgB.
6. If OrgB's stack requires that status/context for `deployable?`/`blocking_statuses`, the forged status can unlock deploy/continuous-delivery for OrgB's commit.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
