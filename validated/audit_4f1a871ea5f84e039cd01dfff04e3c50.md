### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook against the GitHub App/organization derived from `repository.owner.login` (or `organization.login`) in the payload [1](#0-0) [2](#0-1) . Every other webhook `Handler` scopes the effect of the event to the repository named in the payload via `Handler#stacks`, which filters `Repository.from_github_repo_name(repository_name)` using `repository.full_name` [3](#0-2) . `StatusHandler`, however, does not use this repository-scoped `stacks` helper at all: it looks up commits globally by `sha` alone and mutates their CI status [4](#0-3) .

### Finding Description
The verified/authenticated entity (the organization whose `webhook_secret` produced a valid HMAC over the payload, resolved via `repository_owner`) is not the same entity that is acted upon by `StatusHandler#process`. That handler runs:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This query is not scoped to `stack`, `repository`, or the payload's `repository.full_name`/`owner.login` in any way — any `Commit` row across any `Stack`/`Repository` tracked by this Shipit instance whose `sha` matches the attacker-supplied value will have a new status attached via `create_status_from_github!` [5](#0-4) .

Git commit SHAs are content-addressed (tree, parent(s), author/committer identity+timestamp, message), not repository-addressed. An attacker who legitimately administers their own GitHub organization/repo that is separately connected to the same Shipit instance (and therefore knows/controls that organization's `webhook_secret`, satisfying `verify_webhook_signature`) can craft a commit with identical content/metadata to a target commit that exists in a *different*, unrelated repository/stack also tracked by the same Shipit instance, producing an identical SHA. They then send (or trigger, e.g. by pushing to a CI-linked branch) a validly-signed `status` webhook for their own org that references that shared SHA with `"state": "success"`. Because `StatusHandler` never checks that the commit's `stack`/`repository` corresponds to the verified organization, Shipit will attach a fabricated "success" status to the victim commit in the unrelated repository.

This breaks the binding: `organization that authenticated (repository_owner used by verify_signature) == repository whose commit's status is written`. The equality fails because the write path (`Commit.where(sha:)`) is entirely decoupled from the authenticated organization/repository.

### Impact Explanation
`Commit#deployable?` and continuous-delivery scheduling depend directly on the aggregated `status` built from `statuses` records [6](#0-5) [7](#0-6) . A forged "success" status injected by a cross-tenant attacker can:
- Mark a commit that never passed real CI as `deployable?`, and
- Trigger `schedule_continuous_delivery` → `ContinuousDeliveryJob`, causing Shipit to automatically deploy that commit if `continuous_deployment?` is enabled on the victim stack.

This matches the required "unauthorized deploy" impact category: an attacker with no privileges on the victim organization/repository/stack can cause Shipit to treat an arbitrary commit as CI-green and deploy it, purely by controlling an unrelated organization also connected to the same Shipit instance.

### Likelihood Explanation
Exploitation requires: (1) the attacker administers at least one GitHub organization/repository that is also configured as a Shipit stack on the same instance (a realistic scenario for any multi-tenant Shipit deployment, e.g. an internal platform serving many teams/orgs), and (2) the ability to produce a commit whose SHA collides with a real, targeted commit in the victim repository — achievable deterministically by duplicating the exact tree/parent/author/committer/timestamp/message of a *public* target commit (git SHAs are fully determined by these fields, not by which remote hosts the commit). No `ApiClient` token, `webhook_secret` of the victim org, or GitHub write access to the victim repo is required — only knowledge of the attacker's own organization's already-known webhook secret, which they legitimately possess.

### Recommendation
Scope `StatusHandler#process` to the repository indicated by the verified webhook payload, mirroring what `Handler#stacks` already does for other handlers, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a status update can only affect commits belonging to the same repository/organization that was authenticated by `verify_signature`.

### Proof of Concept
1. Attacker controls GitHub organization `attacker-org`, which has installed the Shipit GitHub App and knows its own `webhook_secret` (legitimately configured for their own integration).
2. Attacker identifies a target commit `sha = X` in `victim-org/victim-repo`, a completely unrelated stack tracked by the same Shipit instance, that is currently blocked (CI failing/pending).
3. Attacker crafts a commit in their own repo with identical tree/parent/author-committer identity & timestamps/message such that `git hash-object` yields the same SHA `X` (deterministic given identical inputs).
4. Attacker sends a `status` event to Shipit's `/webhooks` endpoint, with `repository.owner.login = attacker-org` (so `verify_signature` validates using `attacker-org`'s own secret) and body `{"sha": "X", "state": "success", ...}`.
5. `WebhooksController#verify_signature` succeeds (valid signature for `attacker-org`) [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: "X")`, matches the commit in `victim-org/victim-repo`, and creates a "success" status on it [4](#0-3) [5](#0-4) .
7. If `victim-org/victim-repo`'s stack has `continuous_deployment?` enabled, `schedule_continuous_delivery` fires and Shipit deploys the now-"deployable" commit [7](#0-6) .

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
