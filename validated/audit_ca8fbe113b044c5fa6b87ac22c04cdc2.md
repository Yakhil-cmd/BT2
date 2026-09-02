### Title
Cross-tenant commit-status injection via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify a payload against based on the payload's `repository.owner.login` (falling back to `organization.login`), then hands the *entire* raw JSON body to the matching event handler. [1](#0-0) [2](#0-1)  Most handlers re-derive the target *repository* from the same payload and scope their side effects to stacks belonging to that repository, e.g. `PushHandler` and `CheckSuiteHandler` operate on `stacks` (which is built from `Repository.from_github_repo_name(repository_name)`). [3](#0-2) [4](#0-3) [5](#0-4) 

`StatusHandler`, however, does not scope by repository at all — it looks up commits **instance-wide** purely by SHA and applies the attacker-controlled status to whatever it finds: [6](#0-5) 

This breaks the equality that should hold: `organization whose webhook_secret authenticated the request == repository/stack whose Commit state is mutated`. In a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration [7](#0-6) ), the signature check only proves the request came from *some* legitimate, configured organization — not that it is authorized to write into the specific commit/stack the payload references.

### Finding Description
1. `Shipit` supports hosting multiple GitHub organizations against a single engine instance, each with its own `webhook_secret` configured under `github.<org>.webhook_secret`. [7](#0-6) 
2. `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` using only `repository.owner.login`/`organization.login` from the untrusted payload, and verifies the raw body's HMAC signature against that organization's secret. [8](#0-7) [9](#0-8) 
3. Once the signature check passes for *organization A* (an org the attacker legitimately administers/owns on this shared instance), the full attacker-controlled JSON body is dispatched to `Shipit::Webhooks.for_event('status')`, i.e. `StatusHandler`. [10](#0-9) [11](#0-10) 
4. `StatusHandler#process` never checks `repository.full_name`/owner — it simply does `Commit.where(sha: params.sha)` across the **entire database**, then calls `commit.create_status_from_github!(params)` for every match, regardless of which stack/organization the commit actually belongs to. [6](#0-5) 
5. `create_status_from_github!` creates a `Status` record and runs `add_status`, which fires `deployable_status` hooks and, when the resulting state is `success`, schedules merges/continuous delivery based on `Status#schedule_continuous_delivery`. [12](#0-11) [13](#0-12) [14](#0-13) 
6. `Commit#deployable?` treats a commit as deployable once it has a `success` status and is not blocked/locked. [15](#0-14) 

Because the SHA used to select the target `Commit` is entirely attacker-supplied and globally unscoped, an attacker who legitimately owns/administers Organization A (with a valid, real `webhook_secret` for their own GitHub App installation on the shared Shipit instance) can forge a `status` webhook whose `sha` matches a real commit belonging to victim Organization B's stack. The signature verifies (it was signed with A's own secret over A's own payload), yet the actual database write (`Status` creation) lands on B's commit.

### Impact Explanation
This is a cross-tenant integrity break: an org that is only authorized to sign/push its own webhooks can inject a fabricated CI status ("success") onto another org's tracked commit. If the victim stack has `continuous_deployment` enabled or otherwise treats a `success` status as a deploy/merge gate, this can trigger an **unauthorized deploy** of a commit that never actually passed CI, purely from a different, unprivileged tenant on the same shared instance — matching the Critical-impact category of "unauthorized deploy, rollback or merge."

### Likelihood Explanation
Requires: (a) the Shipit instance is configured for multiple GitHub organizations (a documented, first-class configuration), (b) the attacker administers/owns one of those organizations' GitHub App installations (giving them a legitimate `webhook_secret` they can sign arbitrary bodies with, without any special privilege on the victim organization), and (c) knowledge of a target commit SHA in the victim's repository (SHAs are routinely public — visible via GitHub UI/API, PRs, or Shipit's own stack pages). No access to the victim's GitHub token, `webhook_secret`, or Shipit session is required. This is a realistic likelihood in genuinely multi-tenant Shipit deployments.

### Recommendation
`StatusHandler#process` should scope the commit lookup by the repository identified in the payload (as `PushHandler`/`CheckSuiteHandler` already do via `stacks`), e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(params.repository.full_name)` before matching by SHA, ensuring the organization that authenticated the webhook can only mutate commits belonging to its own repositories.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations, `victim-org` and `attacker-org`, each with distinct `webhook_secret`s. [7](#0-6) 
2. Attacker legitimately administers `attacker-org`'s GitHub App and thus knows `attacker-org`'s real `webhook_secret`.
3. Attacker learns (via public GitHub) the SHA of a commit `deadbeef...` on `victim-org/victim-repo`, tracked by a Shipit stack with `continuous_deployment: true`.
4. Attacker crafts a `status` event JSON body: `{"sha": "deadbeef...", "state": "success", "context": "ci/travis", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/some-repo"}}`.
5. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker_webhook_secret, body)` and POSTs to `/github/webhooks` with header `X-Github-Event: status`.
6. `verify_signature` resolves `repository_owner` = `attacker-org`, verifies successfully against `attacker-org`'s secret. [1](#0-0) 
7. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')`, finds the victim's commit (unscoped by repository), and creates a `success` `Status` on it. [6](#0-5) 
8. The victim commit becomes `deployable?`/triggers continuous delivery scheduling despite the attacker having no relationship to `victim-org`.

Note: I was unable to trace the exact chain from `Status#schedule_continuous_delivery` through `ContinuousDeliveryJob` to a real deploy invocation within the available context (only file names were located, not full contents), so the final "does it actually deploy" step is inferred from `Commit#deployable?` and hook names rather than directly confirmed line-by-line.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
