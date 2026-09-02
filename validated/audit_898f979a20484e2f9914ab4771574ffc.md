### Title
Status webhook events are matched globally by commit SHA with no repository scoping, allowing cross-repository status writes - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `WebhooksController#verify_signature` before_action authenticates a webhook by resolving a `Shipit::GitHubApp` from the `repository.owner.login` (or `organization.login`) field of the *incoming, attacker-supplied* JSON body, and validating the request signature against that organization's own `webhook_secret`. [1](#0-0) [2](#0-1)  This only proves the payload was signed by *some* organization that is legitimately registered in `Shipit.github`, not that the specific resource referenced inside the payload actually belongs to that organization.

The `status` event handler, `Shipit::Webhooks::Handlers::StatusHandler`, never checks which repository the event claims to originate from — it simply looks up commits globally by SHA across the entire installation and writes a status onto them: [3](#0-2) 

Compare this to `PushHandler`, which correctly scopes to the repository named in the payload via `Handler#stacks`/`Handler#repository_name` before taking any action. [4](#0-3) [5](#0-4)  `StatusHandler` does not inherit this scoping check for the `sha` it operates on.

### Finding Description
This breaks the trust binding: *the organization whose signature was verified* ≠ *the repository/commit whose state is actually written*.

- Verification side: `verify_signature` derives `repository_owner` straight from the JSON body (`params.dig('repository','owner','login')`), fetches that org's `GitHubApp`, and validates the HMAC using **that org's own `webhook_secret`**. [1](#0-0)  A legitimate GitHub App installation on organization `attacker-org` (which the attacker fully controls and for which they can obtain properly signed webhooks) will pass this check for any payload it signs, regardless of what the `sha` field inside the JSON contains.
- Write side: `StatusHandler#process` performs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filter on stack/repository ownership. [3](#0-2)  `Commit` records from every stack/repository configured in the Shipit instance live in the same table, and `sha` is not guaranteed unique per organization.

So a party that legitimately controls its own GitHub organization/App installation (registered in `Shipit.github`, with a valid `webhook_secret`) can craft and correctly sign a `status` webhook whose `sha` matches a commit belonging to a completely different, unrelated repository/stack tracked by the same Shipit instance, and have Shipit record an arbitrary commit status (state, `target_url`, `description`, `context`) on that foreign commit — triggering `Hook.emit(:commit_status, ...)` / `:deployable_status` and potentially unblocking or gating deploys via `Commit#deployable?`/`blocked?`, which are driven by status state. [6](#0-5) [7](#0-6) 

### Impact Explanation
Commit status directly gates whether a commit is `deployable?` (via `blocked?`/`success?`) and whether continuous delivery proceeds (`schedule_continuous_delivery`). [6](#0-5) [8](#0-7)  An attacker who owns any organization onboarded to the Shipit instance can forge status updates for commits in a different, unrelated repository they have no access to, potentially unblocking commits for deploy or corrupting the CI-derived deploy gating for that stack — this is a cross-repository write into another tenant's deploy pipeline data, which matches the Critical "cross-repository writes" impact category.

### Likelihood Explanation
The main precondition is that the attacker's own organization is registered as a `Shipit.github` tenant with a valid `webhook_secret` (a normal, unprivileged onboarding step for any org using this Shipit instance, not a privileged credential). The `sha` collision requirement (needing to guess/know a commit SHA in the victim repository) is the limiting factor — SHAs are effectively unguessable at random but are frequently public knowledge for public/open-source repositories tracked by the same Shipit deployment, making this practically exploitable against known target commits.

### Recommendation
In `StatusHandler#process` (and any other handler that trusts payload-provided identifiers without scoping), constrain the lookup to commits belonging to the repository named in the same payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, mirroring the scoping already used in `Handler#stacks`/`PushHandler`.

### Proof of Concept
1. Attacker registers organization `attacker-org` with the Shipit instance (legitimate `Shipit.github` config entry with its own `webhook_secret`), as commonly supported by multi-tenant Shipit deployments.
2. Attacker learns (e.g., from a public commit) the SHA of a commit belonging to `victim-org/victim-repo`, tracked in a different stack on the same Shipit instance.
3. Attacker sends a `status` webhook to `/webhooks` (or equivalent mount path) with:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/attacker",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
   }
   ```
   signed with `attacker-org`'s own `webhook_secret` and header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (it's legitimately theirs). [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim's commit (no repository filter), writing a forged status onto it. [3](#0-2)

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
