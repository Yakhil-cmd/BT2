### Title
Cross-repository commit status injection via unscoped `sha` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The webhook signature check authenticates *which organization/repository owns the webhook secret used to sign the request*, but the `status` event handler never re-validates that the commit it mutates actually belongs to that same repository. This breaks the binding: `organization authenticated by signature == repository whose commit/stack is written`.

### Finding Description
`WebhooksController#verify_signature` selects the `GithubApp`/`webhook_secret` to validate the HMAC using `repository_owner`, which is read straight out of the untrusted JSON payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

This only proves that the *sender controls a webhook secret for the org/repo named in the payload*. It does not restrict which records the handler is allowed to mutate — the entire raw payload is handed unchanged to the registered handlers once the signature checks out: [3](#0-2) 

`StatusHandler#process`, however, looks up commits **globally by `sha` alone**, with no join/filter on the repository or stack that the verified webhook secret belongs to: [4](#0-3) 

Compare this to the base `Handler` class, which does define a `repository_name`/`stacks` scoping helper based on `payload.dig('repository','full_name')`, but `StatusHandler` does not use it: [5](#0-4) 

Creating a status on an unrelated commit is not a no-op: `Commit#create_status_from_github!` → `#add_status` emits `commit_status`/`deployable_status` hooks and, critically, calls `stack.schedule_merges` and schedules continuous delivery when the new status is `pending` or `success`: [6](#0-5) [7](#0-6) 

**Binding broken:** `repository_owner` (authenticated via `verify_webhook_signature`) `==` `repository of the Commit being written by StatusHandler`. Before the fix this equality is implicitly assumed by the controller design; after an attacker's crafted request it is false — the signer is org A, but the commit written/mutated can belong to any stack tracked by the Shipit instance, as long as the `sha` string matches.

### Impact Explanation
An attacker who legitimately owns/administers *any* GitHub repository tracked by this Shipit instance (i.e. can configure that repository's own webhook and thus knows/derives its `webhook_secret`) can sign a `status` event payload with an arbitrary `sha`. If that `sha` collides with a commit that exists in a *different* stack (realistic via a shared-history fork, cherry-pick, or simply reusing a known public commit sha from another tracked repository — commit SHA1s are content/parent-derived and identical across forks/mirrors of the same history), the handler will create a `success`/`pending` status on that unrelated stack's commit. This can flip CI gating for continuous delivery and trigger `stack.schedule_merges` / continuous deployment on a repository the attacker does not control, i.e. an unauthorized deploy/merge on someone else's stack — matching the "unauthorized deploy, rollback or merge" High-impact criterion.

### Likelihood Explanation
Requires the attacker to (a) be a legitimate integrator for at least one repository already tracked by the target Shipit instance, and (b) find or engineer a commit whose sha is shared with a commit in the victim stack (trivial for forks/mirrors sharing history, or public repos where SHAs are known in advance). No Shipit session, `ApiClient` token, or GitHub App key is required — only a legitimate webhook secret for the attacker's own onboarded repository, which is a normal, unprivileged capability granted to any repo owner who is allowed to add this Shipit instance's webhook.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stack(s) belonging to the repository named in the (already-authenticated) payload, using the same `repository_name`/`stacks` helper the base `Handler` class already exposes, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker owns/admins `attacker-org/forked-repo`, a fork of `victim-org/victim-repo`, tracked as its own Shipit stack, and knows `webhook_secret` for `attacker-org` (a normal capability for anyone allowed to configure webhooks on their own repo).
2. Because it's a fork, some commit `sha = X` is shared with `victim-org/victim-repo`, which is tracked by another stack on the same Shipit instance.
3. Attacker POSTs to `/github/webhooks` a `status` event body: `{"sha": "X", "state": "success", "context": "ci/travis", "repository": {"owner": {"login": "attacker-org"}}}`, signed with `attacker-org`'s webhook secret in `X-Hub-Signature`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org` and validates the signature successfully — [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: "X")`, which matches the commit in `victim-org`'s stack (unscoped) — [4](#0-3) , creating a `success` status and potentially triggering continuous delivery for `victim-org`'s stack.

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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
