### Title
Cross-repository write via SHA collision - StatusHandler#process never checks `commit.stack.repository.full_name == payload.dig('repository','full_name')` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits globally by `sha` and writes a status onto every matching `Commit` row, regardless of which repository the webhook was authenticated for. Signature verification in `WebhooksController#verify_signature` only proves the payload came from the GitHub App/organization matching `payload.dig('repository','owner','login')`; it does not bind the payload to the specific repository the SHA belongs to. If two stacks (e.g. victim's and attacker's own) have a `Commit` row sharing the same `sha`, the attacker's own authenticated webhook writes a status onto the victim's commit too.

### Finding Description
The broken binding, stated as an equality that must hold but is never checked: `commit.stack.repository.full_name == payload.dig('repository', 'full_name')`.

Code path: `WebhooksController#create` parses the JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) . Before that, `verify_signature` calls `Shipit.github(organization: repository_owner)` and checks the HMAC signature against that organization's configured `webhook_secret` [2](#0-1) . This proves the payload is authentic for the organization named in `payload.dig('repository','owner','login')` — nothing more. It does **not** prove that the SHA inside the payload belongs to that repository, nor that no other repository has a colliding `Commit.sha`.

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This query is unscoped by repository — it matches every `Commit` row in the entire database with that `sha`, across all stacks/repositories. The base `Handler` class does provide a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, derived from `payload.dig('repository','full_name')` [4](#0-3) , but `StatusHandler#process` never calls it, unlike the equivalent check-suite/push flows that scope by repository. `Commit#create_status_from_github!` unconditionally appends to `statuses` [5](#0-4) .

Exploit flow:
1. Victim stack has `Commit(sha: S)` (e.g. the empty-tree SHA `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, which is trivially shared, or any SHA the attacker manages to reproduce on their own repo/branch).
2. Attacker owns `attacker/evil`, configured in Shipit with their own registered GitHub App/webhook secret for their own organization (this is a real precondition — see Likelihood).
3. Attacker pushes/creates a commit with SHA `S` in `attacker/evil` and triggers GitHub to send a legitimately-signed `status` webhook for `attacker/evil` with `sha: S`, `state: 'success'`.
4. `verify_signature` succeeds because the signature matches attacker's own configured secret for their own org — this is real, valid verification, just for the wrong scope.
5. `StatusHandler#process` runs `Commit.where(sha: S)`, which matches the victim's row as well, and calls `create_status_from_github!` on it, inserting a status row into the victim's `Commit#statuses` and potentially flipping `deployable?`/triggering continuous delivery via `add_status`/`schedule_continuous_delivery` [6](#0-5) [7](#0-6) .

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) do not stop this: they validate the signature's authenticity for the attacker's own org and validate the shape of `params`, but never compare `payload.dig('repository','full_name')` against the repository owning the matched `Commit`.

### Impact Explanation
A payload legitimately authenticated for one repository (`attacker/evil`) causes a database write (a `Status` row, potentially affecting `deployable?`, `blocked?`, `schedule_continuous_delivery`, and `Hook.emit(:deployable_status, ...)`) on a `Commit` belonging to an unrelated victim `Stack`/repository that never authorized the webhook. This is a cross-repository mutation of Shipit's own record model driven entirely by an attacker-controlled, self-authenticated webhook — matching the "payload for one repository mutating another's stack/commit" Critical category. Because `create_status_from_github!` can flip a commit's aggregate `state` to `success` and this feeds `deployable?`/`schedule_continuous_delivery`, this could contribute to triggering an unintended deploy/merge on the victim stack if other conditions align (`ignore_ci?`/`continuous_deployment?`). The technique is repeatable against any stack whose recorded commit SHAs the attacker can predict or collide with (trivial for well-known SHAs like the empty tree, or any commit the attacker also happens to push, e.g. cherry-picks/rebases producing identical SHAs across unrelated repos — SHA collisions across repos are common for identical file+metadata content, not just adversarial hash collisions).

### Likelihood Explanation
Preconditions: (1) the victim stack must already have a `Commit` row with the exact SHA the attacker will forge a status for — trivially satisfiable for SHAs that are identical across repositories by construction (e.g. the empty-tree SHA, or any commit whose tree/parents/author/committer/message/timestamps match — which can happen for automated bot commits, initial commits, or generated boilerplate) — actual cryptographic SHA-1 collision grinding is not required in the common case. (2) The attacker must own/control a repository that is registered as a GitHub App installation known to `Shipit.github(organization: ...)` so that `verify_signature` succeeds for their own org — this is achievable by any GitHub user by installing the Shipit-integrated GitHub App on their own account/org (a normal, unprivileged, self-service action), or simply because the app is installed org-wide/covers arbitrary repos. No Shipit session, API token, or secret is needed. Cost: negligible — push one commit with a colliding/known SHA and let GitHub deliver a real `status` event, or send an equivalent JSON via any repo the attacker's installed app covers. Fully repeatable against every stack with a matching commit SHA.

### Recommendation
Scope the commit lookup by repository in `StatusHandler#process`: replace `Commit.where(sha: params.sha)` with a query restricted to commits belonging to stacks under the requesting repository, e.g. `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, using the existing `Handler#stacks` helper (derived from `payload.dig('repository','full_name')`) so that only commits whose `stack.repository.full_name` matches the authenticated payload's repository are updated.

### Proof of Concept
Minitest plan (no live GitHub calls, using existing webhook signature test helpers):
1. Create `victim_stack` with `Repository(full_name: 'victim/repo')` and `Commit.create!(stack: victim_stack, sha: 'deadbeef...')`.
2. Create `attacker_stack` with `Repository(full_name: 'attacker/evil')` and `Commit.create!(stack: attacker_stack, sha: 'deadbeef...')` (same SHA).
3. Build a `status` webhook JSON payload: `{ 'sha' => 'deadbeef...', 'state' => 'success', 'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker' } } }`.
4. POST to `/webhooks` with `X-Github-Event: status` and a valid `X-Hub-Signature` computed using the app's configured `webhook_secret` for organization `attacker` (i.e., signature verification legitimately passes).
5. Assert before: `victim_commit.statuses.count == 0` and `victim_commit.stack.repository.full_name != payload.dig('repository','full_name')`.
6. Assert after the request: `victim_commit.reload.statuses.count == 1` — demonstrating the equality `commit.stack.repository.full_name == payload.dig('repository','full_name')` was violated and a status was still written to the victim commit, while `attacker_commit.reload.statuses.count == 1` as expected.

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
