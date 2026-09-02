### Title
Cross-repository commit status injection via globally-scoped `status` webhook handler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The webhook signature check authenticates a payload against the **organization** derived from the payload's own `repository.owner.login` (or `organization.login`), but the `status` event handler never re-checks that the commit `sha` it writes actually belongs to a stack of that same, verified repository. It looks the commit up **globally** by `sha` across the entire Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/webhook secret to validate against using the organization embedded in the payload itself: [1](#0-0) [2](#0-1) 

This means the cryptographic guarantee only proves "this request was signed with organization `repository_owner`'s webhook secret" — it says nothing about which specific commit/stack the event is allowed to affect. Most handlers correctly re-derive scope from the same signed `repository.full_name` field via the shared `stacks` helper: [3](#0-2) 
e.g. `PushHandler` scopes to `stacks.not_archived.where(branch:)` before acting. [4](#0-3) 

`StatusHandler`, however, breaks this pattern: it resolves the affected commit purely by `sha`, with no call to `stacks`/`repository_name` at all: [5](#0-4) 

Because git commit SHAs are content-addressed, the identical SHA can legitimately exist in more than one repository tracked by the same Shipit instance (forks, subtree/vendor imports, monorepo splits, cherry-picks, shared upstream history). The binding that should hold — *the organization whose signature was verified* == *the repository/stack whose commit status is written* — is broken: an attacker who controls (or has push/webhook access to) **any** organization/repository configured in this Shipit instance can produce a validly-signed `status` webhook (signed with their own org's `webhook_secret`) carrying a `sha` that also exists in a different, unrelated stack, and `StatusHandler#process` will write a status onto that commit regardless of which repository the signature actually vouches for.

### Impact Explanation
Commit statuses drive deploy/merge-queue gating (`Commit#deployable?`, the `require_ci` check surfaced in `Api::DeploysController`). By injecting a fabricated `success` status onto a shared-SHA commit belonging to a stack the attacker does not control, the attacker can make an otherwise CI-blocked commit appear deployable/mergeable, i.e. contribute to an unauthorized deploy/merge on someone else's stack — a cross-repository write of authorization-relevant state that crosses the "organization authenticated" vs "repository written" boundary called out in the scope rules.

### Likelihood Explanation
Exploitability depends entirely on being able to produce a genuine SHA collision across two distinct repositories tracked by the same Shipit deployment (forked/mirrored/vendored repos, shared subtree history, or a repo an attacker controls that shares commit history with a target repo). This is a real but narrower precondition than a pure logic flaw — it requires the attacker to already operate a webhook-integrated repository on the same Shipit instance and for the victim's commit SHA to also be reachable/known in that or another attacker-controlled repo. No signature, token, or session compromise is required beyond ownership of one legitimately configured repository.

### Recommendation
Scope `StatusHandler#process` the same way as the other handlers: resolve `stacks` from `repository_name` (the signed `repository.full_name`) first, and only update statuses for commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker configures/owns Repository `attacker/repo` in the Shipit instance (or already has push+webhook access to a repo whose `owner.login` is recognized by `Shipit.github(organization:)`), and thus knows that organization's `webhook_secret`.
2. Attacker discovers or engineers a commit `C` with SHA `S` that exists both in `attacker/repo` and in the victim stack `victim/repo` (e.g., a shared vendored commit, a fork before divergence, or a cherry-picked commit).
3. Attacker POSTs to `/webhooks` a `status` event body: `{"repository":{"owner":{"login":"attacker-org"},"full_name":"attacker/repo"},"sha":"S","state":"success", ...}`, signed with `attacker-org`'s real webhook secret via `X-Hub-Signature`.
4. `verify_signature` validates successfully because it only checks `attacker-org`'s secret against the raw body.
5. `StatusHandler#process` runs `Commit.where(sha: S)`, which also matches the commit in `victim/repo`'s stack, and calls `commit.create_status_from_github!(params)`, writing a forged `success` status onto the victim's commit — potentially satisfying `require_ci` gating for a deploy the attacker does not otherwise have access to trigger CI for.

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
