### Title
Commit status webhook handler updates commits across all tracked repositories without verifying the payload's repository scope - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook signature is verified per-organization based on `repository.owner.login`, but `StatusHandler#process` never checks which repository the payload claims to be for — it looks up commits purely by `sha` across the entire installation. This breaks the binding between "the organization whose webhook secret authenticated the request" and "the repository/stack whose data is written."

### Finding Description
`WebhooksController#verify_signature` derives `repository_owner` from the payload and verifies the HMAC signature using that organization's `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves the request came from an app installed on that organization's own repository. Most handlers correctly scope subsequent writes to that same repository via `Handler#stacks`, which resolves the target stacks from `payload.dig('repository', 'full_name')`: [3](#0-2) 
and `PushHandler#process` uses this scoping before acting: [4](#0-3) 

However, `StatusHandler#process` never calls `stacks`/`repository_name` at all — it queries `Commit` globally by SHA and mutates every matching commit, regardless of which stack/repository/organization it belongs to: [5](#0-4) 

So the equality the code implicitly assumes is: "organization that authenticated the webhook == repository whose commits get their status written." That equality does not hold here — the org used for signature verification is never checked against the commit's owning stack/repository before the status is persisted.

### Impact Explanation
If any commit SHA is shared between repositories tracked by different Shipit stacks/organizations (common with forked repos, mirrored repos, repos migrated between orgs, or monorepo-derived stacks that ingest the same upstream history), a correctly-signed, legitimate `status` webhook delivery from Organization A's repository will also update the commit status on the same-SHA commit belonging to Organization B's stack — an org/attacker with no relationship to Organization B. Since commit status feeds Shipit's deployable-status/deploy-gating logic, this allows cross-repository status injection that can mark a commit as `success` in a stack the attacker does not control, enabling an unauthorized deploy in that stack.

### Likelihood Explanation
Requires the attacker to control (or trigger) a `status` webhook delivery correctly signed for some organization Shipit trusts (e.g., they have push/CI access to any tracked repo in Org A), and requires that the targeted commit SHA also exists in a stack for Org B. This is realistic for forked/mirrored repositories and shared-history setups, which are common in practice, but is not universally exploitable against arbitrary unrelated repos with unrelated histories.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup to the stacks resolved from the payload's own repository (i.e., reuse `Handler#stacks`), the same way `PushHandler` and `CheckSuiteHandler` do, e.g. `Commit.where(sha: params.sha, stack: stacks).each { ... }`, so a webhook can only mutate commits belonging to the repository it was actually authenticated for.

### Proof of Concept
1. Shipit tracks two stacks: `org-a/repo` (secret `S_A`) and `org-b/repo-fork` (secret `S_B`), where `repo-fork` shares commit history with `repo` (e.g., it was forked from it), so both contain commit `abc123...`.
2. Attacker has legitimate access to trigger a `status` event for `org-a/repo` (e.g., via their own CI integration with push/status access to that repo), sending a payload with `sha: abc123...`, `state: success`, correctly HMAC-signed with `S_A`.
3. `WebhooksController#verify_signature` resolves `repository_owner` as `org-a` and successfully verifies the signature with `S_A`. [6](#0-5) 
4. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, which matches the commit in both `org-a/repo` and `org-b/repo-fork`, and calls `create_status_from_github!` on both — updating the status of a commit in `org-b`'s stack despite the request only ever being authenticated for `org-a`. [5](#0-4)

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
