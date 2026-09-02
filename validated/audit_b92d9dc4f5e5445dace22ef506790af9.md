This is a solid finding. Let me verify how `Status` affects deployability/merge gating to substantiate impact.### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up the target `Commit` solely by SHA, with no scoping to the repository/organization whose webhook signature was actually verified. This breaks the trust binding that should hold between "the organization whose GitHub App secret authenticated this webhook" and "the repository/stack whose state is written." Any GitHub `status` event that is validly signed for *any* configured organization can be used to set CI status on a commit belonging to a *different*, unrelated tracked stack, as long as an identical SHA exists there.

### Finding Description
The webhook controller verifies the HMAC signature against the GitHub App configured for the organization named in the payload's own `repository.owner.login` field: [1](#0-0) [1](#0-0) 

This only proves that the request was legitimately delivered by GitHub for *that organization's* app installation — it says nothing about which `Commit` record the handler is allowed to touch. Most handlers correctly re-derive the target scope from `repository.full_name` in the same, signature-covered payload (e.g. `Handler#stacks`/`#repository_name`): [2](#0-1) 

`StatusHandler`, however, does not use `repository_name`/`stacks` at all. It resolves the target purely by matching the `sha` field against every `Commit` row in the entire Shipit instance, across all repositories and organizations: [3](#0-2) 

Git commit SHA-1s are content hashes (tree, parent, author/committer, timestamps, message), not repository-bound identifiers. An attacker who administers *any* repository that is onboarded into the same Shipit instance (even a low-value one, in an organization whose GitHub App/webhook secret they don't need to know — GitHub signs and delivers the webhook itself) can:
1. Fetch the raw git object of a commit belonging to a **different, higher-value tracked stack** (commit SHAs and full commit metadata are public/visible via the GitHub UI/API for any repo they can read).
2. Recreate an identical commit object (same tree, parents, author, committer, timestamps, message) in a repository they control, reproducing the exact same SHA-1.
3. Push that commit to a branch in their own repo, or otherwise cause GitHub to fire a `status` event referencing that SHA for their repo (they fully control status API for their own repo/CI integration).
4. Because `StatusHandler` never checks which repository the status event came from, it writes the forged status (`success`, `pending`, etc.) onto **every** `Commit` row across the whole Shipit installation that shares that SHA — including the one in the unrelated, victim stack.

The binding that is violated: `organization authenticated by verify_signature == repository/stack whose Commit rows are written by the handler`. `StatusHandler` treats these as unrelated.

### Impact Explanation
Commit statuses directly gate `Commit#deployable?`, which is used for merge-queue admission and deploy triggering: [4](#0-3) [5](#0-4) 

Forging a `success` status on a commit in a stack the attacker does not own can flip that commit from "blocked/pending" to `deployable?`, unblocking `continuous_deployment` (`schedule_continuous_delivery`) and CI-gated merges/deploys of a repository the attacker has no legitimate access to: [6](#0-5) 

This is a cross-repository write that can result in an unauthorized deploy/merge of a stack outside the attacker's control, matching the accepted High/Critical impact categories (escalation into deploy/merge gating across repositories).

### Likelihood Explanation
Medium. It does not require any Shipit credentials, `ApiClient` token, or privileged GitHub team membership — only that the attacker administers (or has push access to) one arbitrary repository already tracked by the same Shipit instance, which is a common multi-tenant deployment pattern for this engine. Reproducing an exact SHA-1 for a *chosen* target commit requires copying its full metadata (feasible since commit objects are public), so the practical difficulty is in identifying/targeting a specific victim commit, not in bypassing any cryptographic control — the webhook signature check is fully satisfied by design, since it authenticates the wrong entity (organization) rather than the entity actually mutated (commit/stack).

### Recommendation
`StatusHandler#process` must scope the `Commit` lookup to the repository identified in the same verified payload, exactly as the other handlers do via `Handler#stacks`/`repository_name`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so that a status event can only mutate commits belonging to the repository whose organization actually signed the webhook.

### Proof of Concept
1. Shipit is configured with multiple GitHub organizations (`OrgAttacker`, `OrgVictim`), each with its own GitHub App / webhook secret, as supported by `Shipit.github(organization:)`/`github_app_config` (see `test/dummy/config/secrets_double_github_app.yml`).
2. Both `OrgAttacker/repo` and `OrgVictim/repo` are tracked stacks.
3. Attacker reads a target commit `C` (sha `deadbeef...`) in `OrgVictim/repo`'s protected branch, which currently has no/failing status and is thus not `deployable?`.
4. Attacker reconstructs an identical commit object (same tree/parents/author/committer/timestamps/message) inside `OrgAttacker/repo`, producing the same sha `deadbeef...`, and pushes/configures a CI status webhook on it with `state: success`.
5. GitHub signs and delivers this `status` webhook using `OrgAttacker`'s legitimate webhook secret; `WebhooksController#verify_signature` passes because it only checks that the payload was signed by `OrgAttacker`.
6. `StatusHandler#process` executes `Commit.where(sha: 'deadbeef...')`, which matches the `Commit` row belonging to `OrgVictim/repo`'s stack, and calls `create_status_from_github!`, marking `C` as `success`.
7. `C.deployable?` now returns true in `OrgVictim`'s stack, enabling continuous deployment/merge-queue admission for a repository the attacker never had access to.

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

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```
