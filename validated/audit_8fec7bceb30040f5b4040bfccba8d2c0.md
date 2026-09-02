### Title
Cross-organization commit-status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` binds signature verification to the organization named in the incoming payload (`repository.owner.login` / `organization.login`) and validates the HMAC against that organization's own `webhook_secret`. This authenticates only that "the request is a legitimate webhook from GitHub App X, installed on organization A." However, `Shipit::Webhooks::Handlers::StatusHandler#process` does not scope its side effect to organization A's repositories/stacks at all — it looks up commits globally by SHA across the entire `commits` table and mutates them.

### Finding Description
The webhook signature check resolves the secret to verify against using data taken from the same payload it is verifying: [1](#0-0) [2](#0-1) 

This ties the "authenticated organization" identity to whatever `repository.owner.login` (or `organization.login`) is present in that specific payload — i.e., it proves "this payload was HMAC-signed with organization A's configured webhook secret," nothing more.

Most handlers correctly re-derive the target scope from the same `repository.full_name` field via the base `Handler#stacks`/`repository_name` helper, keeping the authenticated organization and the affected repository/stack in agreement: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, breaks this binding. It ignores `repository`/organization scoping entirely and updates **any** `Commit` record anywhere in the installation whose `sha` matches the value supplied in the (attacker-controlled) payload body: [5](#0-4) 

Because git commit SHAs are computed only from the commit's own content/parent/metadata (not from which repository stores them), the same commit object — and therefore the same SHA — routinely exists in multiple repositories/stacks tracked by Shipit (forks, mirrors, cherry-picks, shared upstream history, subtree merges, or repositories migrated/renamed over time). An attacker who legitimately controls a GitHub App installation on their **own** organization (org B) — and therefore possesses org B's real `webhook_secret` and can send a validly-signed `status` webhook — can supply a `sha` value that also exists in a completely unrelated victim stack belonging to organization A. `verify_signature` will happily accept the webhook (it's correctly signed for org B), but `StatusHandler#process` will write/update the `Status` on the matching commit in **org A's** stack, since the lookup is `Commit.where(sha: params.sha)` with no `stack_id`/repository filter.

This is precisely the class of bug the reference report describes at a higher level (a value the "trust boundary" is supposed to bind — the org whose secret validated the request — is not actually enforced on the object being mutated), applied here as: **"organization that authenticated" (org B, via its own webhook secret) ≠ "repository/stack that is written" (org A's tracked commit)**.

### Impact Explanation
Writing a forged `Status` onto a commit in an organization/stack the attacker has no legitimate relationship to is a cross-repository/cross-organization write performed purely through the webhook endpoint, without any Shipit session, `ApiClient` token, or GitHub write access to the victim repository. Downstream consequences from `Commit#add_status` are significant: [6](#0-5) 
- It can flip `deployable_status` and trigger `stack.schedule_merges` when the forged status is `success`/`pending`, potentially unblocking the merge queue or continuous deployment for a commit that never actually passed CI in the victim's own pipeline.
- It emits `commit_status`/`deployable_status` hooks that downstream integrations may act on.

This matches the "Critical — cross-repository writes" / unauthorized deploy-or-merge impact category, since it lets an attacker with no privileges on the victim org influence the victim's merge/deploy gating.

### Likelihood Explanation
Medium-to-High: the attacker only needs to control any GitHub App installation Shipit trusts (their own org, if Shipit supports multiple orgs, or simply be able to author a status webhook payload for a SHA they know is shared with a target). Finding a SHA collision across repositories requires that the victim's commit history intersects with a repository the attacker controls (forks, shared upstream, vendoring, subtree merges are common in real deployments), which is a realistic occurrence rather than a cryptographic hash collision.

### Recommendation
Scope `StatusHandler#process` (and any other handler using `Commit.where(sha:)` without repository context) to the repository named in the same authenticated payload, e.g. join through `stacks`/`Repository.from_github_repo_name(repository_name)` exactly as `Handler#stacks` already does for other handlers, so that only commits belonging to the organization whose webhook secret actually signed the request can be mutated.

### Proof of Concept
1. Shipit is configured with multiple GitHub Apps/organizations (as documented in `docs/setup.md`, "Using Multiple Github Applications"), or the attacker otherwise controls a GitHub App installation trusted by this Shipit instance for organization B, and therefore knows org B's `webhook_secret`. [7](#0-6) 
2. Victim organization A has a Shipit-tracked stack containing a commit whose SHA is also present in a repository the attacker controls under organization B (e.g., a shared open-source upstream commit, a fork, or a cherry-pick).
3. Attacker crafts a `status` event payload: `{"sha": "<shared_sha>", "state": "success", "repository": {"owner": {"login": "OrgB"}, "full_name": "OrgB/attacker-repo"}}` and signs it with org B's real `webhook_secret` (`X-Hub-Signature`).
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgB"`, fetches OrgB's `GitHubApp`, and confirms the signature is valid.
5. `StatusHandler#process` runs `Commit.where(sha: "<shared_sha>")`, which matches the commit in Org A's victim stack (in addition to/instead of any commit in Org B), and calls `create_status_from_github!`, writing a forged `success` status onto Org A's commit, potentially unblocking Org A's merge queue. [5](#0-4)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
