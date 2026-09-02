This confirms the pattern: `PushHandler` and other handlers use the `stacks` scope (derived from `payload.dig('repository', 'full_name')`) to restrict operations to stacks belonging to the authenticated repository, but `StatusHandler` does not — it queries `Commit.where(sha: params.sha)` globally, across all stacks/organizations.

### Title
Cross-organization CI status forgery via unscoped SHA lookup in `StatusHandler#process` - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, a value that is public and content-addressed and not bound to any particular repository, then writes a `CommitStatus` to whatever commit matches — regardless of which organization's webhook secret authenticated the request. Because `WebhooksController#verify_signature` derives the signing organization purely from the attacker-controlled `repository.owner.login` field in the same payload, an attacker who owns any GitHub org with a Shipit webhook configured can sign a `status` event naming a victim's commit SHA and inject a forged CI status onto it.

### Finding Description
The broken binding: the organization that authenticates the webhook (`repository_owner` = `payload.dig('repository','owner','login')`, verified in `Shipit.github(organization: repository_owner)`) must equal the organization owning the `Commit`/`Stack` being mutated. This is enforced in every other handler via the `stacks` helper (`Handler#stacks`, `app/models/shipit/webhooks/handlers/handler.rb:32-38`), which scopes by `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository','full_name')` — the exact same payload field. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) demonstrates the correct pattern: `stacks.not_archived.where(branch:).find_each { ... }`.

`StatusHandler#process`, however, does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

This performs a global, unscoped lookup by `sha` with no reference to `stacks`, `repository_name`, or `repository_owner` at all. `create_status_from_github!` unconditionally creates a `Status` row tied to `commit.stack_id` [2](#0-1) [3](#0-2) .

Attack flow: org-attacker registers/owns a Shipit-integrated repository with a valid `webhook_secret` (attacker's own, legitimately obtained credential). Attacker discovers a public commit SHA belonging to org-victim's repository (SHAs are public and discoverable via GitHub, PRs, commit links, etc.). Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login` is `org-attacker` (so `verify_signature` validates against attacker's own secret and succeeds) but whose `sha` field is the victim commit's SHA, `state: success`, `context: 'ci/attacker'`. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) only checks the signature is valid for the org named in the payload — it never confirms that org actually owns the commit referenced by `sha`. `StatusHandler.process` then finds the victim's `Commit` row (created earlier via a legitimate push from org-victim) purely by matching `sha`, and calls `create_status_from_github!`, writing a new `Status`/`CommitStatus` under the victim's `stack_id`.

Existing guards do not stop this: `verify_signature` only binds the signature to the org named in the request, not to the target commit's actual owner; `ExplicitParameters` schema in `StatusHandler.params` only validates presence/type of fields, not ownership; and there is no `stacks`/`repository_name` check anywhere in `StatusHandler`.

### Impact Explanation
A successful request lets org-attacker write an arbitrary `CommitStatus` (state/context/description/target_url of their choosing) onto any commit in Shipit's database whose SHA they know, including commits belonging to unrelated organizations/stacks. This is a genuine cross-tenant write: a payload authenticated by org-attacker mutates org-victim's `Stack`/`Commit` data. Since `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) treats `success?` (driven by the aggregated status state) as a gating condition for deploys, forging a `success` status can push a victim commit into a "green"/deployable state it did not actually earn, potentially enabling or accelerating an unauthorized deploy. This is repeatable against any commit SHA the attacker can discover, with no bound to a specific repository, making it a broadly exploitable cross-tenant integrity issue.

### Likelihood Explanation
Preconditions are modest: the attacker only needs their own legitimate GitHub org/repo hooked into the shared Shipit instance (a common multi-tenant Shipit deployment), which they can register through normal channels. No victim secrets, sessions, or special roles are required — only knowledge of a public commit SHA, which is trivial to obtain from any public commit link, PR, or clone of the victim repo. The attack is a single crafted HTTP POST, fully scriptable, and repeatable at will against arbitrary commits already known to Shipit.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to only commits belonging to stacks associated with the authenticated repository, mirroring `PushHandler`/`CheckSuiteHandler`, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each { |commit| commit.create_status_from_github! params }`, using the existing `Handler#stacks` helper.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` (or a new `status_handler_test.rb`), add a minitest that:
1. Creates a victim `Stack`/`Repository` (e.g. `full_name: 'org-victim/repo'`) and a `Commit` under it with a known `sha`.
2. Stubs/configures `Shipit.github(organization: 'org-attacker')` with its own webhook secret so `verify_signature` passes.
3. POSTs `X-Github-Event: status` with body `{ sha: <victim_commit.sha>, state: 'success', context: 'ci/attacker', repository: { full_name: 'org-attacker/other-repo', owner: { login: 'org-attacker' } } }`, signed with org-attacker's secret.
4. Asserts `assert_difference('victim_commit.statuses.count', 1) { post :create, body:, as: :json }` — i.e., the write against the victim's commit succeeds — and asserts the equality-under-test explicitly: `repository_owner` (`'org-attacker'`) used to authenticate the request `!= victim_commit.stack.repository.owner` (`'org-victim'`), yet the status was still written, proving the binding is broken.

### Citations

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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
