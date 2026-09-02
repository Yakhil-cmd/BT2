### Title
Cross-repository status forgery bypasses required CI checks and triggers unauthorized deploys/merges - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook signature is verified against the secret belonging to the *authenticated organization* extracted from the payload, but `StatusHandler#process` writes the resulting `Status` record to **any** `Commit` in the entire Shipit installation that happens to share the reported `sha` — with no check that the commit belongs to a stack of the repository/organization that the signature actually authenticated for. This breaks the binding: `organization authenticated by HMAC == repository whose commit state is written`.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC with based on `repository_owner` taken from the *unverified* payload, then verifies the raw body against that secret: [1](#0-0) 

Once verification succeeds, this only proves the request was genuinely signed by the GitHub App installed for that particular organization/repository — it says nothing about which *other* organizations' data may be affected.

For most webhook handlers, this is fine because they explicitly scope by `repository.full_name`, e.g. the base `Handler#stacks` helper: [2](#0-1) 

However, `StatusHandler` never uses this scoping. It looks up commits purely by SHA, globally, across every stack/repository tracked by the Shipit instance: [3](#0-2) 

`Commit#create_status_from_github!` then unconditionally creates a `Status` row tied to `commit.stack_id` (the victim stack), using attacker-controlled `state`/`context`/`description`: [4](#0-3) [5](#0-4) 

**Attack path (equality broken):** `repository_owner` used to select the verifying secret ≠ `repository` whose commit actually receives the write.

1. Git commit hashes are deterministic (tree, parent, author, committer, message, timestamps). An attacker who can observe a target commit in a victim's (possibly public) tracked repository can reproduce a byte-identical commit object — and therefore an identical SHA — inside a completely unrelated repository/organization that the attacker legitimately controls and that is *also* tracked by the same Shipit instance (a common deployment shares one Shipit instance across many orgs/repos, as shown by the multi-org secrets format).
2. The attacker pushes that commit to their own repo and lets their own, legitimately-configured CI produce a genuine GitHub `status` webhook (`state: success`, arbitrary `context`) for their own org/repo. This webhook is correctly signed by GitHub with the attacker's own organization's `webhook_secret`, so `verify_signature` passes.
3. `StatusHandler#process` matches `Commit.where(sha: ...)` against the identical SHA that also exists in the **victim's** stack (because the victim's Shipit instance already recorded that commit from the victim repository), and writes a forged `success` status onto the victim's commit — regardless of the fact the signature only proved authenticity for the attacker's own organization.
4. This forged status can satisfy `ci.require`/`merge.require` checks (`StatusChecker`), which are used both for deploy eligibility (`Stack#deployable?` → `deployment_checks_passed?`) and by `MergeRequest#all_status_checks_passed?`/`reject_unless_mergeable!`, potentially causing Shipit to merge or deploy a commit whose real CI never validated it in the victim organization's context. [6](#0-5) 

### Impact Explanation
This satisfies the required "unauthorized deploy/rollback/merge" impact bar: an attacker with no access to the victim's repository, organization, session, ApiClient token, or webhook secret can, purely by controlling their own tracked (potentially throwaway) repository/org that shares the same Shipit deployment, forge a CI status that another organization's stack will trust for merge-queue and continuous-deployment gating decisions — effectively bypassing that organization's actual CI/CD checks.

### Likelihood Explanation
Exploitation requires: (a) the target Shipit instance to track repositories/organizations that don't fully trust each other (the documented multi-org configuration explicitly supports this), and (b) the attacker to reproduce an identical commit SHA in their own repo, which is feasible whenever the target commit's full metadata (tree, parents, author/committer identity and exact timestamps, message) is visible — e.g. any commit from a public GitHub repository, or one whose diff/patch is otherwise obtainable. No cryptographic collision is needed, only faithful replication of the commit object. This is a real, low-cost path once those preconditions hold, though it is limited to Shipit deployments that host multiple mutually-untrusting organizations/repos.

### Recommendation
Scope `StatusHandler#process` (and any other handler operating on shared identifiers such as SHAs) to commits belonging to the verified repository, mirroring what `Handler#stacks`/`repository_name` already does elsewhere:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```
This binds the authenticated repository (from the verified webhook payload) to the repository actually mutated, closing the gap.

### Proof of Concept
1. Attacker creates `attacker-org/throwaway-repo`, tracked by the same Shipit instance that also tracks `victim-org/victim-repo`.
2. Attacker crafts a commit object with the exact tree/parent/author/committer/timestamps/message of a known public commit `X` in `victim-org/victim-repo` (SHA `S`), and pushes it into `throwaway-repo` (git will compute the same SHA `S`).
3. Attacker's own CI (or a manual GitHub status API call the attacker is authorized to make on their own repo) posts a `status` webhook: `{sha: S, state: "success", context: "<victim's required context>", repository: {full_name: "attacker-org/throwaway-repo", owner: {login: "attacker-org"}}}`. GitHub signs this with `attacker-org`'s legitimate `webhook_secret`.
4. Shipit's `verify_signature` succeeds (secret matches for `attacker-org`).
5. `StatusHandler#process` finds `Commit.where(sha: S)` — which includes the victim's `Commit` row for `S` in `victim-org/victim-repo`'s stack — and calls `create_status_from_github!`, creating a `success` `Status` scoped to the victim's stack.
6. The victim's merge queue / continuous-deployment logic now considers commit `S` as passing the forged CI context, potentially triggering an unauthorized merge or deploy.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
