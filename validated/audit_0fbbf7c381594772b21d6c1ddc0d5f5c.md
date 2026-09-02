### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to update **only by their SHA**, with no check that the commit belongs to the repository/organization that the incoming, signature-verified webhook actually originated from. Because the `WebhooksController` only proves that the payload was signed by *some* configured GitHub organization's webhook secret — not that the `sha` inside the payload belongs to *that* organization's repository — an org that is a legitimate (but low-privilege, unrelated) tenant of a multi-organization Shipit instance can push a `status` webhook whose `sha` matches a commit that exists in a *different* tracked repository, and inject a fabricated CI status onto that unrelated commit.

### Finding Description
`WebhooksController#verify_signature` authenticates the webhook only against the organization derived from the payload's own `repository.owner.login` (or `organization.login`) field, using that organization's `webhook_secret`: [1](#0-0) 

This is the only authentication performed. Handlers are then invoked with the raw, verified-but-unscoped payload: [2](#0-1) 

The base `Handler` class defines the correct pattern for binding a webhook's data to *its own* repository, by resolving stacks through `repository.full_name`: [3](#0-2) 

`PushHandler` follows this pattern, scoping all writes to `stacks` (i.e., to the repository named in the payload): [4](#0-3) 

`StatusHandler`, however, does **not** use `stacks`/`repository_name` at all. It looks up commits globally by SHA across the entire database and writes a status onto every match: [5](#0-4) 

Since Git SHAs are content-addressed (derived from tree/blob content and parent SHAs, not from repository identity), it is entirely possible — and often trivial with cherry-picks, forks, shared vendored commits, subtree merges, or monorepo splits — for the same SHA to exist as a `Shipit::Commit` in two different `Stack`s belonging to two different organizations/repositories tracked by the same Shipit instance (Shipit explicitly supports multiple GitHub organizations sharing one install, each with its own webhook secret): [6](#0-5) 

This breaks the binding: **organization authenticated by the webhook signature ≠ repository whose commit status is written.** An attacker who controls (or has push/webhook rights on) their own legitimately-onboarded, properly-signed organization "OrgA" can craft a commit reproducing a target commit's SHA (or simply wait for a naturally colliding SHA, e.g. a shared dependency/vendored commit) and fire a real, correctly-signed `status` event from OrgA. `StatusHandler` will apply that status to **every** `Commit` row with the matching SHA, including ones belonging to `Stack`s of a completely unrelated organization "OrgB" that never authorized or reported that status.

Downstream, commit statuses gate merges and deploys: [7](#0-6) 

By injecting a forged `state: "success"` status with a `context` matching OrgB's required/blocking status name, an attacker without any access to OrgB can clear OrgB's CI gating and unblock a merge or deploy for a commit they do not control.

### Impact Explanation
This is the "organization that authenticated versus the repository that is written" binding-break pattern explicitly called out as in-scope. An unprivileged-relative-to-OrgB attacker (who is merely a legitimate/authenticated sender for a different, unrelated tenant organization OrgA on the same shared Shipit instance) can force a fabricated "success" CI status onto commits in OrgB's repositories, defeating `ci.require`/blocking-status protections and enabling an **unauthorized merge or deploy** — a Critical-severity outcome per the rubric ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly documented/supported configuration, not a misconfiguration), (2) the attacker legitimately controls webhooks for at least one tracked organization, and (3) a SHA collision between a commit they can produce and a target commit in another tracked repository. Natural SHA collisions across repos are realistic (forks, cherry-picks, shared vendored history, monorepo splits) and can also be deliberately engineered by crafting a commit with identical tree/parent/commit metadata to the target. No secret, GITHUB_TOKEN, or ApiClient token is needed — only a normal, validly signed webhook from an org the attacker already has legitimate access to.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records purely by SHA) to the repository the webhook actually originated from, mirroring the `Handler#stacks`/`repository_name` pattern already used by `PushHandler`:
```ruby
def process
  Repository.from_github_repo_name(repository_name)&.stacks&.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a webhook signed for organization X can only mutate commit/status state for stacks that belong to organization X's repository.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org setup).
2. Attacker controls a repo under `orgA` that is a Shipit stack. They craft/obtain a commit `C` whose SHA `deadbeef...` also exists as a tracked commit in `orgB/target-repo` (via fork/cherry-pick/shared history, or deliberate construction).
3. GitHub fires a `status` webhook for `orgA`'s repo referencing SHA `deadbeef...`, correctly HMAC-signed with `orgA`'s `webhook_secret`. `WebhooksController#verify_signature` passes because it only checks the org derived from `repository.owner.login`, which is `orgA` — consistent with the actual signature.
4. `StatusHandler#process` executes `Commit.where(sha: 'deadbeef...')`, which matches the commit row belonging to `orgB/target-repo`'s stack, and writes a `state: "success"` status with `context` equal to `orgB`'s required CI check name.
5. `orgB`'s `MergeRequest#all_status_checks_passed?` / merge-queue and deploy gating now see the forged success status and allow the commit to merge/deploy in `orgB`, even though `orgB` never ran or reported that check.

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

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
