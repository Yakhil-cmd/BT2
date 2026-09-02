### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no repository or stack scoping, then writes the attacker-supplied `context`/`state` onto every matching `Commit` record. Because `verify_signature` only authenticates that the *sender* organization is legitimate (via its own `webhook_secret`), and not that the `sha` in the payload actually belongs to a commit owned by that organization's repository, an attacker who controls a repository onboarded to the same Shipit instance can craft a `status` webhook for a SHA that is shared with (or collides with) a commit in a victim's stack, and have `success`/`failure` states applied to the victim's commit.

### Finding Description
The broken binding: the code implicitly assumes `Commit.sha == params.sha` implies `Commit.stack.repository == repository_owner(payload)`, but no such constraint is enforced.

- `Shipit::WebhooksController#create` parses the payload and dispatches to handlers after `verify_signature` [1](#0-0) .
- `verify_signature` resolves `Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and validates the HMAC signature against **that org's own `webhook_secret`** [2](#0-1) . This only proves the request was sent by (or forged with the secret of) the organization named in the payload — it does not tie the specific `sha` in the payload to that organization's actual repository.
- `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This query is **global across all stacks/repositories** — `Commit` has no repository-scoping predicate here, only `sha`.
- `create_status_from_github!` -> `add_status` recomputes `Status::Group` and, if the simple state changes, emits `deployable_status`/`commit_status` hooks and calls `stack.schedule_merges` [4](#0-3) [5](#0-4) .
- `deployable?` is directly driven by this recomputed status: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [6](#0-5) .

Exploit flow: an attacker who owns/controls a repository already configured in Shipit (with its own valid `github_app`/`webhook_secret` config, which they can compute or send from a real GitHub webhook of their own repo) sends `POST /webhooks` with `X-Github-Event: status`, body `{"repository": {"owner": {"login": "attacker-org"}}, "sha": "<victim-sha>", "context": "ci/jenkins", "state": "success"}`. `verify_signature` passes because it validates against `attacker-org`'s own webhook secret. `StatusHandler#process` then updates **any** `Commit` row anywhere in the database whose `sha` equals `<victim-sha>` — including one belonging to a victim's stack — flipping `ci/jenkins` to `success` and potentially making the victim commit `deployable?` and eligible for merge/auto-deploy.

Existing guards fail here because:
- `verify_signature` authenticates the *organization named in the payload*, not a binding between that organization and the `sha`/`stack` being mutated.
- `drop_unhandled_event`/`ExplicitParameters` only validate that required params (`sha`, `state`) are present with correct types; they impose no repository-ownership constraint.
- There is no model validation in `Commit`/`Stack` preventing cross-stack `sha` collisions, and no repository-scoped predicate added to the `Commit.where(sha:)` query.

The precondition of "SHA shared with a victim stack" is realistic in real GitHub topologies: forks share ancestor commits with upstream, cherry-picks/rebases across mirrored/forked repos preserve SHAs, and any commit that exists identically in both the attacker's and a victim's repository (e.g., a shared base branch, a vendored commit, or an intentionally crafted commit with identical tree/parents/author/timestamp/message to force SHA equality) triggers this.

### Impact Explanation
A successful request causes a `Commit` status write for a repository/stack that never authenticated the event — this is a payload for one repository mutating another's commit/stack state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). Concretely, this can flip a victim's commit `deployable?` state to `true` for a required CI context (e.g. `ci/jenkins`), potentially triggering `ContinuousDeliveryJob`/`schedule_merges` and thus an unauthorized deploy or merge of attacker-controlled/untested code. The attack is repeatable against any repository/stack sharing or colliding on a SHA with an attacker-controlled repository, and its blast radius spans all tenants hosted on the same Shipit instance.

### Likelihood Explanation
Preconditions: the attacker must control at least one repository/org already configured in the shared Shipit instance (so `Shipit.github(organization: repository_owner)` resolves and `verify_signature` can pass with a secret the attacker can produce — either their own legitimate GitHub App webhook delivery, or knowledge of that org's `webhook_secret`), and a SHA collision/sharing with the victim's commit (achievable via forks, shared ancestry, or crafted identical commits). Given multi-tenant Shipit deployments where many orgs/repos are onboarded, and that ordinary GitHub fork/rebase workflows naturally produce shared SHAs across repositories, this is feasible without needing any Shipit secrets beyond what the attacker's own onboarded repository already provides, and is fully repeatable per victim SHA.

### Recommendation
Scope the status update to only commits belonging to a stack whose repository matches the authenticated `repository_owner`/`repository.full_name` from the payload, e.g. change `StatusHandler#process` to filter `Commit.joins(:stack).where(sha: params.sha, stack: { ... repository matching payload ...})`, or pass the verified repository context from the controller into the handler and require `commit.stack.repository.owner == repository_owner && commit.stack.repository.name == payload repo name` before calling `create_status_from_github!`.

### Proof of Concept
```ruby
test "status handler leaks status across repositories sharing a sha" do
  victim_stack = shipit_stacks(:shipit) # requires ci.require including 'ci/jenkins'
  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit")

  attacker_stack = create_stack(repo_owner: "attacker-org", repo_name: "attacker-repo")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "attacker commit")

  before_status = victim_commit.reload.status.state
  before_deployable = victim_commit.deployable?
  assert_not_equal 'success', before_status

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/jenkins'
  }
  Shipit::Webhooks::Handlers::StatusHandler.new.call(payload) # simulates authenticated attacker-org delivery

  victim_commit.reload
  assert_equal 'success', victim_commit.status.state, "victim commit status was mutated by attacker-authenticated webhook"
  assert_not_equal before_deployable, victim_commit.deployable?, "victim commit deployability changed due to cross-repo status write"
end
```
This demonstrates the binding `Commit.where(sha:).stack.repository == authenticated repository_owner` is not enforced, and that a status event authenticated only for `attacker-org` mutates `victim_stack`'s commit state and `deployable?`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
