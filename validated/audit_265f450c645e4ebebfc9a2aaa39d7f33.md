### Title
Cross-repository status forgery via unscoped SHA lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook using only `Commit.where(sha: params.sha)`, with no filter on the repository the webhook actually originated from. This lets a validly-signed status event for one repository update `Status` rows (and thus `deployable?`/`UndeployedCommit#deploy_disallowed?`) for a `Commit` belonging to an entirely different `Stack`, as long as the SHA values collide.

### Finding Description
The binding that should hold is `commit.stack.repository.full_name == payload['repository']['full_name']` for every `Commit` updated by a status webhook. It does not: `Commit.where(sha: params.sha)` at [1](#0-0)  selects every commit row in the database sharing that SHA across all stacks/repositories, then calls `commit.create_status_from_github!(params)` on each one, which flips `Commit#status`/`deployable?` via `add_status` at [2](#0-1)  and [3](#0-2) . That change is what `UndeployedCommit#deploy_disallowed?` reads at [4](#0-3) .

Signature verification in `WebhooksController#verify_signature` only proves the request came from GitHub for the organization/app configuration resolved by `Shipit.github(organization: repository_owner)` [5](#0-4) ; in the common single-app deployment (`github_default_organization` nil), the same global `webhook_secret` is used regardless of the claimed organization [6](#0-5) . Signature verification therefore authenticates "this event came from GitHub for some repository this app is installed on," never "this event came from the specific repository the commit belongs to." Nothing downstream re-checks `payload['repository']['full_name']` against `commit.stack.repository`.

Because git commit SHAs are content-addressed, an attacker who can read the victim's commit content (public repo, or any repo they can view) can push an object-identical commit into a repository they own, then use GitHub's own Statuses API on that repo to set `state: success` for that SHA. GitHub signs and delivers the resulting `status` webhook exactly as for any legitimate event — no forged signature is needed because GitHub itself produces it for a real event on the attacker's own repository. `StatusHandler` then applies that status to every `Commit` row with the matching SHA, including the victim's, regardless of stack/repository.

### Impact Explanation
This is a payload for one repository mutating another stack's commit state, matching the "Critical" category (cross-tenant record mutation leading to unauthorized deploy). Concretely: `Commit#deployable?` and, through it, `UndeployedCommit#deploy_disallowed?` on stack A flip from blocking to permissive based on an event that never touched stack A's repository, presenting a false "ready to deploy" signal in the dashboard/API that a legitimate operator of stack A could act on to trigger a real deploy. Repeatable against any stack whose tracked commit SHA the attacker can reproduce in a repository they control.

### Likelihood Explanation
The attack requires: (1) the attacker's own repository to be covered by the same webhook signing configuration Shipit trusts (true by default in the common single global GitHub App/secret setup, or if attacker is any member of a multi-repo org where the app is installed org-wide), and (2) the attacker being able to reproduce the victim's exact commit object (feasible whenever the victim commit/tree content is visible, e.g. public repos or shared history/forks). No Shipit secrets, sessions, or API tokens are needed; the only cost is creating/controlling a repository and calling GitHub's own Statuses API on it. This is a moderate-cost but fully unprivileged, repeatable attack.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository named in the payload, not SHA alone — e.g. resolve `Stack`s whose `repository.full_name == params['repository']['full_name']` (or equivalent owner/name fields already parsed elsewhere in the controller) and restrict `Commit.where(sha: params.sha)` to those stacks' commits before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or `test/controllers/webhooks_controller_test.rb`):
1. Create `stack_a` bound to repo `victim/repo`, and `stack_b` bound to unrelated repo `attacker/repo`.
2. Create a `Commit` with `sha: "deadbeef"` on `stack_a` in a blocked/pending state; assert `UndeployedCommit.new(commit_a, index: 0).deploy_disallowed?` is `true`.
3. Also create a `Commit` with the same `sha: "deadbeef"` on `stack_b`.
4. POST (or directly call `StatusHandler.new.call`) a status payload with `sha: "deadbeef"`, `state: "success"`, `repository: { full_name: "attacker/repo" }`.
5. Reload `commit_a`; assert `commit_a.deployable?` is now `true` and `UndeployedCommit.new(commit_a, index: 0).deploy_disallowed?` is `false`, despite the payload's `repository.full_name` never equaling `stack_a`'s repository — demonstrating `commit.stack.repository.full_name == payload['repository']['full_name']` is violated.

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

**File:** app/models/shipit/undeployed_commit.rb (L39-41)
```ruby
    def deploy_disallowed?
      !deployable? || !stack.deployable?
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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```
