This confirms a clear inconsistency: `CheckSuiteHandler` scopes its lookup through `stacks.where(branch: ...)` (repository-scoped via the `Handler#stacks`/`repository_name` helpers), while `StatusHandler` performs a completely unscoped `Commit.where(sha: params.sha)` across the entire database, ignoring the `repository` field in the payload entirely.### Title
Cross-repository/organization commit-status forgery via unscoped `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit supports multiple GitHub organizations/apps, each with its own `webhook_secret` used to verify inbound webhook signatures per `repository.owner.login` [1](#0-0) . However, once a `status` webhook's signature is verified for *its own* organization, the handler that processes it does not re-check that the `repository` field in the verified payload matches the repository that actually gets written to.

### Finding Description
`WebhooksController#verify_signature` looks up the GitHub App config keyed by `repository_owner` (derived from `params.dig('repository','owner','login')`) and verifies the signature using that organization's own `webhook_secret` [2](#0-1) . This binds the signature to "this payload came from organization X," but the `repository.full_name` field itself is never used to scope what gets mutated for the `status` event.

`StatusHandler#process` ignores the `Handler#stacks`/`repository_name` scoping helpers entirely and updates **every** commit in the entire database whose `sha` matches, regardless of which stack/repository it belongs to: [3](#0-2) 

Compare this to the sibling handlers that correctly scope by repository before touching any records:
- `PushHandler` scopes via `stacks.not_archived.where(branch:)` [4](#0-3) 
- `CheckSuiteHandler` scopes via `stacks.where(branch: ...)` before touching `stack.commits` [5](#0-4) 
- The shared `Handler` base class even defines `stacks`/`repository_name` for exactly this purpose [6](#0-5) 

`StatusHandler` is the outlier that never applies this scoping — an inconsistency directly analogous to the reported "inconsistent directives across the project" bug class, except here the inconsistency is in security-relevant scoping logic rather than pragma versions.

Because git commit SHAs are shared across forks and mirrors of the same underlying history, an attacker who controls a repository under **their own** legitimately-configured GitHub organization/App installation (attacker-controlled tenant, no privileged access to the victim's Shipit stack, org, or credentials) can trigger a real, validly-signed `status` webhook (e.g. by pushing a commit and having any CI system post a status, or by using the GitHub API status endpoint on their own repo, which they can freely do) for a commit SHA that is shared with (forked from, or otherwise present in) a completely different, unrelated stack/organization tracked by the same Shipit instance. The signature check passes because it is scoped only to the attacker's own organization, but the actual database write in `StatusHandler` is unscoped and updates the commit status on the victim's stack.

### Impact Explanation
Setting a fabricated `success` status on a victim commit can:
- Flip `Commit#deployable?` to true (`success? && !blocked?`) [7](#0-6) 
- Trigger `schedule_continuous_delivery` and enqueue `ContinuousDeliveryJob` for the victim stack if continuous deployment is enabled [8](#0-7) 
- Change `Stack#branch_status`/`merge_status`, unblocking the merge queue for pull requests in an unrelated repository [9](#0-8) 

This can cause an unrelated stack to deploy or merge code that never actually passed its own required CI checks — an unauthorized deploy/merge, matching the Critical impact bar ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires: (1) the target Shipit instance configured for multiple GitHub organizations (a documented, supported configuration — `docs/setup.md` "Using Multiple Github Applications") [10](#0-9) , (2) the attacker to legitimately operate one such tenant/organization's repository (no privileged access to the victim needed — this is exactly the kind of "malicious normal user of a legitimately-onboarded tenant" scenario), and (3) a shared commit SHA between the attacker's repo and the victim's tracked repo (trivially achievable for a fork of the victim's public/open-source repository, which is common for the projects Shipit targets). This is a realistic, low-privilege attack path rather than a purely theoretical one.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stacks belonging to the payload's own repository, matching the pattern already used by `PushHandler` and `CheckSuiteHandler`:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, ensuring every webhook handler consistently enforces the repository binding implied by the verified signature.

### Proof of Concept
1. Attacker configures/owns a repository `attacker-org/evil` which forks `victim-org/target` (shared git history, hence shared commit SHAs) — `attacker-org` is a legitimately onboarded GitHub organization with its own App installation and `webhook_secret` on the shared Shipit instance.
2. Attacker triggers a `status` event on `attacker-org/evil` for a commit SHA `abc123` that is also present (unmerged/undeployed) in `victim-org/target`'s tracked stack, with `state: success`.
3. GitHub signs the webhook with `attacker-org`'s `webhook_secret`; `WebhooksController#verify_signature` looks up `Shipit.github(organization: 'attacker-org')` and successfully verifies it [2](#0-1) .
4. `StatusHandler#process` runs `Commit.where(sha: 'abc123')`, which matches the commit in `victim-org/target`'s stack (no repository filter), and calls `commit.create_status_from_github!(params)`, marking it `success` in the victim's Shipit instance [3](#0-2) .
5. If `victim-org/target`'s stack has continuous deployment enabled, `ContinuousDeliveryJob` is scheduled and the commit is deployed/merged without ever having passed the victim's actual CI.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/stack.rb (L286-304)
```ruby
    def merge_status(backlog_leniency_factor: 2.0)
      return 'locked' if locked?
      return 'failure' if %w[failure error].freeze.include?(branch_status)
      return 'backlogged' if backlogged?(backlog_leniency_factor:)

      'success'
    end

    def backlogged?(backlog_leniency_factor: 2.0)
      maximum_commits_per_deploy && (undeployed_commits_count > maximum_commits_per_deploy * backlog_leniency_factor)
    end

    def branch_status
      undeployed_commits.each do |commit|
        state = commit.status.simple_state
        return state unless %w[pending unknown missing].freeze.include?(state)
      end
      'pending'
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
