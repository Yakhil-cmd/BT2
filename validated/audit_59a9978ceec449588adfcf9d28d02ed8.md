### Title
Webhook signature verification keys on an attacker-chosen organization while the event handlers act on an attacker-chosen, unrelated repository/commit — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to validate an inbound webhook based on `repository_owner`, a field read directly out of the unauthenticated JSON body, then hands the *same unauthenticated body* to the event handlers, which resolve the target `Stack`/`Commit` from a different field (`repository.full_name`, or nothing at all for status events). Nothing binds the organization whose secret validated the signature to the repository/commit the handler actually mutates.

### Finding Description
`verify_signature` computes: [1](#0-0) 

`repository_owner` is derived purely from the JSON body the requester sent (`params.dig('repository','owner','login')`), not from anything cryptographically verified yet: [2](#0-1) 

Once `Shipit.github(organization: repository_owner).verify_webhook_signature` succeeds, `create` dispatches the **entire body** to handlers: [3](#0-2) 

Handlers, however, resolve the actual `Stack` via a *different* field in the same body: [4](#0-3) 

Because the webhooks endpoint has no session/token requirement (it's meant to be called by GitHub, but authentication is solely the HMAC check), any actor who controls a GitHub App/organization of their own (and therefore knows that organization's own `webhook_secret`, which they set themselves when creating their App) can:

1. Set `repository.owner.login` = `attacker-org` (so `verify_signature` looks up and checks against the attacker's own known secret and succeeds).
2. Set `repository.full_name` = `victim-org/victim-repo` (or, for the `status` event, simply supply a `sha` belonging to a commit tracked under any stack).

`PushHandler` and `CheckSuiteHandler` use `repository_name` (i.e. `full_name`) to look up `stacks`, so a forged push/check_suite event signed with the attacker's own secret can trigger `stack.sync_github` or `schedule_refresh_check_runs!` on a victim's stack: [5](#0-4) [6](#0-5) 

`StatusHandler` is worse: it does not scope by repository at all, only by commit `sha`, which is a globally-visible, non-secret value: [7](#0-6) 

This lets the attacker inject an arbitrary CI status (`state`, `context`, `description`, `target_url`) onto any commit in any stack tracked by this Shipit instance, as long as they can guess/observe that commit's SHA (trivial — SHAs are visible in any public or accessible repo, PRs, or even leaked via other Shipit UI). Commit statuses are consumed by `Stack#blocking_statuses`/`required_statuses` to gate deploys and by the merge queue to decide mergeability, so forging a "success" status can unblock a deploy or a PR merge that should have been blocked — this is the same class of bug as the reported `checkLog`: the code queries/authorizes with one field (`block.timestamp` / `repository_owner`) but acts on data tied to a different, uncontrolled field (`log.timestamp` / `repository.full_name` or bare `sha`), breaking the intended one-to-one binding between the authenticated identity and the target of the action.

Equality that should hold but doesn't: `organization_whose_secret_validated_signature == organization_owning_the_repository_that_gets_mutated`. Before the attack, this holds trivially because real GitHub webhooks are self-consistent. After a forged request from an attacker-controlled org/app, `repository_owner` (attacker-controlled org, secret known to attacker) diverges from the repository/stack/commit actually acted upon (victim's), while the signature still validates.

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy or merge" boundary described in-scope: an actor who controls nothing more than their own GitHub App/org secret can forge status/push/check_suite events that mutate state (commit statuses, sync triggers, check-run refreshes) belonging to a completely different, victim-owned stack tracked by the same Shipit instance. Forged commit statuses in particular can flip `blocking_statuses`/`required_statuses` outcomes, enabling an unauthorized deploy or merge-queue action on a repository the attacker has no access to.

### Likelihood Explanation
Requires only that the attacker operate their own GitHub organization/App with Shipit configured for multi-org webhook secrets (`config[:webhook_secret]` per organization, as supported by `lib/shipit/github_app.rb`), which is an ordinary, unprivileged setup — no access to the victim's secrets, tokens, or repository is needed. The only "guess" needed for the `status` path is a valid commit SHA, which is public information.

### Recommendation
Bind the field used to pick the verification secret to the field used to resolve the mutated resource: derive `repository_owner` (or the full repository) once, verify the HMAC using that organization's secret, and then re-validate inside each handler that the resolved `Stack`'s repository actually belongs to that same verified organization (e.g., compare `stack.repository.owner` to the verified `repository_owner`) before applying any mutation. For `StatusHandler` specifically, scope the `Commit` lookup by `stack.github_repo_name == repository_name` rather than by bare `sha` across all stacks.

### Proof of Concept
1. Attacker creates their own GitHub App for `attacker-org` in Shipit's multi-org config, setting `webhook_secret = "s3cr3t"` (they know this value because they set it).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/irrelevant-repo" },
  "sha": "<known sha of a commit in victim-org/victim-repo tracked stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
   with `X-Hub-Signature: sha1=<hmac-sha1(body, "s3cr3t")>`.
3. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature against the attacker's own secret. [8](#0-7) 
4. `create` dispatches to `StatusHandler`, which finds `Commit.where(sha: params.sha)` — the victim's commit — and calls `commit.create_status_from_github!(params)`, creating a forged "success" status on the victim's stack despite the signature only ever having been validated against the attacker's own organization's secret. [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
