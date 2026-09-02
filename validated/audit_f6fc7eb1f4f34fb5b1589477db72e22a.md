### Title
Cross-repository `Status` forgery neutralizes the `require_ci` deploy gate via unscoped `Commit#deployable?` - (File: `app/controllers/shipit/api/deploys_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` writes CI `Status` rows by matching `sha` alone across the entire `commits` table, with no check that the commit's owning stack/repository matches the organization whose `webhook_secret` authenticated the inbound webhook. Because `Shipit::Api::DeploysController#create`'s `require_ci` gate (line 22) trusts `Commit#deployable?`, which is derived purely from these unscoped `Status` rows, a webhook signed by org A can poison the CI state of a commit that actually belongs to org B's stack, causing `require_ci: true` to be satisfied for a commit whose real CI never passed.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:

`org(commit.stack.repository) == org(webhook_secret used in verify_signature for this payload)`

Tracing the code:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) selects the HMAC key via `Shipit.github(organization: repository_owner)`, where `repository_owner` comes from `params.dig('repository', 'owner', 'login')` in the *same attacker-controlled JSON body*. This only proves the payload was signed by *some* org configured in this Shipit instance (the attacker's own org, if they administer a repo/stack tracked by the same central Shipit deployment) — it proves nothing about which commit the `sha` field inside the payload actually belongs to. [1](#0-0) 
- `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it resolves the target commit purely by SHA equality, globally, across every stack/repo Shipit tracks, and never compares `commit.stack.repository_owner`/`repository_name` against the webhook's authenticated organization. [2](#0-1) 
- `Commit#deployable?` is computed solely from those `Status`/`CheckRun` rows: `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, with `success?` delegated to `status` (`Status::Group.compact(self, statuses_and_check_runs)`). [3](#0-2) 
- `Shipit::Api::DeploysController#create` gates `require_ci` purely on this value: `param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?`. [4](#0-3) 

Exploit flow: the attacker administers (or can send authenticated webhooks for) an org/repo tracked by the same Shipit instance as the victim stack — a realistic scenario in a multi-tenant deployment, and made trivial when the attacker forks the victim's public repository, since forked history shares identical commit SHAs with the upstream. The attacker sends `POST /webhooks` with `X-Github-Event: status`, a valid signature computed from their own org's `webhook_secret`, `repository.owner.login` set to their own org, but the JSON `sha` field set to the victim's commit SHA and `state: success` (optionally matching a `context` the victim stack requires). `StatusHandler` writes this forged success `Status` onto the victim's `Commit` row because it never validates repo ownership. Any legitimate caller with a `deploy` `ApiClient` token who later calls `POST /stacks/:id/deploys` with `require_ci: true` for that commit — trusting `require_ci` as an integrity control — will pass the gate at line 22 even though the victim repo's real CI never ran or passed for that commit.

No existing guard prevents this: `verify_signature` only authenticates the org that sent the request, not the target of the `sha` field; `StatusHandler`'s `ExplicitParameters` schema only validates types, not ownership; `require_permission :deploy, :stack` in `DeploysController` authenticates/authorizes the deploy caller but says nothing about whether the *status data itself* originated from the correct repository.

### Impact Explanation
A `Status` write intended for one repository is accepted and applied to a commit belonging to a different, unrelated stack, and that forged status is then consumed by an integrity gate (`require_ci`) to authorize a deploy that should have been blocked. This is a cross-tenant write (forged CI state written for a repository that did not authenticate it) that directly enables an unauthorized deploy of unvetted code — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). The attack is repeatable against any commit SHA the attacker can discover (commit SHAs are not secret) and against any stack tracked by the same Shipit instance, as long as any caller uses `require_ci: true` trusting `deployable?` as an integrity signal.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit instance tracking more than one org/repo, where the attacker administers or controls webhook delivery for at least one tracked repo (e.g., via a fork sharing SHAs with the victim's public repo); (2) some caller relying on `require_ci: true` for the victim stack. The attacker needs no Shipit session, API token, or victim-side secret — only their own legitimately-issued webhook secret for their own tracked org, which is a low-cost, fully attacker-controlled precondition. `StatusHandler`'s lack of repo-scoping makes the forgery itself deterministic and repeatable per SHA.

### Recommendation
In `Commit.create_status_from_github!` / `StatusHandler#process`, scope the commit lookup by the authenticated repository (e.g., match `commit.stack.repository_owner`/`repository_name`, or `commit.stack_id`, against the webhook's verified `repository_owner`/`full_name`) before writing any `Status`, rejecting or ignoring status payloads whose claimed repository doesn't own the target commit's stack.

### Proof of Concept
In `test/controllers/api/deploys_controller_test.rb` (or a new `StatusHandler`/`DeploysController` integration test):
1. Create `stack_victim` (owned by `victim/repo`) with a commit `commit = stack_victim.commits.create!(sha: 'a' * 40, ...)`, and `stack_attacker` (owned by `attacker/repo`).
2. Assert baseline: `commit.deployable?` is `false` (no successful status exists) — LHS of the binding: `commit.stack.repository_owner == 'victim'`.
3. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new(...).call(sha: commit.sha, state: 'success', context: 'ci')` (simulating a webhook whose signature was verified against `attacker`'s `webhook_secret`, i.e., RHS org == `attacker`) directly, bypassing HTTP-level signature machinery but exercising the exact unscoped `Commit.where(sha:)` lookup.
4. Assert `commit.reload.deployable?` is now `true` despite `commit.stack.repository_owner != 'attacker'` — proving `LHS != RHS` yet the write succeeded.
5. As an authenticated `ApiClient` with `deploy` permission on `stack_victim`, `POST /stacks/#{stack_victim.id}/deploys` with `sha: commit.sha, require_ci: true`.
6. Assert response status `:accepted` (not `422 param_error`), proving the `require_ci` gate at `app/controllers/shipit/api/deploys_controller.rb:22` was satisfied solely by the forged cross-repo status.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
```
