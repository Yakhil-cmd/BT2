### Title
Webhook signature is verified against an attacker-chosen organization while the mutated repository/commit is taken from an unverified field in the same payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to validate a webhook against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the attacker-supplied JSON body, then HMAC-verifies the raw POST body against that organization's `webhook_secret`. [1](#0-0) 
Every downstream handler, however, resolves the repository/stack (or, for `status` events, does not even scope by repository at all) using a *different*, independently-controlled field of the same body: `repository.full_name` for `push`/`check_suite`, and a global `Commit.where(sha: params.sha)` scan for `status`. [2](#0-1) [3](#0-2) 

### Finding Description
The equality that should hold is: **organization whose secret authenticated the payload == repository/commit that the handler mutates**. Nothing enforces this.

`verify_signature` derives the signing organization from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and looks up `Shipit.github(organization: repository_owner)` to get that organization's `webhook_secret`, then verifies `X-Hub-Signature` against the raw body with that secret. [4](#0-3) [5](#0-4) 

Anyone who legitimately knows one organization's `webhook_secret` — e.g. a member of a tenant organization onboarded to this same Shipit instance who created/administers that org's GitHub App — can forge an arbitrary raw body, keep `repository.owner.login`/`organization.login` equal to their own org (so the secret lookup and HMAC both succeed), and independently set `repository.full_name` to any other tracked repository, or simply post an arbitrary `sha`/`state` for the `status` event.

Handlers never re-check that the repository they act on belongs to the organization whose secret authenticated the request:
- `Handler#stacks` resolves `Repository.from_github_repo_name(repository_name)` purely from `payload.dig('repository', 'full_name')`, a field the signing check never inspects. [6](#0-5) 
- `PushHandler#process` then triggers `stack.sync_github(expected_head_sha:)` on whichever stacks match that forged `full_name`/branch. [7](#0-6) 
- `CheckSuiteHandler#process` schedules `schedule_refresh_check_runs!` on commits of stacks resolved the same unchecked way. [8](#0-7) 
- `StatusHandler#process` is worse: it doesn't even use `repository_name`; it matches **globally** on `Commit.where(sha: params.sha)` across the whole database and calls `commit.create_status_from_github!(params)`, letting a forger set an arbitrary `state`/`context`/`description` for any commit belonging to any repository/organization tracked by the instance. [3](#0-2) 

This directly parallels the reported bug class: a check exists (`verify_signature`) that is supposed to bind an authenticated identity to an operation, but a downstream, security-relevant mutation instead reads its target from a sibling field of the payload that the check never correlates with the authenticated identity.

### Impact Explanation
Commit statuses gate CI requirements (`ci.require`) used by Shipit to decide whether a commit is safe to deploy, and by the merge queue to decide whether to merge a PR. An organization member who only administers their own org's GitHub App (an "unprivileged" party with respect to any other tenant on the shared Shipit instance) can forge a `status` webhook that flips an arbitrary commit belonging to a different, unrelated repository to `success`, bypassing that other repository's CI gating and enabling an unauthorized deploy or merge-queue merge on a stack they have no legitimate access to. This satisfies the "unauthorized deploy, rollback, or merge" Critical-impact criterion, and the `push`/`check_suite` cross-repository trigger additionally lets a forger cause the engine to sync/refresh check state for a repository outside their authorization boundary.

### Likelihood Explanation
The prerequisite — knowing one organization's own `webhook_secret` on a multi-tenant Shipit deployment — is attacker-plausible without any Shipit session, `ApiClient` token, or GitHub App private key: it only requires being the person (or one of the people) who configured that organization's own GitHub App integration, which is a normal, unprivileged-with-respect-to-other-tenants role. No repository write access to the *victim* repository is needed, and no interception of TLS or the victim's secret is required, since the attack only reuses the *attacker's own* valid secret against a *forged* `repository.full_name`/`sha`.

### Recommendation
After `verify_signature` succeeds, re-derive `repository_owner`/organization strictly server-side and enforce that every handler's resolved repository (`Repository.from_github_repo_name(repository_name)`) actually belongs to that same verified organization before performing any mutation; reject the request otherwise. For `StatusHandler`, scope `Commit.where(sha:)` to commits whose stack's repository owner matches the verified organization, not a global lookup.

### Proof of Concept
1. Attacker is a member of `org-attacker`, which has its own GitHub App configured in this shared Shipit instance with `webhook_secret = S` (known to the attacker because they set it up).
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-repo-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/some-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S, body)` themselves (valid, since it's their own secret) and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner = "org-attacker"`, fetches `org-attacker`'s `webhook_secret` (`S`), and the HMAC check passes because the attacker legitimately knows `S`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim repository's commit regardless of `org-attacker` — and calls `create_status_from_github!`, marking that commit's CI status as `success` in a repository the attacker has no access to, which can unblock its deploy/merge gating.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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
