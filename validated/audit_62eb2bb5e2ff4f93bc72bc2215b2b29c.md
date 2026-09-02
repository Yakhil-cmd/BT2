### Title
Cross-Organization CI Status Forgery via Unscoped `sha` Lookup in `StatusHandler` Leads to Unauthorized Continuous Deployment - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub webhook by looking up the `Shipit::GithubApp` (and its `webhook_secret`) for the *organization named in the payload* (`repository.owner.login` / `organization.login`), then verifying the HMAC signature against that org's secret. This proves only that the request was signed by **some** organization configured on this Shipit instance. However, `Shipit::Webhooks::Handlers::StatusHandler` (invoked for the `status` event) never re-checks that the commit it mutates actually belongs to a stack tracking that same, verified organization/repository — it matches purely on the git `sha` across the entire database.

### Finding Description
The base `Handler` class defines a `stacks` helper that properly scopes work to the repository named in the payload: [1](#0-0) 

Most handlers (`PushHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`) use this `stacks`/`repository` scoping before acting: [2](#0-1) [3](#0-2) 

`StatusHandler`, by contrast, ignores the `repository`/`stacks` scoping entirely and resolves the target purely by SHA, globally: [4](#0-3) 

Meanwhile, signature verification is performed once per request, keyed only by the organization named in the payload: [5](#0-4) [6](#0-5) 

This is a real, deployed multi-tenant configuration pattern (multiple GitHub orgs, each with its own `webhook_secret`, registered on one Shipit instance): [7](#0-6) 

**Equality broken:** `organization authenticated by verify_signature (repository.owner.login)` ≠ `stack/repository whose commit row is written (Commit.where(sha:).stack)`.

**Before the attack:** For any org B legitimately configured on the shared Shipit instance, an attacker who controls org B's GitHub App/webhook (a normal, unprivileged tenant of the same Shipit deployment, not org A) can only affect stacks belonging to repositories under org B.

**After the attack:** Because git commit SHAs are content-addressed and independent of which repository hosts them, the attacker can construct (or otherwise obtain) a commit in a repository under their own org B whose SHA1 matches a commit SHA that already exists in a stack under victim org A (e.g., an open-source dependency commit, a previously public commit, or one the attacker learns via Shipit's public timeline/API). The attacker then triggers (or GitHub sends, since they own that repo) a `status` webhook for org B, signed with org B's own valid `webhook_secret`. It passes `verify_signature` (org B is a legitimate org). `StatusHandler#process` then does `Commit.where(sha: params.sha)`, which matches the victim's org‑A commit too, and calls `commit.create_status_from_github!(params)` on it — writing an attacker-controlled `state`, `context`, `description`, and `target_url` onto a commit belonging to a stack the attacker has no access to.

### Impact Explanation
`Status` creation has significant automated side effects unrelated to authorization: [8](#0-7) 
and on `Commit`: [9](#0-8) 

If the target stack has `continuous_deployment` enabled and the forged status satisfies the stack's required CI contexts, this forged "success" status can cause Shipit to schedule and execute an **unauthorized deploy** of the victim stack — matching the Critical-severity criterion for "an unauthorized deploy" via a boundary an attacker never should have been able to cross (their webhook credentials for org B, acting on org A's data). Even short of triggering CD, this allows unauthenticated (with respect to org A) forgery of CI/status state on arbitrary commits, corrupting the merge queue's status checks (`MergeRequest.required_statuses` / `all_status_checks_passed?`), which can similarly gate an unauthorized merge.

### Likelihood Explanation
This requires the attacker to control at least one legitimate (but unprivileged w.r.t. the victim) organization/GitHub App integration on the same shared Shipit instance — a realistic scenario for any multi-tenant/self-hosted deployment. SHA collision here is not a cryptographic collision — it only requires reproducing an existing commit (same tree/parent/author metadata) in a repo the attacker controls, which is straightforward for public/open-source-derived commits, or feasible in any shared/forked repository history. `CheckSuiteHandler` shows the codebase already knows how to correctly scope by `stacks`/branch — `StatusHandler`'s omission is a clear, isolated regression, not a hardened design choice.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving objects only by content hash) through `stacks`/`repository`, mirroring `Handler#stacks`, so that a `status` webhook can only mutate commits belonging to stacks whose repository matches the organization/repository verified in `verify_signature`. For example, restrict `Commit.where(sha: params.sha)` to `stacks.joins(:commits).where(commits: { sha: params.sha })` (or equivalent), ensuring the commit's stack's repository full name matches `repository_name` from the payload.

### Proof of Concept
1. Configure Shipit with two orgs, `victim-org` and `attacker-org`, each with distinct `webhook_secret`s (a supported/documented multi-org configuration, see `config/secrets.development.shopify.yml`).
2. Attacker controls `attacker-org` and creates/pushes a commit whose SHA1 is identical to an existing commit SHA already tracked by a stack under `victim-org` (e.g., by replicating the exact tree/parent/author/committer metadata of a known public commit).
3. Attacker (or GitHub, since it's their repo) sends a `status` webhook event to `POST /webhooks` with:
   - `X-Github-Event: status`
   - `X-Hub-Signature` computed with `attacker-org`'s real `webhook_secret`
   - body: `{"sha": "<colliding-sha>", "state": "success", "context": "<required-context-for-victim-stack>", "target_url": "https://attacker.example/fake", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/some-repo"}}`
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature (`lib/shipit/github_app.rb:76-83`).
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, which matches the commit in `victim-org`'s stack, and calls `create_status_from_github!`, creating a forged `Status` row on the victim's commit — potentially triggering `schedule_continuous_delivery` and an unauthorized deploy of `victim-org`'s stack.

Note: I could not execute this against a live instance from static analysis alone; the SHA-collision precondition (reproducing an identical commit in a different repository) is asserted based on git's content-addressed commit model and is not verified experimentally here.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```

**File:** app/models/shipit/commit.rb (L24-25)
```ruby
    after_commit :schedule_refresh_statuses!, :schedule_refresh_check_runs!, :schedule_fetch_stats!,
                 :schedule_continuous_delivery, on: :create
```
