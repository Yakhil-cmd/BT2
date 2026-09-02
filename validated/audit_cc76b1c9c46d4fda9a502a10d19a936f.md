### Title
Cross-repository forgery of commit CI status via unscoped `Commit.where(sha:)` lookup in webhook `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an incoming webhook against a specific GitHub organization/app derived from the payload's `repository.owner.login` (or `organization.login`) field. [1](#0-0)  However, `StatusHandler#process`, which actually writes state, never checks that the commit it updates belongs to a repository owned by that authenticated organization — it looks up commits globally by SHA across the entire `commits` table. [2](#0-1)  This breaks the binding: *organization authenticated by the webhook signature* == *repository whose commit state is written*.

### Finding Description
The base `Handler` class exposes a `repository_name`/`stacks` helper that scopes handler logic to the repository named in the payload. [3](#0-2)  Most handlers (e.g. push) use this scoping. `StatusHandler`, however, does not use `stacks`/`repository_name` at all — it calls:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`Commit` records are global to the Shipit installation and belong to whichever `Stack`/`Repository` they were synced from; SHAs are not namespaced per organization. Meanwhile, the signature verification that gates the whole webhook is scoped per-organization:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end
``` [4](#0-3) 

In a multi-organization deployment (explicitly documented and supported — each org has its own `app_id`/`webhook_secret`/`oauth` config), [5](#0-4)  the equality the system relies on is:
`organization whose secret signed the request` == `organization owning the repository whose commit/status is mutated`.

`StatusHandler` never enforces this equality: as long as a request is validly signed for *any* onboarded organization, it can create/overwrite a `Status` for *any* `Commit` row in the database that happens to share the same SHA, regardless of which `Stack`/`Repository` that commit belongs to. Git SHAs are shared across forks and mirrors (any repository sharing history with a victim repository — including a legitimately admin-controlled fork in a separate onboarded organization — contains identical commit SHAs for the shared history). An attacker who administers such a fork/mirror repository already has legitimate write access to their own repo's commit statuses (this is normal CI usage, not a privileged Shipit credential), so GitHub will emit a validly-signed `status` webhook for their organization pointing at a SHA that also exists in the victim's stack.

### Impact Explanation
`Status` records feed directly into `Commit#deployable?` and the `required_statuses`/CI gating computed from `deploy_spec` (`required_statuses`, `blocking_statuses`, etc., in `app/models/shipit/deploy_spec.rb`). [6](#0-5)  By forging a `success` status for a required CI context on a commit that is shared (via fork/mirror history) with a victim stack, an attacker can flip a victim commit from "not deployable" to "deployable" without ever authenticating to the victim's organization or possessing the victim's webhook secret. This can result in an **unauthorized deploy** of a commit whose real CI checks in the victim's own organization never passed — satisfying the "unauthorized deploy" Critical impact criterion, since the CI-gating binding is a load-bearing part of Shipit's deploy-safety model, and it is broken purely through the request/response of a single crafted (but validly signed, for a different org) webhook.

### Likelihood Explanation
Likelihood is moderate-to-high in any Shipit deployment that (a) tracks multiple GitHub organizations/repositories (a documented, supported configuration) and (b) has a victim repository that is forked or mirrored into another onboarded organization admin-controlled by a different party — a common pattern for internal tooling, vendored repos, or organizations that fork upstream projects into their own namespace before deploying. No repository write access, GitHub App private key, or victim webhook secret is required; the attacker only needs legitimate control of their own onboarded org's repository (to trigger a real, validly-signed status webhook) and knowledge of a shared commit SHA (trivially obtainable, since SHAs of shared ancestry are identical and public).

### Recommendation
Scope `StatusHandler#process` (and any other handler that mutates state based only on `sha`) to the repository/stacks derived from the payload's `repository.full_name`, mirroring the base `Handler#stacks` helper, e.g. restrict the `Commit.where(sha:)` lookup to `stacks.flat_map(&:commits)` or add an explicit check that `commit.stack.repository == Repository.from_github_repo_name(repository_name)` before calling `create_status_from_github!`.

### Proof of Concept
Conceptual sequence (cannot be executed without a live multi-org Shipit instance; described from code inspection):
1. Shipit is configured for two organizations, `victim-org` and `attacker-org`, each with its own GitHub App / `webhook_secret` (per `docs/setup.md` multi-app config).
2. `attacker-org/some-repo` is a fork/mirror of `victim-org/app`, sharing commit history/SHAs, and is legitimately administered by the attacker.
3. `victim-org/app` has a Shipit stack requiring CI context `ci/tests` to pass before deploy (`required` in `shipit.yml`).
4. Attacker pushes a real commit or sets a real GitHub Status via the API on `attacker-org/some-repo` for SHA `abc123...` (a SHA shared with the victim's un-passed commit) with `state: success`, `context: ci/tests`. GitHub sends a `status` webhook, signed with `attacker-org`'s real webhook secret.
5. `WebhooksController#verify_signature` verifies successfully because it validates the signature using `Shipit.github(organization: 'attacker-org')`. [4](#0-3) 
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, finds the victim's commit row (unrelated to `attacker-org`), and calls `create_status_from_github!`, marking the victim's commit as passing `ci/tests`. [2](#0-1) 
7. The victim commit now satisfies `required_statuses`, becoming deployable and eligible for an unauthorized deploy on `victim-org/app`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
```

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
