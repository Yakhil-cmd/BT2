### Title
Cross-organization commit-status forgery via unscoped SHA lookup in `StatusHandler` breaks the "authenticated organization = repository written" binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted JSON payload [1](#0-0) [2](#0-1) . Shipit explicitly supports hosting multiple, unrelated GitHub organizations on one instance, each with its own `webhook_secret` [3](#0-2) [4](#0-3) , and `Shipit.github(organization:)` looks the secret up per-org [5](#0-4) .

Once the signature is accepted for organization X, the raw JSON body is dispatched unchanged to event handlers [6](#0-5) . For `status` events, `StatusHandler#process` never re-checks that the commit belongs to a stack owned by the authenticating organization — it matches purely by `sha` across the entire database:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [7](#0-6) 

This breaks the binding: **organization that authenticated the webhook signature ≠ repository/commit that is written**. An attacker who legitimately administers their own onboarded GitHub org (org "B", knows its own `webhook_secret` because they configured it during app installation) can forge a `status` webhook, set `repository.owner.login = "B"` to pass signature verification, and set `sha` to a commit SHA belonging to a completely different tenant's ("A") tracked stack. Because `Commit.where(sha:)` has no repository/stack scoping, the forged status is applied to org A's commit.

### Finding Description
- Signature verification org selection: `repository_owner` is read straight from `params.dig('repository','owner','login')` [2](#0-1) , then used to fetch the appropriate `GitHubApp`/secret via `Shipit.github(organization: repository_owner)` [8](#0-7) . The HMAC itself covers the entire raw body (`OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message)` in `lib/shipit/github_app.rb`), but nothing ties the *content acted upon* (the `sha` field) to the organization used to select the secret.
- `Handler` base class does compute `repository_name` from `payload.dig('repository','full_name')` for scoping purposes [9](#0-8) , and most PR handlers correctly scope through `Repository.from_github_repo_name(...)`. `StatusHandler`, however, does not use this at all; it looks up by raw `sha` only, globally.
- `Commit#create_status_from_github!` → `Status.create!` triggers `add_status`, which can fire `deployable_status` hooks and `stack.schedule_merges` when the new status is `pending`/`success` [10](#0-9) , and `deployable?` depends on `success?` state derived from these statuses [11](#0-10) .

Equality broken: `organization authenticated via HMAC (repository.owner.login)` ≠ `stack/repository whose commit status is mutated (matched only by sha, cross-tenant)`.

### Impact Explanation
By injecting a fabricated `success` status for a known commit SHA in a victim organization's stack (SHAs of public/merged commits are trivially knowable), an attacker with no Shipit privileges and no access to the victim org can:
- Make an otherwise blocked/pending commit `deployable?` in a completely different tenant's stack, and
- Trigger `stack.schedule_merges` / continuous delivery scheduling for that commit.

This can result in an **unauthorized deploy** of a victim stack — one of the explicitly listed Critical impacts.

### Likelihood Explanation
Requires only:
1. Hosting configuration using the documented multi-org schema (an in-scope, documented feature) — i.e., multiple unrelated GitHub orgs share one Shipit instance.
2. The attacker administers/knows the `webhook_secret` of any one of those orgs (achievable by being a legitimate, unprivileged admin of their own onboarded org — no Shipit session or GitHub App private key needed).
3. Knowledge of a target commit SHA in the victim's tracked branch (public repos make this trivial).

No GitHub App private key, Shipit session, or `ApiClient` token is needed — only a webhook secret for *some* org on the shared instance, which is a much weaker credential than full repo write access.

### Recommendation
In `StatusHandler#process` (and any other handler that doesn't already scope through `Repository.from_github_repo_name`), constrain the `Commit` lookup to commits whose `stack.repository.owner` matches the payload's authenticated organization (or, more robustly, to `stacks` derived the same way `PushHandler`/`Handler#stacks` does), rejecting/ignoring statuses for commits outside that scope.

### Proof of Concept
1. Configure Shipit with two orgs sharing one instance (as in `docs/setup.md`'s "Using Multiple Github Applications"): `OrgB` (attacker-administered) and `OrgA` (victim).
2. Attacker knows `OrgB`'s `webhook_secret` (they installed/configured the GitHub App there).
3. Attacker finds a commit SHA `abc123` belonging to `OrgA`'s tracked stack (e.g., from a public PR).
4. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
```json
{
  "sha": "abc123",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgB" } }
}
```
signed with `OrgB`'s webhook secret via `X-Hub-Signature`.
5. `verify_signature` succeeds (`Shipit.github(organization: "OrgB")` verifies against `OrgB`'s secret) [1](#0-0) .
6. `StatusHandler#process` matches `Commit.where(sha: "abc123")` — the record belonging to `OrgA`'s stack — and applies the forged `success` status [7](#0-6) , potentially making the commit `deployable?` and scheduling merges/continuous delivery for `OrgA`'s stack.

**Note on verification limits:** I could not execute this against a live instance; the analysis is based on static code review of `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/commit.rb`, `lib/shipit.rb`, and the documented multi-org configuration. The exact downstream consequences of a forged `success` status (whether it alone suffices to trigger an actual deploy given `Stack#schedule_merges`/CD gating logic) would benefit from confirmation via a live/staging reproduction.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
