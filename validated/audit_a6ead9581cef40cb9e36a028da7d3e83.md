### Title
Webhook signature verification selects the trust anchor from `repository.owner.login`, but event processing acts on the independent `repository.full_name` field, allowing cross-organization webhook forgery in multi-org deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (the `github: { orgA: {...}, orgB: {...} }` config schema), `WebhooksController#verify_signature` picks *which* organization's `webhook_secret` to validate the inbound HMAC signature against using `repository_owner`, a value read from `params.dig('repository', 'owner', 'login')`. However, every webhook `Handler` (e.g. `PushHandler`, `StatusHandler`) determines *which stacks/repository to actually mutate* using a completely independent JSON path, `payload.dig('repository', 'full_name')` (see `Handler#repository_name`). Because these two fields are never checked for consistency, an attacker who legitimately controls one onboarded organization's webhook secret (e.g. their own GitHub App installation on the shared Shipit instance) can forge a payload whose `repository.owner.login` names their own org (so the signature check passes with a secret they know) while `repository.full_name` names a repository belonging to a *different* organization also hosted on the same instance, causing writes to that other organization's stacks.

### Finding Description
`WebhooksController#verify_signature` does: [1](#0-0) 

selecting the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) via `repository_owner`: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization secrets from `secrets.github`, one distinct `webhook_secret` per configured org, as documented and tested for the multi-app schema: [3](#0-2) [4](#0-3) 

Once the signature check passes, `WebhooksController#create` dispatches the *same raw payload* to handlers: [5](#0-4) 

But the base `Handler` class — used by `PushHandler`, `StatusHandler`, and others — resolves the target `Repository`/stacks from a **different** JSON key, `repository.full_name`, not `repository.owner.login`: [6](#0-5) 

`PushHandler#process` then acts on those resolved stacks, triggering `sync_github`: [7](#0-6) 

`StatusHandler#process` similarly writes commit statuses by `sha` alone with no organization scoping at all: [8](#0-7) 

**The broken equality**: the code implicitly assumes
`org(repository.owner.login) == org(repository.full_name)`
holds for every inbound request, because for a genuine GitHub-originated webhook it always does. But nothing enforces this. An attacker who is an onboarded tenant (owns a legitimate GitHub App installation and therefore knows their own `webhook_secret`) can submit a payload where:
- `repository.owner.login = "attacker-org"` → causes `verify_signature` to fetch and check against `attacker-org`'s secret, which the attacker knows and can sign correctly.
- `repository.full_name = "victim-org/victim-repo"` → causes the handler to resolve and mutate stacks belonging to `victim-org`, an organization the attacker has no relationship with.

This directly matches the report's bug class: a value used to establish trust (which secret authorizes the request) is not the same value that determines what gets written, and the two are only bound by an unenforced assumption — exactly the class of bug in the original report where `savingsAccountTransfer()`'s return value silently diverged from the accounting value that was actually recorded.

### Impact Explanation
This allows an attacker who legitimately controls one organization's webhook credentials on a shared/multi-tenant Shipit instance to forge `push`, `status`, `pull_request`, etc. events targeting a *different* organization's repositories/stacks. Consequences include:
- Cross-repository writes: enqueuing `GithubSyncJob`/`sync_github` for a victim org's stack, injecting spoofed commit history state.
- Forged CI/commit statuses (`StatusHandler`) attached to arbitrary commits by `sha`, with no org/repository check at all, potentially unblocking deploy gating (`ignore_ci`/commit status checks) for a victim's stack and enabling an unauthorized deploy.
- Depending on which handler is targeted, this can escalate into review-stack creation/archival or merge-related actions for a repository the attacker does not own.

This satisfies the Critical bar of "cross-repository writes" / "an unauthorized deploy" defined in scope, since the trust boundary crossed is between organizations that are each individually onboarded but not supposed to be able to affect each other's stacks.

### Likelihood Explanation
This is only exploitable when a Shipit instance is configured with the multi-organization schema (`github: {org1: {...}, org2: {...}}`), which is an explicitly documented and supported configuration for hosting multiple GitHub orgs on one Shipit instance. Any attacker who is one of the legitimately onboarded organizations (i.e., possesses a valid GitHub App installation and its own `webhook_secret` for *their own* org) can trivially construct and sign such a cross-org payload themselves — no secret guessing, no privileged Shipit account, and no interception is required. This is a realistic and immediately reachable path in that supported deployment mode.

### Recommendation
After computing `repository_owner` for secret selection, also require that any `repository.full_name` present in the payload belongs to that same organization before dispatching to handlers (e.g., compare `repository.owner.login` case-insensitively against the owner segment of `repository.full_name`, rejecting the request with a `422` on mismatch). Alternatively, resolve the acting organization from the verified GitHub App installation context rather than from attacker-suppliable payload fields, and pass that verified organization into handlers so `Handler#repository_name`/`stacks` can reject repositories outside the verified org.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-org schema as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker legitimately installs their own GitHub App for `attacker-org` and thus knows `attacker-org`'s `webhook_secret`.
3. Attacker creates a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef...attacker-controlled-sha",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org-webhook-secret, body)>` and posts it to `POST /github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`), and the signature validates successfully because it was signed with the correct (attacker's own) secret.
6. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name('victim-org/victim-repo')` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: 'deadbeef...')` on `victim-org`'s stacks — a repository the attacker never authenticated for.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
