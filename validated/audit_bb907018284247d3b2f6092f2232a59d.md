### Title
Cross-Organization/Cross-Repository Commit Status Forgery via Webhook Signature Scoping Mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The webhook signature check authenticates a request against the GitHub App secret belonging to the organization named in the payload's `repository.owner.login` field, but the event handlers that subsequently mutate state (in particular `StatusHandler`) never verify that the record they act on actually belongs to that organization/repository. The binding "organization whose secret validated the HMAC" == "repository/commit the payload is allowed to affect" is not enforced, so a party who possesses a valid `webhook_secret` for **any one** organization configured on a multi-tenant Shipit instance can forge webhook events that mutate data belonging to a **different**, unrelated organization/repository tracked by the same instance.

### Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp`/secret to use for HMAC verification purely from a field parsed out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the app config by the organization name embedded in the same payload it just used to compute the signature comparison against: [3](#0-2) 

Shipit explicitly supports multiple independent GitHub App configurations (and therefore multiple independent `webhook_secret`s) in a single deployment, one per organization, as documented and fixtured: [4](#0-3) [5](#0-4) 

Once the signature check passes (because it was checked against the secret of the org named in the payload), the raw parsed JSON is dispatched to handlers, unmodified and un-rescoped: [6](#0-5) 

Critically, `StatusHandler#process` resolves the target `Commit` purely by SHA, with **no** repository, stack, or organization scoping at all: [7](#0-6) 

This means the "repository.owner.login" value that determined *which secret was checked* has no logical connection to the record that is actually mutated by the handler (`Commit.where(sha: params.sha)`, matched against the whole `commits` table). An attacker who legitimately controls (or is a customer/tenant of) `OrgA` on a shared Shipit instance knows `OrgA`'s real `webhook_secret` (it's their own GitHub App/webhook config, delivered to them by GitHub for real events, or directly known to them as the org administrator). They can:

1. Construct a synthetic `status` event JSON body with `repository.owner.login = "OrgA"` (so `verify_signature` selects and matches `OrgA`'s secret) and with `sha` set to the SHA of a commit that actually belongs to `OrgB`'s stack (git SHAs of a target commit are frequently public/discoverable through GitHub's API, PRs, or the Shipit UI itself).
2. Sign the raw body with `OrgA`'s `webhook_secret` (HMAC-SHA1) and POST it to `/github/webhooks`.
3. `verify_signature` succeeds using `OrgA`'s config, but `StatusHandler` then finds and mutates the `Commit` row for `OrgB`'s repository (because the lookup ignores repository/organization entirely) and creates a forged CI `Status` (e.g., state `success`, arbitrary `context`) on it via `Commit#create_status_from_github!`.

The `push`, `pull_request/*`, and `check_suite` handlers exhibit the same weaker (but related) pattern: they resolve their target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` — a field independent of `repository_owner` (`params.dig('repository','owner','login')`) used for signature scoping — via `Repository.from_github_repo_name`: [8](#0-7) [9](#0-8) 

Since the JSON body is entirely attacker-controlled once they know any one org's secret, nothing forces `repository.owner.login` (used to pick the verifying secret) to correspond to `repository.full_name` (used to pick the mutated repository/stack). `StatusHandler` is the most severe instance because it doesn't even use the repository field — it is a pure cross-tenant, cross-repository primitive keyed only on a public commit SHA.

### Impact Explanation
Shipit's continuous-delivery/merge-queue logic relies on commit statuses (`ci.require`, `ci.blocking`, `merge.require`) to gate whether a commit is deployable or mergeable, as documented: [10](#0-9) 

By forging a passing (`success`) status for a target commit in an organization/repository the attacker does not control, the attacker can satisfy required-CI-status gating for that stack and cause Shipit to consider the commit deployable/mergeable — i.e., contribute to an **unauthorized deploy** of a commit that never actually passed real CI, in a repository outside the attacker's authorization boundary. This crosses the "organization that authenticated" vs. "repository/commit actually written" trust boundary defined in the engine's threat model, satisfying the Critical impact bar ("cross-repository writes … or an unauthorized deploy").

### Likelihood Explanation
Exploitation requires only that the attacker know a valid `webhook_secret` for **any one** organization configured on the Shipit instance — a realistic condition for any multi-tenant/self-hosted Shipit deployment using the documented "Using Multiple Github Applications" configuration, where separate customer organizations each control their own app/secret but share the same Shipit instance and `commits`/`repositories` tables. No GitHub session, `ApiClient` token, or repository write access on the *victim* org is needed — only the attacker's own org's webhook secret and the target commit's SHA (frequently public). The webhook endpoint is unauthenticated aside from the per-org HMAC check, so this is directly reachable over the network.

### Recommendation
- In `WebhooksController`/`Shipit::Webhooks::Handlers::Handler`, thread through the organization that was actually verified (`repository_owner` used in `verify_signature`) and require every handler to check that the resolved `Repository`/`Stack`/`Commit` belongs to that verified organization before mutating it.
- Specifically fix `StatusHandler#process` (and `Commit.create_status_from_github!`) to scope the `Commit` lookup by repository/organization, not solely by `sha`.
- Reject events where `repository.owner.login` (or `organization.login`) does not match the repository actually referenced by `repository.full_name`.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org schema).
2. As an operator/attacker who legitimately knows `OrgA`'s `webhook_secret` (e.g., an org admin on a shared Shipit instance), obtain the SHA of a commit tracked under an `OrgB` stack (public repos/commit SHAs are discoverable via GitHub).
3. Build a JSON body:
```json
{
  "sha": "<OrgB target commit sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/some-repo" }
}
```
4. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, raw_body)>`.
5. POST to `/github/webhooks` with header `X-Github-Event: status`.
6. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully against `OrgA`'s secret.
7. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, matches the `OrgB` commit (no org/repo scoping applied), and creates a forged "success" status on it via `commit.create_status_from_github!(params)`, potentially unblocking deploy/merge gating for `OrgB`'s stack despite the attacker having no legitimate access to `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** README.md (L444-480)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
  require:
    - ci/circleci
```

**<code>ci.hide</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to ignore.

For example:
```yml
ci:
  hide:
    - ci/circleci
```

**<code>ci.allow_failures</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to be visible but not to required for deploy.

For example:
```yml
ci:
  allow_failures:
    - ci/circleci
```

**<code>ci.blocking</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to disallow deploys if any of them is missing or failing on any of the commits being deployed.

For example:
```yml
ci:
  blocking:
    - soc/compliance
```
```
