### Title
Webhook signature verification selects the GitHub App/organization from an unverified payload field that is independent of the field handlers use to target the repository — allowing cross-organization webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` chooses which organization's `webhook_secret` to validate the HMAC against using `repository_owner`, a value read straight from the **unauthenticated** JSON body, before the signature has been checked. Every downstream `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the target `Repository`/`Stack` from a *different* payload field, `payload.dig('repository', 'full_name')`. Because both fields are attacker-controlled JSON and are never cross-checked against each other, a party who legitimately knows one organization's webhook secret (e.g. an admin of a smaller/less-trusted org hosted on the same multi-org Shipit instance) can craft a payload whose `repository.owner.login` matches their own org (so their own secret verifies) while `repository.full_name` points at a repository belonging to a completely different organization on the same instance.

### Finding Description
- `verify_signature` ( [1](#0-0) ) computes `repository_owner` via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` ( [2](#0-1) ) and uses it to fetch the corresponding `GitHubApp`/`webhook_secret` with `Shipit.github(organization: repository_owner)`, then verifies `X-Hub-Signature` against that secret ( [3](#0-2) ).
- Shipit explicitly supports hosting multiple independent GitHub organizations from one instance, each with its own `webhook_secret`, exactly as documented and exercised in `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml` ( [4](#0-3)  ) and `Shipit.github`/`github_app_config` ( [5](#0-4) ).
- Once the signature is accepted, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the raw, unauthenticated JSON ( [6](#0-5) ).
- Every handler resolves its target repository/stacks from `payload.dig('repository', 'full_name')` via the base `Handler#repository_name`/`#stacks` ( [7](#0-6) ), which is a field completely independent from `repository.owner.login` used for signature routing.
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` (a write action queuing `GithubSyncJob`) for every non-archived stack matching the branch ( [8](#0-7) ), and `StatusHandler#process` creates commit statuses ( [9](#0-8) ) — neither re-validates that the resolved stack's repository owner matches the organization whose secret authenticated the request.
- Since `repository.owner.login` and `repository.full_name` are two separate, attacker-writable JSON keys inside the same unauthenticated body, an attacker who controls Org A's `webhook_secret` (a legitimate customer of the Shipit instance, not a Shipit operator) can set `repository.owner.login = "OrgA"` (so `Shipit.github(organization: "OrgA")`'s secret verifies the HMAC) while setting `repository.full_name = "OrgB/some-repo"` so the handler acts on Org B's stack.

This breaks the intended binding: **organization whose secret authenticated the webhook == organization/repository the handler writes to**. The signature only proves "the sender knows *an* org's secret," not "the sender is authorized for *the specific repository named in the payload*."

### Impact Explanation
This allows cross-organization writes without any GitHub-side authorization: an attacker who is a legitimate, unprivileged tenant/webhook-secret holder for one organization on a shared multi-org Shipit deployment can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events targeting stacks/repositories/teams belonging to a different organization they have no access to — e.g., forcing `GithubSyncJob` to run against another org's stack, injecting fabricated commit statuses that influence deploy gating (`CI` checks used by `deployable?`), or manipulating `Team`/`Membership` records tied to a different org's `organization` field. This matches the "cross-repository writes" Critical-impact category in scope, since it crosses a repository/organization trust boundary the signature was meant to enforce.

### Likelihood Explanation
Requires the deployment to use the multi-organization `github:` config format (explicitly documented and supported) and for the attacker to possess (or be) a legitimate webhook-secret holder for at least one hosted organization — not a Shipit-privileged user, GitHub App private key, or repository write access to the *victim* organization. This is a realistic operating mode for any Shipit instance shared across multiple orgs/teams, which is a documented, first-class configuration.

### Recommendation
After `verify_signature` succeeds, re-derive the organization from the same field the handlers use (`repository.full_name`'s owner segment, or `organization.login` for org-level events) and confirm it matches the `repository_owner` used to select the verifying secret. Reject the request (422) if they diverge, closing the gap between the field that authorizes the request and the field that determines what gets written.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `docs/setup.md` "Using Multiple Github Applications").
2. Attacker holds `OrgA`'s `webhook_secret` (e.g., they administer OrgA's GitHub App/webhook settings on GitHub, a capability entirely outside Shipit's own authorization model).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` using OrgA's `webhook_secret` over this exact body and sends it to `POST /webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")`, whose secret matches the attacker-supplied signature, so the request passes ( [1](#0-0) ).
6. `PushHandler` resolves stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` ( [7](#0-6) ) and queues `GithubSyncJob`/triggers sync for OrgB's stack ( [8](#0-7) ), even though the attacker only proved knowledge of OrgA's secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
