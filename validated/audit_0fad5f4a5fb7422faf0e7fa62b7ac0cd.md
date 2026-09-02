This confirms the vulnerability path. `Handler#stacks` resolves the target `Stack`/`Repository` purely from `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the HMAC against using `repository_owner`, itself parsed from the same unverified JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [2](#0-1) . In a multi-org deployment (`Shipit.github(organization:)` selecting per-org secrets as documented in `docs/setup.md`) [3](#0-2) , the org whose secret authenticates the request is never cross-checked against the `repository.full_name` that the handler actually acts on.

### Title
Webhook signature verification authenticates the wrong organization's secret against an attacker-controlled repository field, allowing cross-repository writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App config (and thus the HMAC `webhook_secret`) to validate a webhook against using `repository_owner`, a field read directly from the unauthenticated JSON body. The rest of the payload, including `repository.full_name`, is only checked for HMAC validity against *that same* org's secret — there is no additional binding ensuring the signed org actually owns the repository the payload claims to act on.

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [4](#0-3) . This value comes straight from the raw, not-yet-verified request body. Once `Shipit.github(organization: repository_owner)` resolves an app/secret and the HMAC checks out, `create` dispatches the full JSON payload to handlers [5](#0-4) . Handlers such as `PushHandler` resolve the target `Stack` purely from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`Repository.from_github_repo_name` [1](#0-0)  — a completely separate field from the one used to select the verifying secret.

In a single-org deployment this is harmless since there is only one secret. But `Shipit` explicitly supports multi-org configuration where each org has its own `webhook_secret`, resolved dynamically by `Shipit.github(organization:)` [3](#0-2) , as documented in `docs/setup.md`'s "Using Multiple Github Applications" section. Any entity that legitimately knows/controls one configured org's webhook secret (e.g. is a collaborator/admin of `OrgA`'s installed GitHub App, which is a normal, unprivileged-relative-to-`OrgB` capability) can craft a raw payload where `repository.owner.login`/`organization.login` = `OrgA` (so `verify_signature` fetches and validates against `OrgA`'s secret, which they know) while `repository.full_name` = `OrgB/target-repo`. The signature check passes because it is only checking "this body was HMAC-signed with OrgA's secret" — it never checks "and this body's actions apply to a repository owned by OrgA." The handler then acts on `OrgB/target-repo`'s stacks using data from an attacker-fully-controlled JSON body.

This is the exact analog of the reported bug class: two fields that should be bound together (the org whose secret authenticated the request vs. the repository the payload instructs Shipit to act on) are decoupled — one is checked, the other, differing field is what's actually acted upon.

### Impact Explanation
This breaks the equality `{org that authenticated} == {repo owner the handler writes to}`. Depending on which webhook event/handler is targeted, an attacker holding only one org's webhook secret can trigger actions against a stack belonging to a *different* org configured on the same Shipit instance: e.g. `PushHandler` triggers `sync_github`/deploy pipelines [6](#0-5) , and `pull_request` handlers can auto-provision/merge review stacks for the target repo. This is a cross-repository/cross-org write performed without possessing that target org's own webhook secret — satisfying the "cross-repository writes" Critical impact criterion.

### Likelihood Explanation
Requires a multi-org Shipit deployment (explicitly a supported, documented configuration) and requires the attacker to know one configured org's `webhook_secret` (e.g., because they administer that org's GitHub App installation) — not the target org's secret. No repository write access, `ApiClient` token, or session on the target org is needed; only knowledge of a different org's webhook secret configured on the same instance.

### Recommendation
After computing `repository_owner`/`Shipit.github(organization: repository_owner)` and verifying the HMAC, cross-check that the resolved organization actually matches the owner of the repository the payload/handler will act on (e.g., re-derive the owner from `repository.full_name` and require it to equal `repository_owner`/the org whose secret validated, or bind the signature check itself to `repository.full_name` rather than the possibly-different `owner.login`/`organization.login` field).

### Proof of Concept
1. Multi-org `secrets.yml` configured with `OrgA` and `OrgB`, each with distinct `webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`) [7](#0-6) .
2. Attacker knows `OrgA`'s `webhook_secret` (e.g. is an admin of `OrgA`'s GitHub App).
3. Attacker crafts a `push` payload: `{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}, "ref": "refs/heads/main", "after": "<attacker-controlled sha>"}`.
4. Attacker computes `X-Hub-Signature` using `OrgA`'s `webhook_secret` over this exact JSON body.
5. `POST /webhooks` with `X-Github-Event: push`: `verify_signature` resolves `Shipit.github(organization: 'OrgA')`, and `verify_webhook_signature` succeeds because the body was correctly signed with `OrgA`'s secret [8](#0-7) .
6. `create` dispatches to `PushHandler`, which resolves stacks via `repository.full_name` = `OrgB/target-repo` [6](#0-5) [1](#0-0) , triggering `sync_github(expected_head_sha: ...)` on `OrgB`'s stack — an action the attacker was never authorized to perform against `OrgB`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-45)
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
```
