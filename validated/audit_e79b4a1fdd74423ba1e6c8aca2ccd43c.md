Confirmed: `Handler#stacks`/`Handler#repository_name` resolve the target repository from `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects *which* GitHub App's secret to check the HMAC against using a different field, `repository.owner.login` (falling back to `organization.login`) [2](#0-1) . These two fields are never cross-checked against each other.

### Title
Webhook organization used for signature verification is decoupled from the repository `full_name` acted upon by handlers - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments (`config/secrets.yml` keyed by org, e.g. `test/dummy/config/secrets_double_github_app.yml`) [3](#0-2) , the webhook signature is validated against the GitHub App belonging to `params.dig('repository','owner','login')` [4](#0-3) , but the object actually mutated by the handler is chosen via the separate `repository.full_name` field [5](#0-4) . Nothing in the code enforces that `repository.owner.login` is the owner segment of `repository.full_name`.

### Finding Description
`Shipit.github(organization:)` picks a `GitHubApp` (and thus a `webhook_secret`) keyed strictly off `repository_owner` [6](#0-5) . An attacker who legitimately administers one onboarded GitHub organization ("OrgA", with a real, known `webhook_secret`) can POST directly to `/webhooks` with `X-Hub-Signature` computed using OrgA's genuine secret, while setting the JSON body's `repository.owner.login` to `"OrgA"` (so `verify_signature` picks and passes OrgA's secret) but `repository.full_name` to `"OrgB/target-repo"` (a repository belonging to a different onboarded organization "OrgB"). `verify_signature` only checks the raw body's HMAC against OrgA's secret and never checks that `repository.full_name`'s owner segment matches `repository.owner.login`. Downstream, `PushHandler#process` resolves the target stacks purely from `full_name` via `Repository.from_github_repo_name` [7](#0-6) , so the forged event is processed against OrgB's stacks even though the signature only proves knowledge of OrgA's secret. The equality that should hold — `organization authenticated by the HMAC` == `organization owning the repository acted upon` — is broken.

### Impact Explanation
This lets an attacker who is a legitimate admin of one org's GitHub App on a shared multi-tenant Shipit instance forge webhook events (e.g. `push`, `status`, `check_suite`, `pull_request`) that are processed as if they came from a different organization's repository they do not control, e.g. triggering `GithubSyncJob` for OrgB's stack, closing/archiving OrgB review-stack pull requests, or updating commit statuses used to gate deploys — a cross-repository/cross-tenant write performed without ever authenticating as OrgB.

### Likelihood Explanation
Requires the host to run Shipit in the documented multi-organization configuration and requires the attacker to already be an admin of at least one onboarded GitHub App (so they know its `webhook_secret`) — this is not a fully anonymous attacker, but it is not a Shipit account or `ApiClient` token either; it is cross-tenant privilege that the trust model assumes is properly siloed per organization.

### Recommendation
Bind the signature-verifying organization to the same field the handlers act on: derive `repository_owner` from `repository.full_name`'s owner segment (or validate that `repository.owner.login` matches the owner segment of `repository.full_name`) before dispatching to handlers, and reject the webhook if they diverge.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `secrets_double_github_app.yml`).
2. As an attacker who administers OrgA's GitHub App, compute `X-Hub-Signature: sha1=HMAC(OrgA_secret, body)` for a JSON body: `{"ref":"refs/heads/master","after":"<sha>","repository":{"owner":{"login":"OrgA"},"full_name":"OrgB/target-repo"}}`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` computes `Shipit.github(organization: "OrgA")` and validates successfully against the attacker's own secret [8](#0-7) .
5. `PushHandler#stacks` looks up `Repository.from_github_repo_name("OrgB/target-repo")` and syncs/enqueues jobs for OrgB's stack [9](#0-8) , even though only OrgA's credentials were ever proven.

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
