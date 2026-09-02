## Analog Found

Confirmed root cause: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to select the `Repository`/`Stack` to act on [1](#0-0) , while `WebhooksController#verify_signature` selects the GitHub App/secret used to validate the request from a *different* field, `payload.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) . In multi-organization deployments (`Shipit.github_app_config`), each organization has its own independently-configured `webhook_secret`, which can legitimately be blank for one org while set for another [3](#0-2) [4](#0-3) . `GitHubApp#verify_webhook_signature` trivially returns `true` when `webhook_secret` is blank: `return true unless webhook_secret` [5](#0-4) .

### Title
Webhook signature is verified against `repository.owner.login`, but the acted-upon repository comes from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The binding "organization whose signature authenticated the request" == "repository that is written by the handler" is not enforced. The signature-selecting field (`repository.owner.login`) and the write-target field (`repository.full_name`) are two separate, independently attacker-controlled JSON fields inside the same unsigned-until-verified request body.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp`/secret to check against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` [6](#0-5) . But the handler that actually mutates state (`PushHandler`, and all others via `Handler#stacks`) looks up the target `Repository`/`Stack` using a completely different field, `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing in the code enforces that `full_name`'s owner segment matches `owner.login`.

In a multi-org Shipit deployment, an operator can legitimately configure one organization with `webhook_secret: nil` (shown as the documented/example configuration) and another with a real secret [7](#0-6) [8](#0-7) . An attacker who knows (or guesses) the name of an org configured without a secret can craft a raw POST to `/github/webhooks` with:
- `repository.owner.login` = the org with no `webhook_secret` (or `organization.login` as fallback)
- `repository.full_name` = `"other-org/other-repo"` referencing a stack that belongs to a *different*, securely-configured organization

`verify_signature` resolves `Shipit.github(organization: 'org-with-no-secret')`, and `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank [9](#0-8) . The request now passes validation entirely without needing any secret. `Webhooks.for_event('push').each { |handler| handler.call(params) }` then dispatches `params` (the full attacker JSON, unrelated to which org "authenticated" it) to `PushHandler`, which resolves the target stacks purely from `full_name` — the other, secured org's repository [10](#0-9) . This lets the attacker trigger `stack.sync_github(expected_head_sha: ...)` and other webhook-driven behaviors (status updates, check-suite refresh, membership/team mutation, pull-request/merge-queue events) against a repository/org whose real webhook secret was never presented — an authentication bypass against the "org authenticated" vs "repo written" binding described in the analog rules.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Depending on which webhook event is forged, impact ranges from forcing unauthorized `sync_github` refresh cycles, injecting forged commit `status`/`check_suite` payloads that influence merge-queue/deploy decisions, to mutating `Team`/`Membership` records — all without possessing the target organization's `webhook_secret`. This is an authentication-bypass class issue (High), since it lets an unprivileged external actor make the engine accept and act on webhook payloads for a stack/org protected by a secret it doesn't hold, purely by pivoting through a differently (or un-)configured sibling org in the same deployment.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (explicitly documented and tested as a supported configuration — `docs/setup.md` "Using Multiple GitHub Applications", `test/dummy/config/secrets_double_github_app.yml`), and (2) at least one configured organization with a blank/absent `webhook_secret` (also a documented, apparently-supported configuration, since `verify_webhook_signature` explicitly special-cases `webhook_secret` being absent). Given that GitHub Apps can be created without a webhook secret and the example config ships with `webhook_secret: # nil`, this is a realistic operational state, not a purely theoretical one, and requires no privileged token, session, or repository access to exploit — only network access to the public `/github/webhooks` endpoint and knowledge of the low-secret org's name.

### Recommendation
Enforce the binding: after computing `repository_name` (`full_name`) in the handler layer, derive the organization to verify against from the same field the handlers actually trust, or conversely, require the controller to re-validate that `repository.full_name`'s owner segment equals `repository.owner.login`/`organization.login` before dispatch, and reject mismatches with `422`. More robustly, disallow `github_app_config` entries with a blank `webhook_secret` when multiple organizations are configured, or fail closed (return `false`) instead of `true` when a secret is absent in a multi-org (`github_default_organization` non-nil) setup.

### Proof of Concept
1. Configure Shipit with two orgs as in `test/dummy/config/secrets_double_github_app.yml`: `OrgOne` (webhook_secret: nil) and `OrgTwo` (webhook_secret: <real-secret>), each with tracked stacks, e.g. `OrgTwo/secure-repo`.
2. As an unauthenticated attacker, POST to `/github/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "OrgTwo/secure-repo",
    "owner": { "login": "OrgOne" }
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: 'OrgOne')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) `X-Hub-Signature` header [5](#0-4) .
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name('OrgTwo/secure-repo')` and invokes `stack.sync_github(expected_head_sha: 'attacker-chosen sha')` on the `OrgTwo` stack [11](#0-10)  — despite the request never being validated with `OrgTwo`'s real secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
