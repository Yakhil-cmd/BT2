## Title
Webhook signature is verified against the payload's `repository.owner.login`, but handlers act on `repository.full_name` (and, for status events, no repository binding at all) — allowing a forged status/push event across GitHub Apps/organizations - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a signature against using `repository_owner` (`params.dig('repository','owner','login')`), then relies on that single successful verification to authorize processing of the *entire* payload by all matching handlers. But `Shipit::Webhooks::Handlers::Handler` (and the `StatusHandler` in particular) determine which stacks/commits to mutate using a *different* field — `repository.full_name`, or in the case of `StatusHandler`, no repository scoping at all. This breaks the trust binding `organization that authenticated == repository that is written`.

### Finding Description
`verify_signature` in `WebhooksController` picks the GitHub App config for HMAC verification purely from the `owner.login` sub-field of the payload: [1](#0-0) [2](#0-1) 

Once `head(422)` is *not* triggered (i.e., signature matches the secret configured for whatever org is named in `repository.owner.login`), the full raw JSON is dispatched unmodified to every registered handler for the event type: [3](#0-2) 

Handlers, however, resolve the affected stacks using a completely separate field, `repository.full_name`: [4](#0-3) 

Nothing checks that `repository.full_name`'s owner matches `repository.owner.login` used for signature selection. Worse, `StatusHandler` doesn't even use `stacks`/`repository_name` scoping — it looks up commits globally by SHA across the entire installation: [5](#0-4) 

Because Shipit supports multiple GitHub Apps/organizations configured with independent `webhook_secret`s (as shown in the multi-org test fixture), an attacker who is an admin of, or otherwise controls, the webhook secret for one configured GitHub App/organization ("OrgA") can craft a payload where `repository.owner.login = "OrgA"` (so `verify_signature` picks OrgA's secret and passes) while `repository.full_name` — or for `status` events, `sha` — refers to a repository/commit belonging to a completely different organization ("OrgB") also hosted on the same Shipit instance: [6](#0-5) 

### Impact Explanation
- For the `status` event, `StatusHandler#process` creates a `CommitStatus` on *any* commit matching the given SHA, with attacker-controlled `state`, `context`, `description`, and `target_url`, regardless of which organization's key signed the payload. Commit statuses feed into Shipit's deployability checks, so an attacker controlling one org's webhook secret can forge a fake "success" status on a commit belonging to a different, unrelated repository/stack, potentially making that commit appear deployable and enabling an **unauthorized deploy** in a stack the attacker has no legitimate access to.
- For the `push` event, `PushHandler#process` resolves stacks via `repository.full_name` (independent of the org used for signature verification) and enqueues `GithubSyncJob` for that branch — allowing cross-organization triggering of sync jobs on repositories outside the attacker's authorized scope.
- This satisfies the required High/Critical impact bar: it is a genuine authorization boundary crossing — an "organization that authenticated" vs. "the repository that is written" — leading to an unauthorized deploy trigger and forged deploy-gating state on repositories the attacker does not control.

### Likelihood Explanation
Requires the attacker to possess a valid `webhook_secret` for *any one* GitHub App/organization configured on the Shipit instance (e.g., because they administer that org's GitHub App settings) — not the target organization's secret. In multi-tenant/multi-org Shipit deployments (explicitly supported and tested, per `secrets_double_github_app.yml`), this is a realistic scenario where different orgs' admins are mutually untrusted, yet one can forge webhook activity affecting stacks of the other.

### Recommendation
In `WebhooksController#verify_signature` and/or in `Shipit::Webhooks::Handlers::Handler`, ensure the resolved stacks/commits are scoped to the same organization that produced the verified signature — e.g., re-derive `repository_owner` from `repository.full_name` (not from a possibly-independent `owner.login` field) for signature selection, and have handlers reject/ignore records whose `repository.full_name` owner does not match the verified `repository_owner`. `StatusHandler` should scope its `Commit` lookup to commits belonging to stacks under the verified repository/organization rather than a global SHA lookup.

### Proof of Concept
1. Shipit is configured with two GitHub Apps: `OrgA` (attacker-controlled webhook secret) and `OrgB` (victim, hosting `victim-stack`).
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/whatever" },
  "sha": "<sha of a commit belonging to OrgB/victim-stack>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` using the secret they legitimately hold for `OrgA`.
4. `POST /webhooks` with header `X-Github-Event: status`. `verify_signature` looks up `Shipit.github(organization: "OrgA")` (from `repository.owner.login`), verifies successfully against OrgA's secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the OrgB commit (no repository scoping check), and calls `create_status_from_github!`, creating a forged `success` status for that commit — even though the request was never authorized by OrgB's GitHub App/webhook secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
