### Title
Webhook signature verified against `repository.owner.login` while the actual write target is taken from the unverified `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` used to check the `X-Hub-Signature` HMAC based on `repository.owner.login` (or `organization.login`) inside the JSON payload, but the handlers that actually act on the payload (e.g. `PushHandler`, `StatusHandler`, review-stack handlers) resolve the target `Repository`/`Stack` from a *different* field, `repository.full_name`. Both fields live in the same attacker-controlled JSON body and are never cross-checked against each other, so a signature computed with one organization's `webhook_secret` can be replayed with a `full_name` pointing at a stack that belongs to a completely different, unrelated repository/organization configured on the same Shipit instance.

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`repository_owner` is only used to pick *which* `GitHubApp` (and therefore which `webhook_secret`) verifies the HMAC. The HMAC itself only proves that whoever sent the request knows the secret associated with the organization named in `repository.owner.login` — it never binds the signature to any particular repository under that org, nor to the `repository.full_name` value that downstream code actually trusts.

Every event handler, by contrast, resolves the entity to act on from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end

def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [2](#0-1) 

For example `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching that `full_name`/branch: [3](#0-2) 

and PR handlers such as `OpenedHandler`/`LabeledHandler` provision or archive review stacks using `Repository.from_github_repo_name(params.repository.full_name)`: [4](#0-3) 

Shipit explicitly supports multiple independently-configured GitHub Apps/organizations with distinct `webhook_secret`s in the same installation (see the documented multi-org secrets format): [5](#0-4) [6](#0-5) 

Because `verify_signature` only authenticates "sender knows *some configured org's* secret," while every handler trusts `repository.full_name` — an attacker-controlled field inside the same signed blob — to decide **which stack in the whole installation to mutate**, the equality the code implicitly assumes,
`organization authenticated by verify_webhook_signature == organization owning the repository/stack that handlers act on`,
does not hold. An attacker holding the `webhook_secret` for any one low-value organization onboarded onto the Shipit instance can forge a payload whose `repository.owner.login` matches that low-value org (so the HMAC verifies) but whose `repository.full_name` names a stack belonging to a different, higher-value organization also configured on the same instance.

### Impact Explanation
This lets a party who possesses only a *weaker* organization's `webhook_secret` trigger unauthorized state changes against stacks owned by other organizations hosted on the same Shipit instance: forcing `GithubSyncJob`/deploy-triggering syncs via `PushHandler`, archiving/unarchiving review stacks via the PR handlers, or injecting commit statuses via `StatusHandler`. This crosses a repository/organization trust boundary using credentials that were never meant to authorize actions against that target repository, matching the "unauthorized deploy/rollback" and "cross-repository writes" High/Critical impact categories.

### Likelihood Explanation
Exploitability requires the attacker to already know a `webhook_secret` for *some* organization configured on the target Shipit instance (their own onboarded org, for example) — this is the minimum bar for anyone able to register a webhook at all, and is explicitly supported by Shipit's multi-org configuration format. No repository write access, session, or `ApiClient` token to the *victim* repository is needed; only crafting an HTTP POST with a valid HMAC for a secret the attacker legitimately holds is required.

### Recommendation
After signature verification, re-derive the acting organization from the same GitHub App config used to verify (`repository_owner`) and assert that it matches the owner segment of `repository.full_name` (and of `organization.login` if present) before dispatching to any handler. Reject the webhook (422) on mismatch. Alternatively, resolve the `GithubHook`/`Stack` scoped strictly to the verified organization and refuse to act on any `full_name` outside that organization's namespace.

### Proof of Concept
1. Configure Shipit with two orgs as in `test/dummy/config/secrets_double_github_app.yml` — `OrgOne` (victim, has a stack `OrgOne/prod-repo`) and `OrgTwo` (attacker-controlled, attacker knows `OrgTwo`'s `webhook_secret`).
2. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/prod-repo"
  }
}
```
3. Attacker signs the raw body with `OrgTwo`'s `webhook_secret` and sends it as `X-Hub-Signature` to `POST /github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "OrgTwo")` and successfully verifies the signature using `OrgTwo`'s secret [7](#0-6) .
5. `PushHandler` resolves `Repository.from_github_repo_name("OrgOne/prod-repo")` and calls `stack.sync_github(expected_head_sha: ...)`, causing an unauthorized sync/deploy trigger on `OrgOne`'s stack despite the attacker never having had `OrgOne`'s `webhook_secret` [3](#0-2) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
