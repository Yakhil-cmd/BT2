### Title
Signature verification keyed on `repository.owner.login` while routing keyed on `repository.full_name` allows cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate an incoming webhook against using an attacker-controlled field of the *unverified* JSON body (`repository.owner.login`, falling back to `organization.login`), but the event handlers that actually act on the payload (create syncs, close/open review stacks, update statuses, etc.) select the target `Stack`/`Repository` using a *different* field, `repository.full_name`. In a multi-organization Shipit deployment where any one configured GitHub App has no `webhook_secret` set (`verify_webhook_signature` explicitly treats a blank secret as "always verified"), an attacker can produce a payload whose `repository.owner.login` points at the unsecured org while `repository.full_name` points at a fully-secured org's repository, bypassing signature verification for actions that affect the secured org's stacks.

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

`repository_owner` is read straight out of the still-unauthenticated request body, and it is used to pick *which* `GitHubApp` (and thus which `webhook_secret`) to check the signature against, via `Shipit.github(organization:)`:
```ruby
def github(organization: github_default_organization)
  ...
  config = github_app_config(organization)
  raise GithubOrganizationUnknown, organization if config.nil?
  ...
  @github[organization] ||= GitHubApp.new(organization, config)
end
``` [2](#0-1) 

`GitHubApp#verify_webhook_signature` intentionally treats a missing `webhook_secret` as "signature not required":
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Meanwhile, the event handlers that actually mutate state resolve the target repository/stack from an *entirely different* field of the same untrusted body — `repository.full_name` — not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler`, for example, uses this `repository_name`-derived `stacks` scope to trigger `sync_github`:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

Equality that should hold but does not: **the organization whose credential authenticated the request == the organization that owns the repository being acted on**. In this multi-tenant configuration (documented and tested via `test/dummy/config/secrets_double_github_app.yml`, which shows two independently configured GitHub Apps, `OrgOne` and `OrgTwo`, each with its own `webhook_secret`), an attacker who can reach the shared `/webhooks` endpoint can set `repository.owner.login` to any org configured with a blank/absent `webhook_secret` — causing `verify_webhook_signature` to unconditionally return `true` — while setting `repository.full_name` to a repository belonging to a *different*, properly secured org whose stacks are the real target. [6](#0-5) 

### Impact Explanation
This breaks the trust boundary between "organization that authenticated" and "repository that is written," matching the required Critical/High impact bar. In this engine, `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)`, which forces a stack's known-deployed-ref state to an attacker-chosen SHA for a repository the attacker does not control credentials for; `PullRequest` handlers can archive/unarchive/provision review stacks for repositories in the properly-secured org. This is an authentication-bypass class issue: the deployment host is enforcing "some" HMAC check, but the check is bound to the wrong identity, letting an unauthenticated party spoof events attributed to a fully-configured, secret-protected organization's repositories as long as *any* other org in the same Shipit deployment lacks a `webhook_secret` (a legitimate, documented configuration state — `webhook_secret: # nil` appears in the shipped `docs/setup.md` example and `config/secrets.development.shopify.yml` template).

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (a documented, supported configuration — see `github_app_config`/`github_organizations` and the dummy fixture with two orgs), and (2) at least one configured organization with no `webhook_secret` set — which is the *default* placeholder value shown in the shipped configuration templates (`webhook_secret: # nil`). No credentials, tokens, or repository write access are needed; the attacker only needs to know the unsecured org's login name (often discoverable) and the target org/repo's `full_name` (public information). This is plausible for any deployment that onboards a low-security/test organization alongside a production one.

### Recommendation
Bind signature verification to the same organization identity that is used for routing, and never trust a field pulled from the unauthenticated body for selecting which secret verifies that body. Concretely: after verifying against a secret, derive the acting organization/repository strictly from the verified GitHub App's own installation context (or require `repository.full_name`'s owner to equal `repository_owner`), and reject requests where a `webhook_secret` is blank rather than treating blank as "always trust." At minimum, do not allow a per-organization signature bypass (`return true unless webhook_secret`) to apply to events whose payload references a different organization's repository.

### Proof of Concept
1. Deploy Shipit with two GitHub Apps configured, e.g. mirroring `test/dummy/config/secrets_double_github_app.yml`: `OrgOne` (target, has real repos/stacks, assume it is given a real `webhook_secret` in production) and `OrgTwo` (has `webhook_secret` left blank, as shown by the template default `webhook_secret: # nil` in `docs/setup.md`/`config/secrets.development.shopify.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/production-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` computes `repository_owner => "OrgTwo"`, loads `OrgTwo`'s `GitHubApp` (blank `webhook_secret`), and `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/invalid) `X-Hub-Signature` header.
4. `PushHandler#process` resolves `stacks` via `repository.full_name` = `"OrgOne/production-repo"`, matching `OrgOne`'s real stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — an unauthenticated actor has driven state for a stack belonging to the properly secured organization.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
