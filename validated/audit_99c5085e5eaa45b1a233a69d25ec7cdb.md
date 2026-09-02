### Title
Webhook signature verification is bound to `repository.owner.login`, not the repository actually acted upon (`repository.full_name`) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org configuration (and therefore which `webhook_secret`) to use for HMAC verification from an attacker-controlled field in the *unverified* JSON body (`repository.owner.login`), while every event handler resolves the actual stack/repository to mutate from a *different* field in the same body (`repository.full_name`). These two fields are never cross-checked, so authentication of "who signed this" and authorization of "what repository this payload is allowed to affect" are decoupled — exactly the broken binding pattern described in the report (a callback/verification step that checks one thing while a different, unguarded value drives the state change).

### Finding Description
`verify_signature` computes the org used for verification purely from payload data: [1](#0-0) 

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
```

`GitHubApp#verify_webhook_signature` bypasses verification entirely if the selected org has no configured secret: [2](#0-1) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Every handler, however, resolves the repository/stack the event actually mutates from a separate, unrelated field of the same body: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`webhook_secret` is documented as optional per-organization ("Webhook secret (optional)") [4](#0-3) , and Shipit explicitly supports multiple organizations configured simultaneously, each with its own (possibly blank) secret [5](#0-4) .

The equality that should hold but doesn't:
`organization whose secret authenticated the request` == `organization that owns the repository the handler actually writes to`.

An unauthenticated attacker can satisfy verification by setting `repository.owner.login` to any org in the multi-tenant configuration that has no `webhook_secret` set (a valid, documented, non-privileged configuration state — `verify_webhook_signature` then returns `true` unconditionally, ignoring `X-Hub-Signature` entirely), while setting `repository.full_name` to point at an entirely different, secured organization's tracked repository. The handler dispatch logic never re-validates that the "authenticating" org and the "acted upon" repository's org match.

### Impact Explanation
Because `StatusHandler`/`PushHandler`/`CheckSuiteHandler` etc. trust `repository.full_name` to select the stack, and the commit `state`/`context`/`target_url` fields directly from the payload to create `Status` records [6](#0-5)  / trigger `GithubSyncJob` [7](#0-6) , an attacker who only needs to know that some configured org lacks a webhook secret (no secret, no token, no private key, no repository access required) can forge a `status` event for an arbitrary victim commit in a completely unrelated, secured org's stack. A fabricated "success" CI status on a commit that never actually passed CI can unblock a merge/deploy gate that Shipit relies on for release safety, resulting in an unauthorized deploy — matching the Critical impact bucket ("unauthorized deploy").

### Likelihood Explanation
Likelihood is high in any real-world multi-org Shipit deployment: `webhook_secret` is explicitly optional per org, so it's common for at least one org (e.g., a low-stakes test/internal org) to be configured without one while other orgs host sensitive production stacks. No credentials, tokens, or write access are required — only knowledge of one blank-secret org's login, which is discoverable from the Shipit UI/stack listing or by trial.

### Recommendation
Cross-validate that `repository.owner.login` (or `organization.login`) used to select the verifying org's secret matches the owner segment of `repository.full_name` before dispatching to handlers, and reject the request if they diverge. Additionally, treat a missing `webhook_secret` as "verification not configured for this org" rather than "always verified" — either require a secret for every configured org, or ensure the fallback still validates that the target repository belongs to that same org's known repository set instead of trusting `full_name` unconditionally.

### Proof of Concept
1. In `config/secrets.yml`, configure two orgs: `OrgWithoutSecret` (no `webhook_secret`) and `victim-org` (configured with a real secret, tracked stacks).
2. Send:
```
POST /webhooks
X-Github-Event: status
(no valid X-Hub-Signature required)

{
  "repository": { "owner": { "login": "OrgWithoutSecret" }, "full_name": "victim-org/victim-repo" },
  "sha": "<real commit sha in victim-org/victim-repo>",
  "state": "success",
  "target_url": "https://attacker.example/fake",
  "context": "ci/tests",
  "branches": [{ "name": "master" }]
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgWithoutSecret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/invalid) signature header.
4. `StatusHandler` resolves the stack via `repository.full_name` = `victim-org/victim-repo` and creates a forged `Status` "success" on the targeted commit, potentially satisfying a CI-gated deploy condition for a repository the attacker has no access to.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L28-30)
```markdown
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
