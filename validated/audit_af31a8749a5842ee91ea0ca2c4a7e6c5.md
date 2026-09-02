### Title
Webhook signature verification authenticates the GitHub organization named in the unverified payload, decoupling it from the repository the event handlers act on - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification by reading an **unauthenticated** field straight out of the raw JSON body (`repository.owner.login`, falling back to `organization.login`), *before* any signature has been checked. In a multi-organization Shipit deployment (supported natively via `Shipit.github(organization:)` and demonstrated by the `secrets_double_github_app.yml` fixture), this breaks the intended binding: `organization authenticated by signature == repository the handlers write to`.

### Finding Description
```ruby
# app/controllers/shipit/webhooks_controller.rb
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
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`repository_owner` is derived from the attacker-controlled JSON body itself, and it is used only to pick *which organization's webhook secret* to HMAC-verify against — it does not, and cannot, prove that the rest of the payload (e.g. `repository.full_name`, `sha`, commit data) actually belongs to that organization. Verification only proves "the sender knows the secret configured for org X"; it says nothing about whether the repository fields the downstream handlers subsequently read and act on (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) genuinely correspond to org X.

The decoupling of these two payload fields is demonstrable: the controller test suite shows `repository.full_name` being mutated completely independently of the fields the signature-organization lookup relies on:
```ruby
unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
``` [2](#0-1) 

and the signature-verification test explicitly keys the lookup off a hard-coded organization string (`'shopify'`) that is set from the payload merge, independent from whatever repository the event body ultimately names:
```ruby
Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)
``` [3](#0-2) 

Because a single Shipit engine instance can be configured with several distinct GitHub Apps/orgs, each with its own `webhook_secret` (`config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`) [4](#0-3) [5](#0-4) , an attacker who legitimately controls one of these configured organizations (e.g., they administer a GitHub org that this Shipit instance also tracks stacks for) can produce a valid HMAC for a payload whose `repository.owner.login`/`organization.login` names *their own* org, while setting the remaining payload fields (`repository.full_name`, commit `sha`, `state`, `target_url`, etc.) to reference a **different, victim stack** hosted under a different org on the same Shipit instance. `verify_signature` passes (it only checked the attacker's own org's secret), and the event handler is then invoked with the full, attacker-forged `params` hash naming the victim repository/commit.

### Impact Explanation
Handlers such as the `status` event handler create/update a `Status` record for an arbitrary commit `sha` in whatever stack matches the (attacker-supplied) repository fields, directly from unauthenticated payload content (`state`, `target_url`, `description`) as shown in the controller test [6](#0-5) . Shipit deploy safety gates on commit CI status; forging a `success` status on a victim stack's commit via a signature that only proves control of an unrelated, attacker-owned org lets an unprivileged attacker cause an unauthorized deploy to proceed against a repository they never authenticated for — a cross-repository write that was never covered by the verified signature, matching the Critical impact bar (unauthorized deploy / cross-repository writes).

### Likelihood Explanation
Requires the attacker to control at least one GitHub organization that is itself configured as a Shipit GitHub App/webhook-secret entry on the same Shipit instance (a realistic scenario for shared/self-service multi-tenant Shipit deployments per the documented multi-org config format), and knowledge of the target victim stack's `repository.full_name`/commit shas, both of which are ordinary public information. No repository write access, API token, or session is needed — only the ability to send a webhook HTTP request with a signature computed from the attacker's own legitimately-known secret.

### Recommendation
Bind the signature-verifying organization to the *same* repository identity the handlers subsequently act on: after HMAC verification succeeds for `repository_owner`, re-derive/require that `repository.full_name`'s owner matches `repository_owner` (or resolve the target `Repository`/`Stack` strictly by the same owner field used for secret selection) before dispatching to handlers, rejecting any payload where these fields diverge.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (supported multi-org config).
2. Attacker crafts a `status` webhook body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "sha": "<victim commit sha>", "state": "success", ...}`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` (which they legitimately know) over the raw body.
4. POST to `/github/webhooks`. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies the HMAC against the attacker's own secret [7](#0-6) .
5. `create` then dispatches `params` (naming `victim-org/victim-repo` and the victim commit sha) to the `status` handler, which writes a forged `success` `Status` onto the victim stack's commit, bypassing that org's own webhook secret entirely.

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
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

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end
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
