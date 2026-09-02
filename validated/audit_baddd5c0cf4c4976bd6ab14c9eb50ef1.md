### Title
Webhook signature verification keyed by attacker-controlled `repository.owner.login` is decoupled from the `repository.full_name` actually acted upon, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an inbound webhook's HMAC signature against using a field taken directly from the untrusted JSON body (`repository.owner.login` or `organization.login`), while the handlers that actually mutate state (e.g. `PushHandler`, `StatusHandler`) resolve the target `Repository`/`Stack` using a *different* untrusted field from the same body (`repository.full_name`). Nothing binds these two fields together, so in a multi-organization deployment (a supported configuration, see `test/dummy/config/secrets_double_github_app.yml`), an attacker who can produce a validly-signed (or unsigned, if that org has no `webhook_secret`) payload for *one* configured organization can set `repository.full_name` to point at a repository belonging to a *different* configured organization, and the handler will act on it as if the request had been authenticated for that organization.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
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
``` [1](#0-0) [2](#0-1) 

`repository_owner` — the value that selects *which organization's webhook secret* is used to verify the HMAC — is read straight out of the attacker-supplied JSON body, before any verification has occurred.

`GitHubApp#verify_webhook_signature` additionally short-circuits to `true` whenever that organization has no configured secret:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Meanwhile, every handler resolves the actual object being written using a separate, independently attacker-controlled field of the same body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler` then uses that resolved stack to trigger a sync directly from the webhook payload's `after` SHA:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

`StatusHandler` similarly writes a `Status` record for a commit resolved purely from payload data (as exercised by `WebhooksControllerTest#":state create a Status for the specific commit"`), and these `Status` rows are what gate whether a commit is considered deployable in the rest of the engine. [6](#0-5) 

Multi-organization installations are an explicitly supported configuration:
```yaml
github:
  OrgOne:
    webhook_secret: # nil
    ...
  OrgTwo:
    webhook_secret: # nil
    ...
``` [7](#0-6) 

**Binding broken (as an equality):**
`organization authenticated by verify_signature (repository_owner)` ⇎ `repository actually written by the handler (repository.full_name)`.

Both sides are read from the same unauthenticated JSON body, but only the first is subject to any cryptographic check, and that check is keyed by the attacker's own choice of `repository_owner`. There is no requirement that `full_name` be prefixed by `repository_owner`, nor any secondary check tying the two together after the fact.

### Impact Explanation
In a Shipit deployment tracking repositories across more than one GitHub organization/App (a configuration the engine explicitly supports via `Shipit.github(organization:)` and documented in the dummy multi-app secrets fixture), if any one of those organizations has no `webhook_secret` configured (`nil`, which `verify_webhook_signature` explicitly treats as "always verified"), an unauthenticated attacker can:
1. Craft a webhook body with `repository.owner.login` set to the org with no/known secret, and `repository.full_name` set to a repository tracked under a *different, victim* organization.
2. Send it to `/webhooks` with event `push` or `status`.
3. `verify_signature` picks the weak/unsecured org's app and passes, while `PushHandler`/`StatusHandler` act on the victim organization's stack/commit.

This lets an outsider forge `push` events to trigger arbitrary `sync_github` calls, or forge `status` events to fabricate green CI/commit statuses for commits in a repository they do not control, which is precisely the signal Shipit's deploy-readiness checks rely on — enabling an unauthorized deploy of a commit that never actually passed CI in the real repository. This falls under the "unauthorized deploy" / "unauthenticated write into repository/stack state" impact category.

### Likelihood Explanation
Requires only an HTTP POST to the public `/webhooks` endpoint, no session, no `ApiClient` token, and no GitHub write access to the victim repository — only knowledge that some organization on the instance has `webhook_secret` unset (visible from documentation guidance that it is "optional") or a webhook secret the attacker legitimately possesses for their own onboarded organization. Multi-tenant/multi-org Shipit installs are a first-class, documented configuration, making this a realistic deployment shape.

### Recommendation
Do not let attacker-controlled payload fields select the verification key context. Instead:
- Verify the webhook signature against every configured organization's secret (or a global secret) rather than one chosen by an untrusted field, or
- After verification, require that the resolved `repository_owner` used for verification matches the owner embedded in `repository.full_name`/`stacks`' actual `Repository#owner`, rejecting the request otherwise, and
- Disallow (or explicitly flag) organizations configured with a blank `webhook_secret` when any other organization on the same instance has push/deploy-gating repositories, since a blank secret makes that organization's identity trivially forgeable and usable as a pivot.

### Proof of Concept
Given a Shipit instance configured with two GitHub Apps as in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne`, `OrgTwo`, both currently shown with `webhook_secret: # nil` in the fixture) and a tracked repository `OrgOne/victim-repo`:

1. Attacker sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<anything, or omitted>
{
  "repository": {
    "owner": { "login": "OrgTwo" },   // selects OrgTwo's (secret-less) GithubApp for verification
    "full_name": "OrgOne/victim-repo" // actually acted upon by StatusHandler
  },
  "sha": "<victim commit sha>",
  "state": "success",
  ...
}
```
2. `verify_signature` calls `Shipit.github(organization: "OrgTwo")`, whose `verify_webhook_signature` returns `true` unconditionally because `OrgTwo`'s `webhook_secret` is blank. [8](#0-7) 
3. `StatusHandler` resolves the commit/stack via `payload.dig('repository', 'full_name')` = `"OrgOne/victim-repo"`, and writes a fabricated `success` status for the victim repository's commit. [9](#0-8) 

This is directly analogous to the reported bug class: a security check is performed using one variable (`repository_owner`, chosen to select the verification key — akin to `balanceOf(address(this))`), while the actual state-changing operation is driven by a different, uncorrelated variable from the same untrusted input (`repository.full_name`, akin to `totalSupply()`), letting the two diverge and defeating the intended invariant that "only a signed webhook for organization X can affect organization X's data."

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-35)
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
