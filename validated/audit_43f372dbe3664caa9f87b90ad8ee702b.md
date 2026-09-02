### Title
Forged GitHub webhooks accepted for any stack when any configured multi-org GitHub App has no `webhook_secret` set, because the field used to select the verifying organization is disconnected from the field used to resolve the target repository/stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App configuration (and therefore which `webhook_secret`) to validate an inbound webhook against using a value taken straight from the unauthenticated request body, before any signature has been checked. Downstream event handlers then act on a *different* field of that same unauthenticated body (`repository.full_name`) to decide which `Stack`/`Repository` the event applies to. When Shipit is configured with multiple GitHub organizations (a documented, supported deployment mode) and at least one of them has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` unconditionally returns `true`, so an attacker can send an arbitrary, unsigned payload that "authenticates" as the secret-less organization while its `repository` object names a completely different, protected repository/stack.

### Finding Description
`WebhooksController#verify_signature` resolves the authority to check the request against like this: [1](#0-0) 

`repository_owner` is derived purely from the JSON body, with a fallback: [2](#0-1) 

If the `repository.owner.login` key is absent, Shipit falls back to `organization.login`, which is a *different* nested object than `repository`. Both are supplied by the attacker in the same unauthenticated POST body — `repository_owner` is only used to pick which org's `GitHubApp`/secret to check with, it is never itself covered by a signature at the time it's read.

The actual cryptographic check is: [3](#0-2) 

Note `return true unless webhook_secret` — if the organization selected via `repository_owner`/`organization.login` has no `webhook_secret` configured (a supported configuration, shown blank in the project's own multi-org fixture), signature verification is a no-op regardless of the `X-Hub-Signature` header supplied.

Once `verify_signature` passes, `create` dispatches the full, still-unauthenticated `params` hash to event handlers, keyed only by the same body: [4](#0-3) 

Handlers (e.g. the `status` handler) then resolve and mutate real DB objects (in the case of `status` events, creating `Status` records) directly from body-supplied `sha`/`state`/`context`/`repository` fields, as demonstrated by the engine's own test suite: [5](#0-4) 

Multiple independent GitHub App configurations, each with their own optional `webhook_secret`, is a first-class supported feature: [6](#0-5) 

and the project's own test fixture demonstrates two orgs configured side by side, each with `webhook_secret: # nil`: [7](#0-6) 

**The broken equality:** the organization whose credentials authenticate the request (`repository_owner`/`organization.login`, used only to select the `GitHubApp` instance) is never proven to equal the repository actually acted upon (`repository.full_name`, used by handlers to find the `Stack`). As soon as *any one* configured org lacks a `webhook_secret`, that equality can be broken by an anonymous attacker: authenticate as the secret-less org, act on any other org's repository/stack.

### Impact Explanation
This is an authentication-bypass / cross-repository-write class issue: an unauthenticated, external attacker can inject arbitrary `status`, `push`, `check_suite`, etc. events for *any* stack managed by the Shipit instance, not just the one belonging to the secret-less GitHub App. In particular, forging `status` webhooks lets an attacker mark arbitrary commits as CI-`success` for stacks belonging to a different (properly-secured) organization, which can satisfy `ci.require`/merge-queue/continuous-deployment gating conditions and lead to an unauthorized deploy of unreviewed or malicious code — matching the "unauthorized deploy" impact tier.

### Likelihood Explanation
Requires only that the Shipit deployment be configured for more than one GitHub organization (documented supported feature) and that at least one of those organizations omits `webhook_secret` (also explicitly supported: `return true unless webhook_secret`). No credentials, session, `ApiClient` token, or prior access is required — a bare unauthenticated `POST /webhooks` request with a crafted JSON body is sufficient.

### Recommendation
- Never allow `verify_webhook_signature` to short-circuit to `true` when a `webhook_secret` is unset for an organization that shares a Shipit instance with other organizations; require signature verification whenever any other configured organization enforces one, or reject the request outright.
- Bind the organization used for signature selection to the organization actually referenced by the payload consumed by handlers: verify signatures using the secret associated with `repository.full_name`'s owner (post-verification), not a value read from the payload before verification, and reject events whose `repository.owner.login` does not match `organization.login` when both are present.
- Consider requiring `webhook_secret` to be mandatory for all configured GitHub organizations in a multi-org setup.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `SecretOrg` (with `webhook_secret` set, hosting the target stack `secretorg/protected-repo`) and `OpenOrg` (with `webhook_secret` left blank), matching the pattern in `test/dummy/config/secrets_double_github_app.yml`.
2. Send an unauthenticated request:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "organization": { "login": "OpenOrg" },
  "sha": "<any commit sha of secretorg/protected-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "secretorg/protected-repo", "owner": {} }
}
```
(no `X-Hub-Signature` header is needed, or any arbitrary value works)
3. `repository_owner` falls back to `params.dig('organization','login')` = `"OpenOrg"`; `Shipit.github(organization: "OpenOrg")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
4. The `status` handler processes the payload using `repository.full_name` = `secretorg/protected-repo`, creating a forged `success` `Status` for the target stack that Shipit never actually received a legitimate, `SecretOrg`-signed webhook for.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
