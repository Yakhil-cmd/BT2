### Title
Cross-organization webhook forgery via organization/repository binding mismatch in `WebhooksController#verify_signature` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a webhook's HMAC signature against using `repository_owner`, which is read from `payload.dig('repository','owner','login')`. However, the webhook handlers that actually act on the payload (e.g. `Handlers::Handler#stacks`) look up the target `Repository`/`Stack` using an entirely different, unbound field of the same attacker-controlled JSON body: `payload.dig('repository','full_name')`. Because a webhook's raw body is provided in full by whoever sends the POST request (not re-derived by Shipit from GitHub metadata), an attacker who knows the `webhook_secret` for *any* organization configured in a multi-org Shipit instance can sign a payload that "owns" `repository.owner.login` for their org, while `repository.full_name` points at a completely different, victim organization's repository.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and fetches the matching Github App config purely to find the right secret: [1](#0-0) [2](#0-1) 

The signature check itself only proves that the raw body was HMAC-signed with the secret belonging to whichever organization's `login` the attacker put in `repository.owner.login`: [3](#0-2) 

Once the signature check passes, the event is dispatched to handlers (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`), and the base `Handler` class resolves the actual `Stack`/`Repository` to operate on using a **different** field of the same payload — `repository.full_name` — with no re-validation that it belongs to the organization whose secret authenticated the request: [4](#0-3) [5](#0-4) 

This is precisely the analog to `TwabLib::getTwabBetween`'s bug class: a value that is used to satisfy validation (`repository.owner.login`, checked to select/verify the signing secret) is not the same value that downstream logic actually trusts and acts on (`repository.full_name`). Since Shipit explicitly supports multiple GitHub organizations sharing one instance, each with its own independent `webhook_secret` (see the multi-org fixture and changelog entry "Support multiple GitHub organisations"): [6](#0-5) [7](#0-6) 

an attacker who legitimately controls (or knows the secret of) one configured organization can forge a payload claiming `repository.owner.login: "orgB"` (their own org, whose secret they hold) but `repository.full_name: "orgA/victim-repo"` (a different organization/repository entirely). `verify_signature` validates successfully using OrgB's secret, and the dispatched handler then resolves and mutates state belonging to OrgA's repository/stack.

The equality that should hold, but doesn't, is:
`organization whose secret authenticated the signature == organization that owns the repository the handler writes to`

### Impact Explanation
Handlers driven by this payload can mutate state for a target repository/stack the attacker does not control: creating fabricated commits, forging commit statuses (`status`/`check_suite` handlers), or influencing merge/deployable-status pipelines for another organization's stack — all without ever having write access to that repository. Depending on which handler is invoked (e.g. `status`, `push`, `check_suite`, `pull_request`), this can mark arbitrary commits as CI-green/deployable in a victim stack, potentially enabling those commits to pass through continuous-delivery gating and be auto-deployed — an unauthorized, cross-organization write into a stack the attacker never had legitimate access to. This satisfies the "cross-repository writes" / "unauthorized deploy" criteria for Critical impact.

### Likelihood Explanation
Exploitation requires only that the attacker knows/controls a `webhook_secret` for one organization already registered in the same multi-tenant Shipit instance (a routine, unprivileged condition for any org onboarded onto a shared Shipit deployment) and the ability to POST directly to the public `/github/webhooks` endpoint — no `ApiClient` token, GitHub App private key, session, or write access to the victim repository is required. The `repository.full_name` vs `repository.owner.login` divergence is not checked anywhere in the request path.

### Recommendation
Do not derive the trust boundary for signature verification from one field of the untrusted payload and the object-resolution boundary from another, unrelated field of the same payload. After signature verification succeeds for `repository_owner`, re-validate that `payload.dig('repository','full_name')` (and `payload.dig('organization','login')` where relevant) actually belongs to that same, now-authenticated organization before dispatching to handlers — e.g., assert `repository.full_name.split('/').first.casecmp(repository_owner).zero?`, or bind the found `Repository`'s owner to `repository_owner` and reject mismatches.

### Proof of Concept
1. Attacker is onboarded onto a shared/multi-org Shipit instance as `orgB`, and knows (or is the admin who configured) `github.orgB.webhook_secret = S`.
2. Attacker crafts a JSON body:
```json
{
  "repository": {
    "owner": { "login": "orgB" },
    "full_name": "orgA/victim-repo"
  },
  "sha": "<attacker-chosen sha>",
  "state": "success",
  "target_url": "https://ci.example.com/fake"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` and sends:
```
POST /github/webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<computed>
```
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgB")` and successfully verifies the signature against secret `S`. [1](#0-0) 
5. The `status` handler resolves the target stack via `Repository.from_github_repo_name("orgA/victim-repo")` and records a forged successful status for `orgA`'s repository/commit, despite the request never being authenticated by anything belonging to `orgA`. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** CHANGELOG.md (L130-132)
```markdown
* Support for sending signed webhooks with the secret key. (#1150)
* No longer assume `master` is the default branch. (#1149)
* Support multiple GitHub organisations. (#1151)
```
