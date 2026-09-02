Found the analog. This confirms a genuine multi-org signature/routing mismatch in `WebhooksController`.

### Title
Webhook signature is verified against an org key chosen from the unverified payload, letting one onboarded GitHub org forge events for another org's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In the multi-org GitHub App configuration, `WebhooksController` selects which `webhook_secret` to check the request signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body, then uses the *same* body's `repository.full_name` to route the event to a stack via `Handler#repository_name`. The org used to pick the verification key and the repository that ends up mutated are two different fields inside the same untrusted payload, and only their combination is protected by the signature - not their consistency with each other.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, not-yet-verified JSON body and uses it to select the `GitHubApp`/secret to validate against: [1](#0-0) [2](#0-1) 

Shipit explicitly supports hosting several independent GitHub Apps/organizations side by side, each with its own `webhook_secret`, selected via `Shipit.github(organization:)`: [3](#0-2) [4](#0-3) 

Once the request is accepted, handlers resolve the target stack purely from `repository.full_name` in the same payload - a field that is *not* used for key selection: [5](#0-4) 

Because HMAC verification only proves "this body was signed with organization X's secret," and organization X is picked by reading a field from that same body, an attacker who is a legitimate installer/admin of *any one* onboarded organization (call it `OrgOne`, with its own real, GitHub-issued `webhook_secret`) can trivially compute a valid `X-Hub-Signature` for an arbitrary hand-crafted JSON body using `OrgOne`'s secret. Because they know `OrgOne`'s secret (it's their own app installation), they can freely author the payload's `repository.full_name` to point at any *other* onboarded stack (e.g. `OrgTwo/victim-repo`) while keeping `repository.owner.login`/`organization.login` set to `OrgOne` (so `verify_signature` picks `OrgOne`'s key, which they know, and the signature check passes). The binding that should hold - "the org whose secret authenticated this request" equals "the org/repo whose state this request is allowed to mutate" - is broken: `repository_owner` (verified indirectly by key selection) and `repository.full_name` (acted upon by handlers) are independent, attacker-controlled fields inside the same signed blob, and nothing cross-checks that the repository actually belongs to the authenticating organization.

### Impact Explanation
This lets an attacker who only controls one tenant's GitHub App installation (a normal, low-privilege scenario in a shared/multi-org Shipit instance) forge webhook events — `push`, `status`, `check_suite`, `membership`, etc. — attributed to a completely different, victim organization's repository/stack that they have no access to. Depending on the handler this can: fabricate CI/check statuses to unblock deploys (`status`/`check_suite` handlers driving `Commit` state used for deploy gating), enqueue `GithubSyncJob` against a victim stack, or manipulate `Team`/`Membership` records used for authorization (`membership` handler creates/removes memberships) — an escalation into `Shipit.github_teams` authorization content and unauthorized deploy gating on stacks belonging to other tenants. This matches the required High-impact class: escalation into `Shipit.github_teams` authorization / unauthenticated manipulation of task/deploy-gating state across repositories the attacker does not own.

### Likelihood Explanation
Requires only that the deployment be configured for multiple GitHub organizations (documented, supported configuration: `docs/setup.md` "Using Multiple Github Applications") and that the attacker controls (as an app installer/admin) at least one of the onboarded organizations - no Shipit session, `ApiClient` token, or private key of the victim org is needed. Forging the HTTP request with a correct `X-Hub-Signature` computed from a secret the attacker legitimately possesses is trivial.

### Recommendation
After selecting the `GitHubApp` and verifying the signature, cross-check that the payload's `repository.full_name`/`repository.owner.login` actually resolves to a `Repository`/`Stack` that belongs to the same organization used for key selection (e.g., compare `repository_owner` against the actual owner recorded for the resolved `Stack`/`Repository`), and reject (422) the webhook if there is a mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the legitimate admin/installer of `OrgOne`'s GitHub App, obtain `OrgOne`'s `webhook_secret` (you own this installation).
3. Craft a JSON body: `{"repository": {"owner": {"login": "OrgOne"}, "full_name": "OrgTwo/victim-repo"}, ... "action": "removed", "member": {"login": "victim-admin"}}` for the `membership` event (or a `push`/`status` payload targeting `OrgTwo/victim-repo`).
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgOne_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: membership` (or `push`/`status`).
5. `verify_signature` reads `repository_owner` → `"OrgOne"`, fetches `OrgOne`'s `GitHubApp`, and the signature validates successfully against the attacker-known secret.
6. `Handler#repository_name` then resolves `"OrgTwo/victim-repo"` from the same payload and the corresponding handler mutates `OrgTwo`'s `Stack`/`Team`/`Commit` state, even though the request was never signed by `OrgTwo`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
