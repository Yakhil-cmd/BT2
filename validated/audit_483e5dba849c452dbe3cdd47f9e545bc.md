### Title
Webhook signature is verified against an organization chosen from an unauthenticated field, but the sync/deploy is executed against a different, unbound repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the request against using `repository_owner`, a value pulled straight out of the untrusted, not-yet-verified JSON body. The actual repository that the event handlers act on (to find `Stack`s and enqueue sync/deploy jobs) is read from a *different* field of the same untrusted body, `repository.full_name`. Nothing binds these two fields together, so the organization whose secret "authenticates" the request is not necessarily the organization that owns the repository being written to.

### Finding Description
`repository_owner` is derived purely from the request body before any signature check occurs: [1](#0-0) 

This value is used to pick the `GitHubApp` instance and thus the `webhook_secret` used to verify `X-Hub-Signature`: [2](#0-1) 

Verification silently passes whenever the selected org config has no secret configured: [3](#0-2) 

Meanwhile, every handler (e.g. `PushHandler`) resolves the *target* repository/stack from a completely separate field, `repository.full_name`, of the same unauthenticated body: [4](#0-3) [5](#0-4) 

Shipit explicitly supports multi-organization configurations, each with its own independent `webhook_secret`, which may legitimately be left blank per org: [6](#0-5) [7](#0-6) 

The broken binding is: **the organization whose credential authenticates the webhook != the repository whose stacks are synced/deployed by that webhook.** Because `repository_owner` (used only for signature lookup) and `repository.full_name` (used to select the affected `Stack`) are independent, uncorrelated fields inside the same forgeable JSON payload, an attacker who knows (or guesses) the login of *any one* configured organization that lacks a `webhook_secret` can trivially satisfy `verify_signature`, then point `repository.full_name` at a totally unrelated, fully-configured organization's repository to drive its handlers.

### Impact Explanation
This allows forged GitHub webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) to be accepted for repositories belonging to organizations that are properly secured with strong secrets, as long as at least one other configured organization in the same Shipit instance has no `webhook_secret` set. Concretely for `push`, an attacker can supply an arbitrary `after` SHA, causing `stack.sync_github(expected_head_sha: params.after)` to run against a victim stack with no valid GitHub signature at all — an unauthenticated cross-repository trigger of Shipit's sync pipeline, which can feed into deploy/auto-deploy flows. This matches the "unauthorized deploy/rollback" / cross-repository-write impact class.

### Likelihood Explanation
Requires a multi-org Shipit deployment where at least one configured GitHub organization has an empty/unset `webhook_secret` (a state the codebase and shipped example configs explicitly treat as valid/supported, e.g. `webhook_secret: # nil`). No authentication, API token, or repository write access is needed — only knowledge of that one organization's GitHub login and the target repository's `full_name`, both of which are typically public information.

### Recommendation
Bind the field used for signature verification to the field used for repository resolution: verify the webhook signature using the secret associated with the *same* repository/org that the handler will act on (derived from `repository.full_name`, not a separately-trusted `repository.owner.login`/`organization.login`), and reject the request if the resolved repository's org doesn't match the org that owns the secret that validated the signature. Additionally, consider requiring a non-blank `webhook_secret` for any organization if multiple organizations are configured, since one unauthenticated org effectively degrades verification for the whole installation.

### Proof of Concept
Preconditions: Shipit configured with two orgs, e.g. `SecureOrg` (strong `webhook_secret`) and `NoSecretOrg` (`webhook_secret: nil`), and a tracked stack for `SecureOrg/target-repo`.

```
POST /github/webhooks
X-Github-Event: push
Content-Type: application/json
(no valid X-Hub-Signature required)

{
  "repository": {
    "owner": { "login": "NoSecretOrg" },
    "full_name": "SecureOrg/target-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```

- `repository_owner` resolves to `NoSecretOrg`.
- `Shipit.github(organization: "NoSecretOrg").verify_webhook_signature(...)` returns `true` immediately because `webhook_secret` is blank for that org [8](#0-7) .
- `PushHandler` then resolves stacks via `repository.full_name` = `"SecureOrg/target-repo"` [9](#0-8) , and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for every matching stack [5](#0-4) , without any valid signature from `SecureOrg`.

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
