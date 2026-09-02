### Title
Webhook signature verification uses a different organization field than the one used to select the target repository/stack, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to verify the HMAC signature against using `repository_owner` (`params.dig('repository','owner','login')`), while every webhook `Handler` resolves the actual `Repository`/`Stack` to act on using a *different* field from the same JSON body, `payload.dig('repository','full_name')` (`Handler#repository_name`). In a multi-organization Shipit deployment, if any configured organization has no `webhook_secret` set, signature verification for that organization is a no-op, letting an attacker forge a payload that claims to be from the unsecured organization while pointing `repository.full_name` at a stack belonging to a different, secured organization.

### Finding Description
`verify_signature` picks the app/secret purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that resolved app: [3](#0-2) 

Meanwhile, every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) determines the `Repository`/`Stack` to mutate using `payload.dig('repository', 'full_name')`, a completely separate field from the same JSON body, with no check that its organization matches the org used for signature verification: [4](#0-3) [5](#0-4) 

Multi-organization configuration, where each org has an independent (optionally absent) `webhook_secret`, is an explicitly documented and supported feature: [6](#0-5) [7](#0-6) 

Every shipped secrets template — including the multi-org example — shows `webhook_secret:` left blank/`nil` as a valid, first-class configuration: [8](#0-7) [9](#0-8) 

**The broken binding:** `organization authenticated (repository.owner.login → GitHubApp secret lookup) == organization whose repository is written to (repository.full_name → Repository/Stack lookup)`. Before the attack, these two fields are only equal because GitHub itself populates both consistently. After an attacker crafts an arbitrary POST to `/webhooks`, nothing enforces that equality: the attacker sets `repository.owner.login` to an organization configured with no `webhook_secret` (bypassing the signature check entirely, since `X-Hub-Signature` is never even validated against real HMAC) and sets `repository.full_name` to `otherorg/other-repo`, a stack belonging to a fully secured, unrelated organization. The `PushHandler`/`StatusHandler` code path only ever looks at `full_name`, so it acts on the target org's stack regardless of which org "authenticated" the request.

### Impact Explanation
An unprivileged, unauthenticated network attacker can:
- Trigger `Stack#sync_github`/`GithubSyncJob` for any stack under any configured organization, forcing arbitrary ref sync state.
- Forge commit statuses (`StatusHandler`) or check-suite results (`CheckSuiteHandler`) on arbitrary commits of stacks belonging to a different, properly-secured organization — statuses/checks are used elsewhere in Shipit to gate deploy readiness ("deployable" checks), so forged green statuses can influence whether a commit is considered deployable.
- This is a real cross-organization write with no credential belonging to the target organization, satisfying the "authentication bypass / cross-repository writes" bar.

### Likelihood Explanation
Requires: (1) the deployment uses the documented multi-organization `github:` config schema, and (2) at least one configured organization has no `webhook_secret` set — a state the shipped example configs treat as the default/normal case (`webhook_secret: # nil`). Given the templates explicitly ship this as an acceptable default, it is plausible in real deployments, and exploitation requires only a single unauthenticated HTTP POST with a guessed/known organization login (organization names are public on GitHub), no secrets and no session.

### Recommendation
Bind the signature-verifying organization to the organization actually acted upon: derive the app/secret used in `verify_signature` from the same repository record that `Handler#repository_name` resolves to (i.e., look up the `Repository`'s configured organization from Shipit's own data, not from attacker-controlled `repository.owner.login`), or explicitly re-validate that `repository.owner.login` matches the owner embedded in `repository.full_name` before dispatching to handlers. Additionally, consider requiring a non-blank `webhook_secret` for every configured organization (fail configuration validation instead of silently trusting unsigned payloads).

### Proof of Concept
1. Configure Shipit with two organizations per the multi-org schema: `OrgA` (no `webhook_secret`) and `OrgB` (secured, has an active `Stack` for `OrgB/private-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/private-repo"
  }
}
```
No valid `X-Hub-Signature` header is required because `Shipit.github(organization: 'OrgA').verify_webhook_signature` short-circuits to `true` (blank secret).
3. `WebhooksController#create` dispatches to `PushHandler`, which resolves the target via `payload.dig('repository','full_name')` = `"OrgB/private-repo"`, and triggers `stack.sync_github(expected_head_sha: "deadbeef...")` for `OrgB`'s stack — despite the request never being authenticated for `OrgB`.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
