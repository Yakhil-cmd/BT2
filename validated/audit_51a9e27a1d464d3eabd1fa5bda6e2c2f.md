## Confirmed: signature-authenticating org key is not bound to the payload's `repository.full_name` used for stack targeting

### Title
Webhook signature verification authenticates only `repository.owner.login`/`organization.login`, while push/status handlers act on the independently-attacker-controlled `repository.full_name` field, allowing cross-organization forged writes in multi-app deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the request against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1)  This is the same equality break pattern as the report's oracle bug: one field of the payload ("owner that authenticates") is checked, while a *different* field of the same payload ("repository actually written") drives the state-changing action, and nothing binds the two together.

### Finding Description
Shipit supports multiple GitHub Apps, one per organization, each with its own independent `webhook_secret`, selected at runtime by `Shipit.github(organization: repository_owner)`. [3](#0-2)  `GitHubApp#verify_webhook_signature` validates the raw request body against that organization's secret — and critically, **returns `true` unconditionally if no `webhook_secret` is configured for that organization**: `return true unless webhook_secret`. [4](#0-3) 

Downstream, the actual event handlers (`PushHandler`, `StatusHandler`, etc.) never look at `repository.owner.login` again. They resolve the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`: [5](#0-4)  and `Repository.from_github_repo_name` simply splits that string on `/`. [6](#0-5) 

Because the JSON body is fully attacker-supplied (there is no cross-check that `repository.full_name`'s owner segment equals `repository.owner.login`/`organization.login`), an attacker who can produce a validly-"verified" request for **any** configured organization (e.g., one that has no `webhook_secret` set, which the docs show as a legitimate per-org config option `webhook_secret: # nil`) [7](#0-6)  can set `repository.owner.login` to that unsecured organization while setting `repository.full_name` to `OtherOrg/some-repo`, a repository belonging to a *different*, secured GitHub App installation. The signature check passes (bound to the unsecured org), but `PushHandler`/`StatusHandler` act on the stack belonging to `OtherOrg/some-repo`.

This breaks the equality: `organization authenticated == organization whose repository is written`.

### Impact Explanation
`PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for any not-archived stack matching the forged branch, and `StatusHandler#process` creates commit statuses (`commit.create_status_from_github!`) for any commit matching the forged sha, on stacks belonging to an organization the attacker never proved control of. This is a cross-repository write reachable with only knowledge that some tenant/org in the same Shipit installation has an unset `webhook_secret` (a documented, supported configuration state), without needing any Shipit session, `ApiClient` token, or GitHub credentials for the targeted organization/repository — matching the "cross-repository writes" Critical criterion.

### Likelihood Explanation
Requires: (1) a multi-org GitHub App deployment (explicitly documented and tested — `test/dummy/config/secrets_double_github_app.yml`) [8](#0-7) , and (2) at least one configured organization with `webhook_secret` left blank (also explicitly documented as valid: `webhook_secret: # nil`). Given multi-tenant Shipit installs commonly onboard orgs incrementally, an org without a secret configured yet is a realistic operational state, making this moderately likely in real deployments that use the multi-org feature.

### Recommendation
After signature verification succeeds against the organization identified by `repository_owner`, re-derive and enforce that every owner-identifying field used later by handlers (`repository.full_name`, `repository.owner.login`) is consistent with the organization whose secret validated the request. Reject the webhook (422) if `repository.full_name.split('/').first` does not case-insensitively match `repository_owner`. Additionally, consider refusing to treat an unset `webhook_secret` as an implicit "always verified" bypass in multi-org configurations, or require an explicit opt-in flag for that behavior.

### Proof of Concept
1. Configure Shipit with two organizations: `SecureOrg` (webhook_secret set) and `OpenOrg` (webhook_secret left blank), matching `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker sends `POST /github/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (or any junk value), and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to exist on SecureOrg/target-repo>",
  "repository": { "owner": { "login": "OpenOrg" }, "full_name": "SecureOrg/target-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OpenOrg")`, whose `verify_webhook_signature` returns `true` unconditionally because `OpenOrg`'s `webhook_secret` is blank. [4](#0-3) 
4. `PushHandler.call(params)` resolves `stacks` via `Repository.from_github_repo_name("secureorg/target-repo")` and invokes `stack.sync_github(expected_head_sha: ...)` on `SecureOrg`'s stack — a write the attacker never authenticated for. [9](#0-8)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
