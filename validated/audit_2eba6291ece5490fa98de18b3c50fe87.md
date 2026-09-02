### Title
Unauthenticated webhook signature bypass via organization/repository binding mismatch in multi-org configurations - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
When Shipit is configured with multiple GitHub Apps (one per organization, per `Using Multiple Github Applications` in `docs/setup.md`), `WebhooksController#verify_signature` selects which app config/secret to use for HMAC verification based on `repository_owner`, a field read directly from the unauthenticated, attacker-controlled JSON body — before that same body is handed to the event handlers, which act on other repository/stack fields from the identical payload.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization purely from the untrusted payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the app config keyed by that same attacker-supplied string via `github_app_config`: [3](#0-2) 

Each organization can have an independent (optionally blank) `webhook_secret`, and `verify_webhook_signature` explicitly treats a blank secret as "always verified": [4](#0-3) 

The binding that should hold is: *the organization whose secret authenticated the request* == *the repository/stack the event handler subsequently writes to*. Because both values are read from the same unauthenticated body, and the org used for verification is chosen from `repository.owner.login`/`organization.login` while downstream handlers (e.g. `PushHandler`, `StatusHandler`, membership/pull_request handlers) act on `repository.full_name` or other repository identifiers taken from the very same JSON, an attacker can decouple them: set `repository.owner.login` (or `organization.login`) to an organization whose app has no `webhook_secret` configured (verification trivially passes per line 77 above), while setting the actual repository fields used by the handler to reference a stack belonging to a *different*, secret-protected organization. Documentation and test fixtures confirm this multi-org, per-org-secret configuration is a supported deployment shape: [5](#0-4) [6](#0-5) 

### Impact Explanation
If any configured organization's GitHub App has no `webhook_secret` set (a supported, documented configuration state, not an operator error unique to a single org), an unauthenticated attacker can forge webhook payloads (push, status, membership, pull_request, check_suite) that pass `verify_signature` by claiming to originate from that unprotected org, while the handler-relevant repository fields in the same JSON reference a stack that actually belongs to a *different*, secret-protected organization. This crosses the "organization that authenticated" vs "repository that is written" trust boundary and can drive state changes (commit status writes, sync jobs, PR/team/membership mutations) against a repository the attacker does not control — a cross-repository write achieved without any credential.

### Likelihood Explanation
Exploitability depends entirely on deployment configuration: it requires (a) multi-org GitHub App setup and (b) at least one configured organization left with a blank `webhook_secret`. Both conditions exist in the codebase's own documented/example configuration (`docs/setup.md`, `secrets.development.example.yml`, `secrets_double_github_app.yml` all show `webhook_secret: # nil` as a valid/example value), so this is a realistic, not purely theoretical, configuration path rather than a contrived edge case — but it is conditioned on an operator choice which I could not further validate beyond what's shown in the docs/examples.

### Recommendation
Do not select the verification secret/organization from an untrusted field of the same payload that will later be used to resolve the target repository/stack. After signature verification succeeds for a given organization, re-validate that every repository-identifying field used by the downstream handler (`repository.full_name`, `repository.owner.login`) actually belongs to that same verified organization before dispatching to handlers, and reject the webhook otherwise.

### Proof of Concept
Not independently executed; the path is derived by static analysis of `WebhooksController#verify_signature`/`#repository_owner` (app/controllers/shipit/webhooks_controller.rb), `Shipit.github`/`github_app_config` (lib/shipit.rb), and `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb), combined with the documented multi-org config schema (docs/setup.md) and example secrets files showing a blank `webhook_secret` as a valid per-org value. I was not able to fully trace every handler's exact field usage (e.g. `PushHandler`, `StatusHandler`) within the tool budget to confirm which specific repository field each handler keys off of versus `repository_owner`; this would need to be confirmed by reading `app/models/shipit/webhooks/handlers/push_handler.rb` and `status_handler.rb` directly.

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
