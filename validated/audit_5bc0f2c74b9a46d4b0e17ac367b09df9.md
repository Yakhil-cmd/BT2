### Title
Signature verification is keyed by an unverified, attacker-controlled `repository.owner.login` field, allowing webhook forgery against any repository once any onboarded organization has no `webhook_secret` configured - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which HMAC secret) to verify the request against by reading `repository_owner` straight out of the still-unverified request body, before the signature has been checked. Combined with `GitHubApp#verify_webhook_signature`, which trivially returns `true` when the selected organization has no `webhook_secret` configured, an attacker can pick any onboarded organization that lacks a webhook secret, craft a payload whose top-level `repository.owner.login`/`organization.login` says that org (satisfying signature "verification"), while the rest of the payload (the actual `repository` object used by event handlers to resolve the `Stack`) refers to a victim repository. The binding broken is: the organization that authenticated the request vs. the repository that the event handlers actually act on.

### Finding Description
`verify_signature` computes the app/secret to check against using data taken directly from the raw, unauthenticated JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or the `organization` sub-object) - both are fields inside the very payload whose authenticity is what's being decided, i.e. fully attacker-controlled prior to any cryptographic check.

`Shipit.github(organization: repository_owner)` then resolves per-organization configuration: [3](#0-2) 

And `verify_webhook_signature` unconditionally passes when that organization has no `webhook_secret` configured: [4](#0-3) 

Multi-organization installs are an explicitly documented and supported configuration, where each org has its own independent `webhook_secret` (which is optional per the docs and the sample config), and a Shipit install commonly has many organizations, not all of them equally hardened: [5](#0-4) [6](#0-5) 

`Shipit::Webhooks.for_event(event)` handlers (e.g. push, status, pull_request) then process the full `params` hash independently, resolving the actual `Repository`/`Stack` from the payload's real repository data - there is no re-check tying the org used for signature verification to the repository object the handler subsequently acts on. Because `repository_owner` used for signing/verification and the repository data used for dispatch both come from the same untrusted body, an attacker who controls the whole payload can make them diverge: set `repository.owner.login`/`organization.login` to any org configured with no `webhook_secret` (satisfying the signature gate), while setting the actual `repository` object read by the event handler to point at a different, victim repository/stack.

### Impact Explanation
This lets an unauthenticated attacker forge GitHub webhook events (`push`, `status`, `pull_request`, `check_suite`, `membership`, etc.) against any stack/repository tracked by the Shipit instance, as long as the instance has at least one onboarded organization without a configured `webhook_secret` (an explicitly supported, undocumented-as-dangerous configuration). Depending on which handler is targeted, this can trigger unauthorized `GithubSyncJob` runs, fake commit statuses that unblock deploys, forged `pull_request`/`membership` events that create teams/users, or otherwise manipulate stack state that legitimate deploy/merge decisions rely on - i.e., an unauthorized effect on deploy/merge-relevant state without possessing any of the org's real webhook secrets.

### Likelihood Explanation
Requires the deployment to run with multiple GitHub organizations (a documented, supported feature) where at least one organization's `webhook_secret` is left blank - which the sample/test configs themselves show as a valid state (`webhook_secret: # nil`). No credentials, tokens, or repository access are required; only knowledge that such an org exists (e.g. via reconnaissance of the multi-org Shipit instance) and the ability to send a crafted HTTP POST to the public `/github/webhooks` endpoint.

### Recommendation
Do not trust unverified payload fields to select the verification secret. Either: (1) require every configured organization in a multi-org install to have a non-blank `webhook_secret`, and reject requests for any org lacking one instead of treating it as "no verification needed"; and (2) after signature verification succeeds, re-validate that the organization/owner used to select the secret actually matches the owner of the repository object that the dispatched handler subsequently acts on, rejecting the request if they differ.

### Proof of Concept
1. Configure Shipit with two organizations: `victim-org` (has a real `webhook_secret`) and `attacker-org` (onboarded but `webhook_secret` left blank, as shown supported in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: push` and a body where:
   - `repository.owner.login` = `"attacker-org"` (used only by `verify_signature`)
   - the rest of the payload's `repository`/`ref`/`after` fields point at a real stack under `victim-org/some-repo`.
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` immediately regardless of the (missing/garbage) `X-Hub-Signature` header.
4. The request proceeds to `Shipit::Webhooks.for_event('push')`, whose handler resolves the `victim-org` stack from the same payload and enqueues `GithubSyncJob`/updates commit state, despite the attacker never possessing `victim-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
