## Title
Webhook organization used to select the verifying secret can be decoupled from the organization/repository actually acted upon, allowing cross-tenant webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

## Summary
`WebhooksController#verify_signature` picks which GitHub App/organization `webhook_secret` to verify the HMAC signature against by reading `repository_owner` from Rails' merged `params` object, while the actual event processing in `create` re-parses the raw body independently and acts on whatever `repository.full_name` (org/repo) is embedded in that raw JSON. Because Rails' `params` merges query-string parameters over JSON body parameters for identical top-level keys, an attacker can make the "organization whose secret authenticates the signature" diverge from the "organization/repository whose Stack is actually written to," breaking the binding the report's SafeERC20 pattern is about (an unchecked/assumed field is trusted for a privileged effect).

## Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and uses it to select the app config/secret to verify against:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 

`params` here is `ActionController::Parameters`, which Rails builds by merging query-string parameters over the parsed JSON body for identical top-level keys (`request_parameters.merge(query_parameters)`), so `?organization[login]=X` or `?repository[owner][login]=X` in the request URL overrides what is actually present, and covered by the HMAC, in the raw body.

Meanwhile, the `create` action re-parses the untouched raw body directly and dispatches it to handlers unconditionally:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers resolve the target `Stack`/`Repository` purely from that raw JSON, independent of whichever organization was used to select the verifying secret:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

Multiple, independently-secreted organizations are a first-class supported configuration (`Shipit.github(organization:)` / `github_app_config`), each with its own `webhook_secret`, `app_id`, `installation_id`, exactly as shown in the multi-tenant test fixture: [5](#0-4) [6](#0-5) 

So the equality the engine relies on — "organization whose `webhook_secret` authenticated this HMAC" == "organization/repository whose `Stack` is written by this payload" — is not enforced anywhere; the two are computed from parameters that can be made to diverge via the query string.

## Impact Explanation
An attacker who legitimately administers one onboarded organization (`AttackerOrg`, with its own known `webhook_secret`, since GitHub Apps' webhook secret is chosen by whoever registers the App) can:
1. Craft an arbitrary raw JSON body whose `repository.full_name` (and other fields) reference a **different, victim** organization/repository (`VictimOrg/victim-repo`).
2. Compute a valid `X-Hub-Signature` over that raw body using `AttackerOrg`'s own known `webhook_secret`.
3. POST to the public `/webhooks` endpoint with `?organization[login]=AttackerOrg` (or `?repository[owner][login]=AttackerOrg`) in the query string.
4. `verify_signature` resolves `repository_owner` to `AttackerOrg` from the query-overridden `params`, fetches `AttackerOrg`'s secret, and successfully verifies the attacker-computed signature.
5. `create` re-parses the raw body and dispatches the forged `VictimOrg/victim-repo` event (e.g. `push`, `status`, `check_suite`, `membership`) to the real handlers, which act on `VictimOrg`'s `Stack`/`Repository`/`Team` records as if GitHub itself had sent it.

This lets an unprivileged attacker forge trusted GitHub events for a victim org they have no access to — e.g. spoofing a `push` to trigger `GithubSyncJob` with attacker-chosen `after` SHA, spoofing a passing `status`/`check_suite` to satisfy deploy/merge gating checks, or spoofing `membership`/`team` events feeding `Shipit.github_teams` authorization — resulting in unauthorized deploy/merge or authorization escalation.

## Likelihood Explanation
Requires only that the attacker controls one legitimately onboarded organization on the same Shipit instance (a normal, unprivileged-relative-to-the-victim tenant), plus knowledge of the well-documented Rails query-string-over-JSON-body parameter merge behavior. No access to the victim's secrets, tokens, or accounts is needed.

## Recommendation
- Verify the webhook signature and determine `repository_owner` from the same, single source of truth: parse `request.raw_post` once and use that parsed hash (never `ActionController::Parameters`) for both signature-org selection and event dispatch.
- After verifying the signature, assert that the repository/organization referenced in the payload used for signature-org lookup matches the repository/organization actually processed by handlers, rejecting on mismatch.

## Proof of Concept
```
POST /webhooks?organization[login]=AttackerOrg HTTP/1.1
Host: shipit.example.com
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(AttackerOrg_webhook_secret, raw_body)>
Content-Type: application/json

{
  "repository": { "full_name": "VictimOrg/victim-repo", "owner": { "login": "VictimOrg" } },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/master"
}
```
- `repository_owner` resolves to `AttackerOrg` (query override wins), so `verify_webhook_signature` succeeds using `AttackerOrg`'s secret. [2](#0-1) 
- `create` then parses the same raw body directly and dispatches the `push` event for `VictimOrg/victim-repo` to `Shipit::Webhooks.for_event('push')` handlers. [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
        def repository_name
          payload.dig('repository', 'full_name')
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
