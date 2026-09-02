### Title
Webhook Signature Verified Against an Attacker-Chosen Organization's Secret While the Same Payload Writes to a Different Organization's Repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments, `WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the incoming payload against, based on an unverified field taken directly from the JSON body — `repository.owner.login` (or `organization.login`). The rest of the pipeline (`create`, and the handlers dispatched via `Shipit::Webhooks.for_event`) then acts on the full, independently-attacker-controlled payload, including `repository.full_name`, which is not required to match the field used for authentication. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` picks the signing secret like this: [1](#0-0) 

and determines which organization's app/secret to use via: [2](#0-1) 

`Shipit.github(organization:)` resolves the app config purely from this attacker-supplied string when Shipit is configured with multiple GitHub organizations (`github_default_organization` non-nil): [3](#0-2) 

Each organization has its own `webhook_secret`, configured independently, e.g. as shown in the multi-org secrets example: [4](#0-3) 

Crucially, the value used to pick the verification secret (`repository.owner.login`) and the value later used by the actual event handlers to determine which `Stack`/`Repository` record to write to (`repository.full_name`, etc., consumed inside `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) are two independent, attacker-controlled JSON fields in the same unverified request body: [5](#0-4) 

Because HMAC verification only proves the request was signed by *some* configured organization's secret — not that the *target repository named inside the payload* belongs to that same organization — an attacker who is the legitimate administrator of one onboarded GitHub organization (and therefore legitimately knows that organization's `webhook_secret`, since GitHub App webhook secrets are set by whoever configures the App in each org) can forge a payload that:
- sets `repository.owner.login` / `organization.login` to *their own* org (so `verify_signature` selects their own known secret and the HMAC check passes), while
- setting `repository.full_name` (and other repository identifiers used by the downstream handler, e.g. push/status handlers that resolve `Stack` by repo name) to a **different organization's repository** tracked by the same Shipit instance.

The signature check therefore authenticates "the payload came from someone who knows OrgB's secret," but the handlers act on "write to OrgA's repository's stack," violating the intended equality between the authenticating organization and the repository being mutated.

### Impact Explanation
This lets an attacker who administers one onboarded GitHub organization on a shared Shipit instance forge webhook events (`push`, `status`, `check_suite`, etc.) that are recorded against a different organization's stack. This can inject fabricated commits/SHAs and fabricated CI statuses into another tenant's repository history inside Shipit, potentially satisfying `required_statuses`/CI checks that gate deploys, or triggering `GithubSyncJob`/continuous-delivery flows for a stack the attacker has no legitimate access to. This maps to "an unauthorized deploy, rollback, or merge" and "cross-repository writes" in the accepted High/Critical impact categories, since the org-authentication boundary and the repository-write boundary are supposed to be the same but are not enforced as such.

### Likelihood Explanation
Requires the deployment to use the multi-organization GitHub App configuration (documented, supported feature: `docs/setup.md`), and requires the attacker to be a legitimate administrator/owner of at least one of the organizations configured in the same shared Shipit instance — a realistic scenario for any multi-tenant Shipit deployment serving more than one GitHub organization. No GitHub App private key, no Shipit session, and no privileged Shipit account are needed — only knowledge of one's own org's webhook secret, which its own admin necessarily possesses.

### Recommendation
After verifying the HMAC, cross-check that the repository/organization actually targeted by the payload (`repository.full_name` / `repository.owner.login` used by the handler) belongs to the same GitHub organization whose secret was used to compute `verified`. Reject the webhook if the two do not match, rather than trusting the payload's self-reported `repository.owner.login` in isolation for secret selection while later trusting unrelated payload fields for the actual write target.

### Proof of Concept
1. Deploy Shipit configured with two GitHub organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `test/dummy/config/secrets_double_github_app.yml`), both tracked by the same Shipit instance.
2. Attacker is the admin of `OrgB` and therefore knows `OrgB`'s `webhook_secret` (they configured the GitHub App/webhook for their own org).
3. Attacker crafts a `push` (or `status`) webhook JSON body where:
   - `repository.owner.login` = `"OrgB"`
   - `repository.full_name` = `"OrgA/victim-repo"` (a stack tracked under OrgA)
   - other fields (`after`, commit SHAs, `state`, etc.) as desired.
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgB_webhook_secret, raw_body)` and POSTs to `/github_webhooks`.
5. `verify_signature` calls `Shipit.github(organization: 'OrgB')`, verifies successfully against `OrgB`'s secret.
6. `create` dispatches the event to registered handlers with the full `params` hash, which resolve the target `Stack`/`Repository` using `repository.full_name` = `"OrgA/victim-repo"`, causing Shipit to process the forged event as if it legitimately originated from `OrgA`.

Note: I was able to confirm the root cause precisely in `app/controllers/shipit/webhooks_controller.rb` and `lib/shipit.rb`. I could not locate/read the specific push/status handler source file(s) under the index (e.g., the exact handler class resolving `Stack` by `repository.full_name`) to cite the exact line performing that lookup — this may be excluded from the index; a full engine checkout (e.g., via a Devin session) would be needed to pinpoint that handler code precisely.

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
