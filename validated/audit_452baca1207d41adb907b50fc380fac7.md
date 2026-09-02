## Title
Cross-repository webhook forgery via organization/repository binding mismatch in signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify a payload against based on `repository_owner`, a field taken directly from the unverified JSON body (`params.dig('repository', 'owner', 'login')`). The handlers that actually act on the payload, however, key off a *different* field — `payload.dig('repository', 'full_name')` — to resolve the target `Repository`/`Stack`. Because these two fields are never cross-checked, and Shipit supports multiple independent GitHub App configs each with its own `webhook_secret` [1](#0-0) , an attacker who legitimately controls one configured organization's webhook secret can forge a payload whose `repository.owner.login` matches their own org (so it passes signature verification) while `repository.full_name` names a stack belonging to a different, victim organization.

### Finding Description
The signature-verification binding is:

```
verified organization (from repository.owner.login) == organization whose secret signed the request
```

But the binding actually needed for safety is:

```
organization that authenticated (i.e., whose secret verified the signature) == organization of the repository the handler acts upon (repository.full_name)
```

`verify_signature` looks up the app/secret purely from the attacker-controlled `repository_owner` field: `Shipit.github(organization: repository_owner)` [2](#0-1) , computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) . Each organization can be configured with its own independent GitHub App/`webhook_secret` under `Shipit.github(organization:)` [4](#0-3) .

Once verification passes, the raw, attacker-supplied JSON is dispatched unchanged to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) . Handlers such as `PushHandler` resolve the target `Repository`/`Stack` solely from `payload.dig('repository', 'full_name')` via the shared `Handler#repository_name`/`#stacks` helpers [6](#0-5) , and then trigger `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack [7](#0-6) .

Nothing in the request pipeline enforces that `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository/stack) refer to the same organization. In a multi-org deployment, an attacker who is a legitimate member/admin of `OrgA` (and thus knows or can produce a validly-signed payload with `OrgA`'s webhook secret, exactly as GitHub itself would for real `OrgA` events) can set `repository.owner.login = "OrgA"` while setting `repository.full_name = "OrgB/victim-repo"`. The signature check passes because it is computed against `OrgA`'s secret matching the `owner.login` field, yet the handler acts on `OrgB`'s repository/stack, which the attacker was never authorized to send events for.

This mirrors the reported bug class: a field (`repository.full_name`, i.e. the "ref"/target the steps operate on) that is acted upon by downstream logic but not actually covered/bound by the verification that is supposed to guarantee authenticity of that field's provenance (the signature only authenticates that "some request signed by OrgA's secret arrived," not that the specific repository named in the body belongs to OrgA).

### Impact Explanation
This lets an attacker with legitimate control of one configured organization/repository (or just its webhook secret) forge `push`/`status`/`check_suite`/`pull_request` events that are processed against a completely different organization's stacks. Depending on the handler exploited, this can trigger `GithubSyncJob`/`sync_github` against a victim's stack, cause commit statuses to be manufactured for the victim's commits, or manipulate check-suite/PR-derived merge state — i.e., unauthorized cross-repository state manipulation that can influence deploys/merges on a repository the attacker does not control. This satisfies the "cross-repository writes / unauthorized deploy" impact class.

### Likelihood Explanation
Requires operating a multi-organization Shipit deployment (`config/secrets.yml` with multiple GitHub orgs, a documented and supported configuration) [1](#0-0)  and the attacker controlling at least one configured organization's webhook secret/app — a realistic scenario for shared Shipit instances serving several orgs/teams. No GitHub App private key, session, or `ApiClient` token is needed; only the ability to send an HTTP POST to `/webhooks` with a validly-HMAC-signed body using a secret the attacker legitimately possesses for their own org.

### Recommendation
After `verify_signature` succeeds, re-derive the organization that must own the acted-upon repository from `repository.full_name` (or `repository.owner.login` used consistently everywhere) and reject the event if it does not match the organization whose secret verified the signature. Alternatively, bind `repository_owner` and `repository.full_name`'s owner segment together with an explicit equality check before dispatching to handlers in `WebhooksController#create`.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`) [8](#0-7) .
2. Attacker is a legitimate holder of `OrgA`'s webhook secret (e.g., operates a repo under `OrgA` with webhooks configured).
3. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)`.
5. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully [9](#0-8) .
6. `PushHandler` resolves `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"` and calls `sync_github` on `OrgB`'s stacks [7](#0-6) , despite the signature only proving knowledge of `OrgA`'s secret.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
