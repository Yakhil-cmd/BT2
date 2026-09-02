### Title
Webhook signature is verified against the organization named in `repository.owner.login`, while all event handlers act on the unrelated `repository.full_name` field, allowing cross-organization event forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the unverified JSON body. Every event `Handler` then resolves the actual repository/stack to mutate using a *different* field from the same unverified body: `repository.full_name`. Because GitHub's HMAC only proves "this body was signed with *some* configured organization's secret," not "this body's `repository.owner.login` matches its `repository.full_name`," an admin of one configured organization (who legitimately knows their own `webhook_secret`) can sign a payload whose `owner.login` is their own org but whose `full_name` points at a repository belonging to a different organization on the same Shipit instance.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-controllable JSON before the signature check has any bearing on which secret is used: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (including `webhook_secret`) from `secrets.github`, keyed by the `organization` string passed in — which is exactly `repository_owner` from the payload: [3](#0-2) 

Meanwhile, every webhook `Handler` resolves the target repository/stacks using a completely separate field, `repository.full_name`, from the same JSON body: [4](#0-3) 

and `Repository.from_github_repo_name` splits that string on `/` to find the target `Repository` record without any check that its `owner` matches the `repository.owner.login` used for signature verification: [5](#0-4) 

This same pattern (checking one field, acting on a different field from the same unverified payload) repeats across handlers, e.g. `pull_request/edited_handler.rb` resolves its target repository via `params.repository.full_name` independently of any owner/organization binding: [6](#0-5) 

The binding broken is: `{organization whose webhook_secret authenticated the request} != {repository actually written to by the handler}`. In the single-org configuration this is not exploitable since there's only one secret and effectively one owner. But `lib/shipit.rb`'s `github_app_config`/`TOP_LEVEL_GH_KEYS` mechanism, exercised in `test/dummy/config/secrets_double_github_app.yml`, explicitly supports hosting multiple independent GitHub organizations (each with its own `webhook_secret`) on one Shipit instance: [7](#0-6) 

### Impact Explanation
An org admin of `OrgOne` (who legitimately possesses `OrgOne`'s `webhook_secret` because they configured their own GitHub App) can POST to `/webhooks` a body with `repository.owner.login = "OrgOne"` (so `verify_signature` picks and validates against `OrgOne`'s secret) but `repository.full_name = "OrgTwo/victim-repo"`. Handlers such as the `push` handler (enqueues `GithubSyncJob` for the matched stack), the `status` handler (creates commit statuses), `check_suite` handler, `pull_request` handlers (updates/merges PR state), etc., all resolve their target via `repository.full_name`, so they act on `OrgTwo`'s repositories/stacks despite the request only being authenticated as `OrgOne`. This is a cross-organization write into data the attacker has no legitimate access to, matching the "cross-repository writes" high-impact criterion.

### Likelihood Explanation
Exploitability requires a Shipit deployment configured with multiple GitHub organizations (the multi-tenant schema shown in `test/dummy/config/secrets_double_github_app.yml`) where the attacker is a legitimate admin/owner of one tenant organization but not another hosted on the same instance. This is a realistic Shipit-as-a-service or shared-instance scenario, and the attacker needs no privileged Shipit account or token — only knowledge of the `webhook_secret` for their own configured org, which they set themselves. No UI/session compromise is required, only a forged HTTP POST to the public `/webhooks` endpoint.

### Recommendation
After computing `repository_owner` and selecting the GitHub app/secret for signature verification, re-derive the acted-upon repository from the *same* verified owner rather than trusting a separately-parsed `full_name` field; alternatively, after successful signature verification, assert that `repository.full_name.split('/').first` (or `organization.login`) equals the `repository_owner` used to select the signing secret, and reject (422) on mismatch before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with two configured GitHub organizations, `OrgOne` (secret `S1`) and `OrgTwo` (secret `S2`), as in `test/dummy/config/secrets_double_github_app.yml`.
2. As an admin of `OrgOne`, craft a `push` webhook body:
```json
{
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" },
  "after": "<sha>"
}
```
3. Sign it with `S1` (known to the attacker) and send `X-Hub-Signature: sha1=<hmac with S1>` to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgOne")`, validates the signature successfully against `S1`. [1](#0-0) 
5. The push handler (via `Handler#repository_name`/`#stacks`) resolves `Repository.from_github_repo_name("OrgTwo/victim-repo")` and enqueues a `GithubSyncJob` against `OrgTwo`'s stack, despite the request never being authenticated with `OrgTwo`'s secret. [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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
