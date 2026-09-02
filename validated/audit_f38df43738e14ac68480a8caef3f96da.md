## Analysis

This confirms Shipit's multi-tenant model: `Shipit.github(organization:)` looks up a **per-organization** config (including a distinct `webhook_secret`) via `github_app_config` [1](#0-0) , and the fixture `secrets_double_github_app.yml` demonstrates two independently configured orgs each with their own `webhook_secret`/app credentials [2](#0-1) . Each org onboarded onto a shared Shipit instance is a mutually-untrusted tenant boundary — an org admin for `OrgOne` is expected to only be able to affect `OrgOne`'s stacks.

### Title
Webhook signature verification authenticates the payload's `repository.owner.login`, but event handlers act on the independently-attacker-controlled `repository.full_name` — allowing a multi-tenant org admin to forge webhook events against other orgs' stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [3](#0-2) / [4](#0-3) . Once the HMAC check passes, `create` dispatches the *entire raw JSON body* to handlers [5](#0-4) , which resolve the target `Repository`/`Stack` from a **different** field: `payload.dig('repository', 'full_name')` [6](#0-5) , used the same way in `PullRequest::OpenedHandler#repository` and siblings [7](#0-6) .

### Finding Description
Shipit supports multiple independently configured GitHub organizations, each with its own `webhook_secret`, `app_id`, `installation_id` and `private_key` — this is the multi-tenant schema exercised by `secrets_double_github_app.yml` [2](#0-1)  and implemented by `Shipit.github_app_config` [8](#0-7) . An administrator of `OrgOne`'s GitHub App configuration legitimately knows `OrgOne`'s `webhook_secret` (they configured it), but has no privilege over `OrgTwo`'s repositories or stacks.

The binding the engine is supposed to enforce is:
```
organization whose secret authenticated the request == organization that owns the repository the handlers act on
```

In practice, the code breaks this equality:
1. `verify_signature` computes `repository_owner` from `repository.owner.login` (top-level JSON field) and fetches `Shipit.github(organization: repository_owner)` to obtain that org's `webhook_secret`, then HMACs the *raw body* against it [9](#0-8) .
2. Nothing enforces that `repository.owner.login` matches `repository.full_name`'s owner segment in the same payload — these are two independent JSON fields that GitHub normally keeps consistent, but the signature computation only depends on `repository.owner.login` selecting the key, not on cross-validating it against `full_name`.
3. Handlers ignore `repository.owner.login` entirely and instead resolve the acted-upon repository via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` [6](#0-5) , which splits `full_name` on `/` to find `owner`/`name` and loads the matching `Stack`s [10](#0-9) .

Because the attacker (an `OrgOne` admin) legitimately possesses `OrgOne`'s `webhook_secret`, they can compute a valid `X-Hub-Signature` HMAC over **any** raw body they construct, including one where `repository.owner.login = "OrgOne"` (so `verify_signature` looks up and validates against the key they know) while `repository.full_name = "OrgTwo/victim-repo"` (so the handler acts on a stack belonging to `OrgTwo`, an organization the attacker has no authority over). The push handler would then trigger `stack.sync_github(expected_head_sha: ...)` for `OrgTwo`'s stack [11](#0-10) , and `PullRequest::OpenedHandler`/`LabeledHandler`/`UnlabeledHandler` would create or archive/unarchive review stacks for `OrgTwo`'s repository based on forged pull-request payloads [12](#0-11) [13](#0-12) .

This is directly analogous to the reported bug class: a value that is protected/verified (the org whose secret signs the request) is not the same value the downstream action actually trusts (the repository/owner encoded in a different, unchecked field of the same signed-but-uncorrelated payload) — matching the "organization that authenticated versus the repository that is written" binding called out in scope.

### Impact Explanation
An admin of one tenant organization on a shared Shipit instance can forge GitHub webhook events (`push`, `pull_request`) that are accepted as authentic and cause Shipit to act on another organization's stacks/review-stacks — triggering unauthorized GitHub syncs, review-stack provisioning, and archive/unarchive actions cross-tenant. This crosses an authentication/tenant boundary (org A's credentials driving actions scoped to org B's repository), matching "cross-repository writes" under the Critical impact bucket, since it results from a legitimately-possessed but wrongly-scoped credential being used to write into another repository's Shipit state.

### Likelihood Explanation
Requires only that the Shipit deployment is configured for multiple GitHub organizations (documented, supported configuration per `TOP_LEVEL_GH_KEYS`/`github_app_config` and demonstrated by the `secrets_double_github_app.yml` fixture) and that the attacker administers one of the onboarded orgs (able to view/rotate its own `webhook_secret`). No access to the target org, no GitHub App private key, and no Shipit session/API token are required — only the ability to POST a hand-crafted, self-signed payload to the shared webhook endpoint.

### Recommendation
In `WebhooksController#verify_signature` / `create`, after signature verification, cross-check that the organization used to select the webhook secret (`repository_owner`) matches the owner segment of `repository.full_name` (and any `organization.login`) before dispatching to handlers, rejecting (422) on mismatch. Equivalently, have handlers derive the target repository/org from the already-authenticated `repository_owner` rather than independently trusting `full_name`.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgOne` and `OrgTwo`, each with distinct `webhook_secret`s (per `secrets_double_github_app.yml` schema).
2. As an administrator of `OrgOne`, obtain `OrgOne`'s configured `webhook_secret`.
3. Craft a JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/victim-repo"
  }
}
```
4. Compute `X-Hub-Signature: sha1=HMAC_SHA1(OrgOne_webhook_secret, raw_body)`.
5. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "OrgOne")` (matching `repository.owner.login`) and validates successfully against the attacker-known secret [3](#0-2) .
6. `PushHandler` resolves the target stacks via `payload.dig('repository','full_name')` = `"OrgTwo/victim-repo"` [6](#0-5) , and triggers `sync_github` on `OrgTwo`'s stack despite the request never being authenticated with `OrgTwo`'s credentials.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
