## Title
Webhook signature verified against `repository.owner.login`/`organization.login` while all handlers act on the unrelated, unbound `repository.full_name` field, enabling cross-tenant webhook forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Just like the Real Wagmi `Multipool` contract used the easily-manipulable `slot0` price to compute LP amounts instead of a value actually bound to the trade being priced, Shipit's webhook pipeline authenticates a request using one payload field (`repository.owner.login` / `organization.login`) but then executes state-changing logic using a *different*, independently attacker-suppliable field (`repository.full_name`). Neither GitHub's HMAC signature nor Shipit's own code enforces that these two fields are consistent, so a valid signature for organization A says nothing about which repository/stack is actually acted upon.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to check the HMAC against purely from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). `Shipit.github(organization:)` uses that value to look up per-organization secrets from the multi-tenant config schema: [3](#0-2) 

This multi-organization configuration is a documented, supported deployment mode (one Shipit instance hosting several GitHub orgs, each with its own `webhook_secret`): [4](#0-3) 

Once the signature check passes, `WebhooksController#create` hands the *entire* raw payload to every registered handler: [5](#0-4) 

All handlers, however, determine *which* `Stack`/`Repository` to mutate using a completely different, unauthenticated field: `repository.full_name`: [6](#0-5) 

For example `PushHandler` (triggers `sync_github` on matching stacks) and the pull-request handlers (`archive!`, `unarchive!`, label capture, provisioning) all resolve their target purely from `params.repository.full_name`: [7](#0-6) [8](#0-7) 

**The equality that should hold, but doesn't:** `organization that authenticated the request` == `owner of the repository that gets written to`. Before the request: the signature only proves the payload was HMAC-signed with *organization A's* secret. After processing: the handler mutates whatever repository is named in `repository.full_name`, which can be set to organization B's repo — a tenant the signing secret has no relationship to. Nothing in `verify_signature` or in `Handler#repository_name` cross-checks that `repository.owner.login` equals the owner half of `repository.full_name`.

### Impact Explanation
In a multi-org Shipit deployment, any party who legitimately possesses (or has extracted) one tenant organization's `webhook_secret` can forge a webhook payload whose `repository.full_name` names a stack belonging to a *different* onboarded organization, causing Shipit to: trigger `sync_github`/deploy-eligibility updates on that foreign stack, archive/unarchive its review stacks, mutate its pull-request/label state, etc. This is a cross-repository/cross-tenant write performed with a credential that was never meant to authorize actions on that repository — matching the report's "Critical: cross-repository writes" bar.

### Likelihood Explanation
Requires only knowledge of one organization's `webhook_secret` (something that org's own GitHub App admins have) plus the ability to POST directly to the public `/webhooks` endpoint with a crafted JSON body — no `ApiClient` token, `GITHUB_TOKEN`, session, or repository write access to the *target* org is required. The only variable dependency is that the instance be configured with the documented multi-organization schema.

### Recommendation
When verifying the signature, also verify that the organization whose secret validated the signature actually owns the repository the payload claims to describe (i.e., compare the resolved GitHub App's organization against the owner segment of `repository.full_name`, not just `repository.owner.login`/`organization.login`), and reject the webhook if they diverge.

### Proof of Concept
1. Configure Shipit with the documented multi-org schema (`OrgOne`, `OrgTwo`, each with distinct `webhook_secret`), as shown in `test/dummy/config/secrets_double_github_app.yml`.
2. As someone who knows `OrgOne`'s `webhook_secret` (e.g., an `OrgOne` GitHub App admin), craft a `push` payload: `{"repository": {"owner": {"login": "OrgOne"}, "full_name": "OrgTwo/target-repo"}, "ref": "refs/heads/main", "after": "<sha>"}`.
3. Compute `X-Hub-Signature` as `sha1=` + HMAC-SHA1(`OrgOne`'s webhook_secret, raw_body).
4. POST to `/github/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "OrgOne")` and the signature checks out.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgTwo/target-repo")` and calls `sync_github` on `OrgTwo`'s stack — a repository the caller's `OrgOne` secret was never meant to authorize.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
