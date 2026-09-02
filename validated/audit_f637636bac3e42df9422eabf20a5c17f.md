### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController` selects which `GitHubApp` (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but the event handlers that actually mutate state (`PushHandler`, `PullRequest::*Handler`, etc.) resolve the target `Repository`/`Stack` from a completely different field in the same JSON body: `repository.full_name`. Because Shipit explicitly supports multiple GitHub Apps/organizations each with its own `webhook_secret`, an attacker who administers one onboarded organization (and therefore knows that organization's `webhook_secret`) can sign a payload with their own secret while pointing `repository.full_name` at a stack belonging to a *different* organization, causing Shipit to act on a repository/stack the attacker does not control.

### Finding Description
`verify_signature` derives the signing identity purely from the payload itself, before any cryptographic check occurs: [1](#0-0) [2](#0-1) 

It fetches the `GitHubApp` for that claimed organization and verifies the raw body's HMAC against *that org's* configured `webhook_secret`: [3](#0-2) [4](#0-3) 

Shipit explicitly supports and documents running multiple independent GitHub Apps/organizations, each with its own distinct `webhook_secret`: [5](#0-4) [6](#0-5) 

Once the signature check passes, `create` dispatches the *entire raw payload* to handlers, without re-checking that the resolved repository/stack belongs to the same organization that was used for signature verification: [7](#0-6) 

Handlers resolve the target `Repository`/`Stack` from `repository.full_name`, a sibling field of `repository.owner.login` inside the same attacker-controlled JSON body: [8](#0-7) [9](#0-8) 

Because `repository.owner.login` (used for secret selection) and `repository.full_name` (used to pick which stack is mutated) are independent, unrelated JSON keys, nothing forces them to be consistent. In a genuine GitHub-originated webhook they always match, but an attacker forging the payload is free to set them independently as long as the whole raw body is HMAC-signed with a secret they know.

**Breaks the binding:** organization authenticated (`repository.owner.login` used to pick the `webhook_secret`) ≠ repository that is written (`repository.full_name` used by `PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabelCapturingHandler`, etc. to resolve `Repository`/`Stack`).

### Impact Explanation
An attacker who is an administrator of any single GitHub organization onboarded to a multi-org Shipit instance (and therefore knows/controls that org's `webhook_secret`, which they set themselves when installing their GitHub App) can:
- Sign an arbitrary JSON body with their own org's `webhook_secret`, set `repository.owner.login` to their own org (to pass `verify_signature`), and set `repository.full_name` to `victim-org/victim-repo`.
- Trigger `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the target branch of the victim's repository — [10](#0-9) , or
- Trigger PR lifecycle handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabelCapturingHandler`) to create/archive/unarchive review stacks or mutate PR/label state for a repository the attacker does not own — [11](#0-10) [12](#0-11) 

This is a cross-repository write / unauthorized deploy trigger crossing an organization trust boundary that the multi-app configuration is explicitly designed to enforce.

### Likelihood Explanation
Exploitation requires the attacker to control (be an admin of) at least one GitHub organization that is legitimately configured in Shipit's multi-org `github` secrets block — a realistic scenario for any Shipit instance serving multiple tenants/organizations, which is the exact use case the "Using Multiple Github Applications" feature is built for. No access to the victim organization, no Shipit session, and no knowledge of the victim's secret is required.

### Recommendation
After resolving the target `Repository`/`Stack` from the payload, verify that the repository's owner/organization matches the organization whose `webhook_secret` was used to verify the signature, rejecting the request otherwise. Alternatively, derive the signing organization strictly from the resolved `Repository` record (looked up first, unauthenticated, purely for secret selection) and require `repository.owner.login`/`organization.login` to equal that same organization before verifying the signature.

### Proof of Concept
Conceptual request (attacker controls `attacker-org`, Shipit also hosts `victim-org/victim-repo`):
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC of raw body using attacker-org's webhook_secret>

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
`verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches that org's `GitHubApp`, and successfully verifies the signature using the attacker's own known secret. `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github` on its stacks, acting on the victim's repository despite the request only being authenticated for `attacker-org`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
