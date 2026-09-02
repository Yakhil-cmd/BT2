## Title
`repository.owner.login` / `repository.full_name` split allows a no-secret-org webhook to provision a fork-controlled review stack on an unrelated repository - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

## Summary
`WebhooksController#verify_signature` selects the GitHub App/org used to verify the HMAC solely from `repository.owner.login` (via `repository_owner`), while every `pull_request` handler resolves the target `Repository`/`Stack` solely from `repository.full_name` [1](#0-0) [2](#0-1) [3](#0-2) . These two fields are never checked for consistency, and if the org named by `owner.login` has no `webhook_secret` configured, `verify_webhook_signature` returns `true` unconditionally [4](#0-3) , letting an attacker forge a `pull_request` event that mutates a completely different (secret-protected) org's repository/stack.

## Finding Description
The broken binding is:

`organization_that_verifies_signature (params.repository.owner.login) == organization_that_owns_the_mutated_repository (params.repository.full_name.split('/').first)`

This equality is never enforced. In `verify_signature`, the controller does:
```ruby
github_app = Shipit.github(organization: repository_owner)   # repository_owner == params.dig('repository','owner','login')
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [5](#0-4) 

`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved app config has no `webhook_secret`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

Meanwhile, every `pull_request` handler (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`) resolves the affected repository purely from `params.repository.full_name`:
```ruby
def repository
  @repository ||=
    Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
    Shipit::NullRepository.new
end
``` [3](#0-2) 

`Repository.from_github_repo_name` simply splits `owner/name` out of `full_name` and does a DB lookup — no relationship whatsoever to `repository.owner.login` [6](#0-5) . None of the handler `params` schemas (`requires :repository do requires :full_name, String end`) even declare `owner.login`, so ExplicitParameters cannot cross-validate it [7](#0-6) .

**Attacker's exact request:** the attacker owns (or has push access to) some GitHub org `attacker-org` that is either (a) not configured in Shipit's `github` secrets at all (any org name not present triggers `Shipit::GithubOrganizationUnknown`, which is rejected with 422 — so this path is NOT usable) or (b) configured in Shipit's `github` secrets but with `webhook_secret` left blank (a documented, supported configuration shown in `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, and `test/dummy/config/secrets_double_github_app.yml`, all of which show `webhook_secret: # nil` as a normal setup option) [8](#0-7) [9](#0-8) . The attacker crafts a `pull_request` "opened" webhook body with:
- `repository.owner.login = "attacker-org"` (the no-secret org — used only to pick the verifier)
- `repository.full_name = "victim-org/victim-repo"` (an unrelated, secret-protected org's repository that has review stacks enabled)
- `pull_request.head.ref` pointing to an attacker-controlled fork/branch
- any `X-Hub-Signature` header value (ignored because `verify_webhook_signature` short-circuits to `true`)

`verify_signature` calls `Shipit.github(organization: "attacker-org")`, gets the no-secret app config, `verify_webhook_signature` returns `true` regardless of the header, and the request proceeds. `Shipit::Webhooks.for_event('pull_request')` then runs `OpenedHandler#process`, which builds `repository` from `full_name` = `victim-org/victim-repo`, and — if that repository has `review_stacks_enabled` and a matching provisioning behavior — calls `ReviewStackAdapter#find_or_create!`, provisioning a new `ReviewStack` for `victim-org/victim-repo` off the attacker-supplied branch/fork [10](#0-9) [11](#0-10) .

Existing guards fail to stop this: `drop_unhandled_event` only checks the event type exists, not payload content [12](#0-11) ; the ExplicitParameters schemas never require or compare `owner.login`; `Repository` model validations only constrain owner/name character format, not cross-consistency with the verifying org; and `force_github_authentication`/`User#authorized?`/`stacks` scope are session-based guards that don't apply to the unauthenticated `/webhooks` endpoint at all.

## Impact Explanation
A payload attributed to org A (no secret) is accepted and used to mutate/provision state for org B (a different, secret-protected org/repository) — this matches the "payload for one repository mutating another's stack" Critical impact category. Concretely, the attacker can force-provision (`OpenedHandler`), unarchive (`ReopenedHandler`/`UnlabeledHandler`), or archive (`ClosedHandler`/`LabeledHandler`) a `ReviewStack` on the victim repository, and the created review stack's `branch` comes directly from the attacker-controlled `pull_request.head.ref` [13](#0-12) . Since review stacks are provisioned/deployed by Shipit's normal deploy machinery, this gives the attacker a foothold to get fork-controlled code into a deploy/CI pipeline for a repository they do not own, which is the described path toward RCE on the deploy host. This is repeatable against any repository configured with review stacks enabled, as long as at least one org in Shipit's multi-org config has no `webhook_secret` set.

## Likelihood Explanation
This requires: (1) Shipit configured with multiple GitHub orgs (the documented "Using Multiple GitHub Applications" setup) [14](#0-13) , (2) at least one configured org lacking a `webhook_secret` (a state the example secrets templates explicitly show as valid/default), and (3) a target repository under a different (properly secured) org with `review_stacks_enabled` and a provisioning behavior that reacts to `opened`/`labeled`/etc. The attacker needs no Shipit credentials, no GitHub App/webhook secret, and no privileged GitHub role — only knowledge that some org name in the deployment is unsecured, which could be guessed or discovered via error responses (`GithubOrganizationUnknown` vs. successful 200/204) that leak which org names exist in config. The attack is a single unauthenticated HTTP POST, fully repeatable.

## Recommendation
Verify the webhook using the organization actually derived from `repository.full_name` (or require `repository.owner.login == full_name.split('/').first` and reject mismatches before calling `Shipit.github`), so the signature check and the mutation target are always the same tenant. Additionally, treat a missing `webhook_secret` as a misconfiguration to warn/fail loudly on rather than silently trusting all incoming events for that org.

## Proof of Concept
minitest plan (extends `test/controllers/webhooks_controller_test.rb`):
1. Configure two orgs via `Shipit.stubs(:secrets)` similar to `test/dummy/config/secrets_double_github_app.yml`: `attacker-org` with `webhook_secret: nil`, `victim-org` with a real `webhook_secret`.
2. Create `Shipit::Repository` with `owner: 'victim-org', name: 'victim-repo'`, `review_stacks_enabled: true`, `provisioning_behavior: 'allow_all'`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature`, and JSON body: `{"action":"opened","number":1,"pull_request":{...,"head":{"ref":"attacker-branch"}},"repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`.
4. Assert response is `200 OK` (not `422`), establishing `params.repository.owner.login ("attacker-org") != params.repository.full_name.split('/').first ("victim-org")` yet the request was accepted.
5. Assert `Shipit::ReviewStack.find_by(environment: 'pr1')` now exists under the `victim-org/victim-repo` repository with `branch: 'attacker-branch'`, proving state was mutated for `victim-org` despite only `attacker-org`'s (non-)secret verifying the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** config/secrets.development.example.yml (L18-34)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
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
