### Title
Webhook signature verification selects the GitHub App/secret from `repository.owner.login`, while event handlers act on the independent `repository.full_name` field, letting a webhook signed for one (attacker-controlled) organization forge state on a victim's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GithubApp` (and therefore which HMAC secret) to validate the request against using `repository_owner`, computed only from `params.dig('repository','owner','login')` (falling back to `organization.login`). [1](#0-0) [2](#0-1) . The event handlers that actually mutate state, however, resolve the target `Stack`/`Repository` from a completely separate JSON field, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name` / `#stacks`. [3](#0-2) 

Because `repository.owner.login` and `repository.full_name` are two independent leaves of the same JSON body, and Shipit supports per-organization GitHub Apps each with its own (optional) `webhook_secret` [4](#0-3) [5](#0-4) , an attacker who legitimately controls (or has installed) a GitHub App for *their own* organization — where they either know the `webhook_secret` or have configured none (`verify_webhook_signature` returns `true` unconditionally when no secret is set) [6](#0-5)  — can send a signed/accepted webhook whose `repository.owner.login` matches their own org (so it passes signature verification) while `repository.full_name` names a victim organization's repository/stack.

### Finding Description
The equality this design relies on but never enforces is:
`organization authenticated (repository.owner.login used by verify_signature) == repository written (repository.full_name used by Handler#stacks)`

- `verify_signature` derives the app/secret purely from `repository.owner.login` / `organization.login`: [7](#0-6) 
- All default handlers (`PushHandler`, `StatusHandler` via `Commit.where(sha:)`, pull-request handlers, `MembershipHandler`, etc.) resolve the target repository/stack from `repository.full_name`, not from the field that was used to select the verifying secret: [3](#0-2) [8](#0-7) [9](#0-8) 
- The signature check only proves the whole raw body was signed by *some* configured org's secret; it never checks that the `owner.login` used to pick the secret matches `full_name`'s owner, nor that the signing org actually owns the repository named in `full_name`.

Since HMAC signs the entire raw body, an attacker cannot alter fields after obtaining a valid signature from GitHub itself — but the attacker does not need GitHub to sign anything: they can hand-craft the JSON body themselves and self-sign it with a secret for any organization for which they have push access / App-installation control (their own org), or exploit an org configured with no `webhook_secret` at all. That crafted body simply needs `repository.owner.login` = their own/no-secret org and `repository.full_name` = the victim's `owner/repo`.

### Impact Explanation
This breaks the credential/repository binding required by the engine: an organization identity that "authenticated" (whose secret validated the payload) is not the organization actually written to. Concretely:
- `StatusHandler#process` looks up `Commit.where(sha: params.sha)` across all stacks and calls `commit.create_status_from_github!`, letting the attacker forge a `success` CI status on a victim commit regardless of which org "signed" the webhook. [10](#0-9)  Because `Commit#deployable?` depends on `success?` and required statuses [11](#0-10) , and `Status#schedule_continuous_delivery` fires automatically on status transitions [12](#0-11) , forging a success status can unlock/trigger an **unauthorized deploy** on the victim's stack via continuous delivery, without any Shipit session or `ApiClient` token.
- `PushHandler#process` resolves stacks purely from `repository.full_name` and triggers `stack.sync_github(expected_head_sha:)`, letting the attacker force a resync against an attacker-chosen `after` SHA on a victim stack. [13](#0-12) 

### Likelihood Explanation
Likelihood is limited by the precondition that at least one configured GitHub organization either has no `webhook_secret` set (explicitly documented as "optional") [14](#0-13)  or the attacker otherwise knows a valid secret for an org they control while multiple orgs are configured (documented multi-org feature) [15](#0-14) . This is a realistic deployment configuration explicitly supported and documented by the engine, not a hypothetical misuse, so this is assessed as a genuine unprivileged-attacker path once that (supported) configuration exists.

### Recommendation
In `WebhooksController#verify_signature`, after determining the repository/stack to act on inside each handler, cross-validate that the resolved `Repository#owner` matches the organization whose secret validated the signature (i.e., pass the verified `repository_owner` into `Handler.call` and have `Handler#stacks` reject any repository whose owner does not match it), rather than trusting `repository.full_name` independently of the field used to select the verifying GitHub App/secret.

### Proof of Concept
Given a Shipit instance configured with two GitHub orgs, `attacker-org` (no `webhook_secret` configured, or a secret known to the attacker) and `victim-org` (owns stack `victim-org/prod-repo`):

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<any value, or omitted>

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-repo"
  }
}
```

`verify_signature` selects `Shipit.github(organization: "attacker-org")`; since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally [6](#0-5) . The request is then dispatched to `StatusHandler`, which finds the commit by `sha` (owned by `victim-org/prod-repo`) irrespective of `repository.owner.login`, and creates a forged success status on it [10](#0-9) , potentially marking the commit deployable and triggering continuous delivery on the victim stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
