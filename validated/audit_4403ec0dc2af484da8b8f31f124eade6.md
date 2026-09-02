This confirms the multi-tenant configuration explicitly documented and supported: multiple GitHub organizations can each be configured with their own `webhook_secret` under `github.<org>.webhook_secret`, as documented in `docs/setup.md` and implemented in `Shipit.github_app_config`/`Shipit.github`.### Title
Webhook signature verification is bound to the payload's `repository.owner.login`/`organization.login` field, but every event handler acts on the independent, unverified `repository.full_name` field — allowing a legitimate multi-tenant GitHub organization to forge webhook events for repositories/stacks belonging to a different organization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit supports hosting stacks for multiple, independent GitHub organizations from a single instance, each with its own `webhook_secret` (`config/secrets.development.shopify.yml`, `docs/setup.md:182-209`). `WebhooksController#verify_signature` selects *which* organization's secret to HMAC-verify against by reading `repository.owner.login` (or `organization.login`) straight out of the same untrusted JSON body it is about to verify. [1](#0-0) [2](#0-1) 

Once the signature passes, the actual event handlers never re-check that field — they independently resolve the target repository/stack from a *different* field of the same payload, `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`: [3](#0-2) 

Nothing binds `repository.owner.login` (used for the signature check) to `repository.full_name` (used for every write). Because Shipit's own documentation and `Shipit.github`/`Shipit.github_app_config` explicitly support onboarding unrelated organizations onto one shared instance, an attacker who legitimately administers *one* onboarded organization (and therefore knows/controls that organization's `webhook_secret`, e.g. by re-configuring the webhook delivery URL/secret on their own GitHub App/organization settings) can sign an arbitrary payload with their own secret while setting `repository.owner.login` to their own org (so `verify_signature` passes) and `repository.full_name` to a **different, victim organization's repository** that is also hosted on the same Shipit instance.

### Finding Description
This is the same class of bug as the reported TOCTOU: a security-relevant decision is made once, on one piece of untrusted state, and then a *different* piece of the same (attacker-influenced) untrusted state is used for the sensitive operation, without re-validating that the two agree.

- Time of Check: `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`, and verifies `X-Hub-Signature` against that organization's `webhook_secret`. [4](#0-3) 

- Time of Use: every registered handler (`PushHandler`, `StatusHandler`, `PullRequest::*Handler`, `CheckSuiteHandler`) resolves the repository/stack to act on using `Handler#repository_name` = `payload.dig('repository','full_name')`, then does `Repository.from_github_repo_name(repository_name).stacks`. [3](#0-2) [5](#0-4) [6](#0-5) 

Because Shipit is explicitly designed to host multiple unrelated GitHub organizations side-by-side, each configured with its own independent `webhook_secret` under `github.<org>.webhook_secret`: [7](#0-6) [8](#0-7) 

the equality that should hold but does not is:
`organization whose secret validated the signature == organization that owns the repository the handler writes to`

An attacker controlling org `A`'s webhook secret can send: `{"repository":{"owner":{"login":"A"},"full_name":"B/victim-repo"}, ...}` signed with A's secret. `verify_signature` resolves `Shipit.github(organization: "A")` and the signature matches (since it's the attacker's own secret), so the request is accepted; then `PushHandler`/`StatusHandler`/etc. resolve the stack via `full_name = "B/victim-repo"`, which belongs to org `B` and has nothing to do with org `A`.

### Impact Explanation
This breaks the fundamental trust boundary between tenants in a multi-organization Shipit deployment. Concretely, an attacker who legitimately controls one onboarded GitHub organization (not a Shipit account, not an `ApiClient` token, not TLS interception) can, for any other organization/stack hosted on the same instance:
- Forge `status` events to create arbitrary `Status` records (`state: success`) for any commit SHA of a victim stack via `StatusHandler#process` / `Commit#create_status_from_github!`, which can flip a commit to `deployable?` and trigger continuous delivery / merge-queue processing (`ProcessMergeRequestsJob`), i.e., driving an **unauthorized deploy or merge** of code the attacker doesn't control CI for. [9](#0-8) [10](#0-9) 
- Forge `push` events to force `GithubSyncJob` re-sync of a victim stack with an attacker-chosen `expected_head_sha`. [11](#0-10) 
- Forge `pull_request` events to archive/unarchive victim review stacks. [12](#0-11) 

This lands in the "unauthorized deploy, rollback or merge" Critical bucket, since forged CI-success statuses can move victim commits through the deploy/merge pipeline.

### Likelihood Explanation
Requires only that the attacker be the legitimate administrator/owner of one GitHub organization already connected to the same multi-tenant Shipit instance (a normal, low-privilege, unprivileged-relative-to-other-tenants position) — no Shipit session, `ApiClient` token, or GitHub App private key for the victim org is needed. This is realistic wherever a shared Shipit deployment onboards multiple, mutually-untrusting organizations (explicitly documented and supported), which is the exact scenario `docs/setup.md`'s "Using Multiple Github Applications" section describes.

### Recommendation
After verifying the HMAC signature, cross-validate that the organization used to select the webhook secret (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` that the handler will actually act upon, and reject the request (422) if they diverge. Ideally, resolve the target repository/stack using the same verified organization identity rather than re-reading an independent field of the untrusted payload.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), each with at least one stack (`OrgA/repoA`, `OrgB/repoB`).
2. As the administrator of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret`), craft a `status` webhook payload:
```json
{
  "sha": "<victim-commit-sha-in-OrgB/repoB>",
  "state": "success",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/repoB" }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, raw_body)` and POST to `/webhooks`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and validates successfully against the attacker's own secret.
5. `StatusHandler#process` resolves the target via `Handler#stacks` → `Repository.from_github_repo_name("OrgB/repoB")`, creating a forged `success` status on `OrgB`'s commit — despite the signature having been verified against `OrgA`, not `OrgB`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
