## Analysis

The reported bug class is a **binding mismatch between the identity that is checked and the identity that is actually acted upon** (withdraw limit tied to account A, but the transfer moves the balance to account B, which is never checked against the same limit). The reachable analog in this engine is a mismatch between **the GitHub organization whose secret is used to authenticate a webhook** and **the repository/stack that the webhook handler actually mutates**, because those two values come from two independent fields of the same JSON payload that the sender fully controls.

`WebhooksController#verify_signature` picks the GitHub App/secret to verify against using `repository.owner.login` (or `organization.login` as fallback): [1](#0-0) [2](#0-1) 

Every handler, however, resolves the target `Stack`/`Repository` using a **different** field of the same payload — `repository.full_name`: [3](#0-2) 
and `PushHandler#process` fans this straight into `stack.sync_github`: [4](#0-3) 
Pull-request handlers do the same, using `params.repository.full_name` to locate the repository whose review stacks get archived/unarchived/provisioned: [5](#0-4) [6](#0-5) [7](#0-6) 

`Shipit.github(organization:)`/`GithubApp` explicitly supports multiple independently configured GitHub Apps, one per organization, each with its own `webhook_secret` set by whoever registers that org's app: [8](#0-7) [9](#0-8) [10](#0-9) 

Since HMAC verification only proves the payload was signed with **the secret belonging to the org named by `repository.owner.login`**, and the handlers never check that `repository.full_name`'s owner equals `repository.owner.login`, an actor who legitimately owns/administers one configured organization's webhook secret can craft a self-signed payload where `repository.owner.login` = their own org (passes signature check) but `repository.full_name` = a victim org/repo they don't control.

### Title
Cross-organization webhook forgery — signature bound to `repository.owner.login`, handlers act on unrelated `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App secret using `repository.owner.login`/`organization.login`, but every webhook `Handler` resolves the affected `Repository`/`Stack` using `repository.full_name`. Because these are two independent, attacker-supplied JSON fields inside the same signed payload, an actor who owns the webhook secret for *one* organization configured in Shipit can forge webhook events (push, pull_request opened/closed/labeled, etc.) that pass signature verification for their own org while targeting any other org/repo's stack.

### Finding Description
`verify_signature` derives `repository_owner` solely from `params.dig('repository','owner','login')` (or `organization.login`) and validates the raw body against that organization's `webhook_secret` [11](#0-10) . Once verified, `WebhooksController#create` dispatches the full parsed payload to every registered `Shipit::Webhooks::Handlers::Handler` for the event [12](#0-11) . Every handler's `stacks`/`repository` lookup uses `payload.dig('repository', 'full_name')` [13](#0-12)  — a value that is never cross-checked against the `owner.login`/`organization.login` value used to pick the signing secret.

Because Shipit supports one independent GitHub App (and one independent `webhook_secret`) per organization [8](#0-7) , whoever configures/owns an org's App knows that org's secret. That party can then compute a valid `X-Hub-Signature` over an arbitrary payload of their own choosing (per `Hook::DeliverySigner`/`verify_webhook_signature`, it is a plain HMAC-SHA1 over the raw body [10](#0-9) ), setting `repository.owner.login` to their own org (so it authenticates) while setting `repository.full_name` to a victim repository/stack.

### Impact Explanation
This breaks the binding: *organization that authenticated == repository that is written*. With a forged payload an attacker can:
- Force `PushHandler` to enqueue `GithubSyncJob`/resync a victim stack with an attacker-chosen `expected_head_sha` [14](#0-13) .
- Drive `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler` to provision, archive, or unarchive review stacks belonging to a repository the attacker does not administer [5](#0-4) [6](#0-5) .

This is an unauthorized cross-repository write / state change performed against a stack outside the attacker's authorization boundary, satisfying the "cross-repository writes" / "unauthorized deploy, rollback" impact class, since stack archival/unarchival and forced resyncs directly affect what commits are considered deployable and when deploys/merges are triggered.

### Likelihood Explanation
Requires only that the attacker legitimately controls the webhook secret for **any one** organization configured in the Shipit instance (a normal, low-privilege scenario in a multi-tenant/multi-org Shipit deployment as documented in `docs/setup.md`), and that the instance hosts stacks for other organizations too. No GitHub App private key, `api_clients_secret`, or session compromise of the victim org is needed — only crafting one raw HTTP POST with a correct HMAC computed from a secret the attacker already possesses.

### Recommendation
In `WebhooksController#verify_signature` and/or `Shipit::Webhooks::Handlers::Handler#repository_name`, require that `repository.full_name`'s owner segment matches `repository_owner` (the organization whose secret validated the signature), rejecting the webhook (422) otherwise. Alternatively, derive `repository_owner` and the handler's target repository from the identical parsed field so there is only one trusted source of truth for "which org/repo this webhook is about."

### Proof of Concept
1. Shipit is configured with two orgs, `orgA` (attacker-administered GitHub App, webhook secret known to attacker) and `orgB/victim-repo` (victim stack), per the multi-app config in `docs/setup.md`.
2. Attacker builds a `push` JSON body: `{"ref": "refs/heads/main", "after": "<attacker-chosen sha>", "repository": {"owner": {"login": "orgA"}, "full_name": "orgB/victim-repo"}}`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, body)`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `repository_owner` = `orgA`, verifies successfully against `orgA`'s secret [11](#0-10) .
5. `PushHandler#process` resolves `stacks` via `repository.full_name` = `orgB/victim-repo` [13](#0-12) , and enqueues `GithubSyncJob` for the victim's stack with the attacker-supplied `expected_head_sha` [14](#0-13) , even though `orgA` has no relationship to `orgB`.

Note: I confirmed the full source of `webhooks_controller.rb`, `handler.rb`, `push_handler.rb`, and the pull-request handlers, but was unable to retrieve the full contents of `app/models/shipit/webhooks/handlers/status_handler.rb` and `check_suite_handler.rb` in this session (index limitations) — grep confirmed their existence and a `process` method, so the same cross-org forgery likely also lets an attacker inject forged CI `Status`/check-run records for a victim commit, which would raise the impact to bypassing CI gating for merges/deploys, but this specific extension is unverified and should be checked directly if a full assessment of impact severity is needed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

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

**File:** docs/setup.md (L181-209)
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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
