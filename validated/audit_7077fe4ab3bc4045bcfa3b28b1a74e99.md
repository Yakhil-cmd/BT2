### Title
Cross-organization webhook payload confusion allows forging repository writes under an unrelated organization's identity - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects **which** GitHub App/organization secret to validate the HMAC signature against by reading `repository.owner.login` (falling back to `organization.login`) out of the untrusted JSON body itself. [1](#0-0) [2](#0-1)  Every event handler, however, determines **which repository/stack to actually mutate** from a completely different field of the same body — `repository.full_name` — with no check that it belongs to the organization that was used to select the signing secret. [3](#0-2) 

In Shipit's documented multi-organization configuration, each organization has its own GitHub App and its own `webhook_secret`, but all organizations POST to the single shared `/webhooks` endpoint. [4](#0-3)  A caller who legitimately possesses (or can obtain, e.g. as an admin of one of the configured GitHub Apps) the `webhook_secret` for Organization A can forge a signed payload where `repository.owner.login` = `"OrgA"` (so `verify_signature` picks OrgA's secret and passes) while `repository.full_name` = `"OrgB/some-repo"` — a repository actually tracked under a *different* organization/secret in the same Shipit instance. Because the handlers only look at `repository.full_name`, the write proceeds against OrgB's stacks despite the signature having been validated against OrgA's key.

### Finding Description
This is a direct analog of the reported bug class: a value that is verified/authorized (`liquidationInitialAsk` bound into the signed lien state) diverges from the value that is actually acted upon (the truncated `uint88` cast used at auction time). Here, the equality that should hold and is silently broken is:

```
organization_whose_secret_verified_the_signature == organization_owning_the_repository_that_gets_written
```

- **Before the attack:** For a legitimately-delivered GitHub webhook, `repository.owner.login` and `repository.full_name`'s owner segment always refer to the same repository, so the two code paths happen to agree.
- **After the attacker's crafted request:** The attacker controls the entire raw JSON body (this is a public, unauthenticated endpoint — the only gate is the HMAC check). [5](#0-4)  They can freely set `repository.owner.login`/`organization.login` to the organization whose secret they know, while setting `repository.full_name` to an arbitrary tracked repository belonging to a different, unrelated organization. `verify_signature` only ever checks the *known-secret* organization; it never re-derives or cross-checks the *target* organization used by the handler. [6](#0-5) 
- Handlers such as `PushHandler` resolve the stacks to act on purely from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`, with zero relation back to the authenticated organization. [7](#0-6)  The same pattern repeats across the pull-request handlers used to provision/archive review stacks (`OpenedHandler`, `LabeledHandler`, `LabelCapturingHandler`, etc.), all of which resolve their target `repository`/`stack` from `params.repository.full_name` alone. [8](#0-7) [9](#0-8) 

### Impact Explanation
Once the signature check is satisfied for the attacker-chosen (known) organization, the effective repository being written comes from an unrelated field with no organization binding. This lets a party who legitimately controls one organization's GitHub App secret drive writes into stacks/repositories that belong to a different organization tracked by the same Shipit instance — e.g., forcing `PushHandler` to enqueue `GithubSyncJob` against another org's stack, or forcing `PullRequest::OpenedHandler` to auto-provision a review stack (and its associated deploy pipeline) for another org's repository using attacker-chosen `head.sha`/`ref` values. This is a cross-repository write across an organizational trust boundary that the app is specifically designed to keep separated (that is the entire purpose of the per-organization `webhook_secret`/App config), satisfying the "cross-repository writes / unauthorized deploy" Critical-impact bar.

### Likelihood Explanation
Exploitability is gated on possessing at least one organization's `webhook_secret` within a multi-organization Shipit deployment — a realistic scenario since Shipit explicitly supports and documents hosting several independent organizations' repositories from a single instance/App set. Any party with that single secret (e.g., an admin of one of the smaller onboarded organizations, who is otherwise not privileged with respect to other organizations sharing the instance) can mount the attack with a single crafted HTTP POST; no session, `ApiClient` token, or GitHub write access to the target repository is required.

### Recommendation
After parsing the payload and verifying the signature for `repository_owner`, require that the `repository.full_name`'s owner segment (or `organization.login` for org-level events) matches the very same organization whose secret validated the request, rejecting the webhook (422) otherwise. This restores the equality: the authenticated organization must be the one whose repository is written.

### Proof of Concept
1. Configure Shipit with the documented multi-org secrets format (`OrgA` and `OrgB`, each with its own `webhook_secret`). [10](#0-9) 
2. As someone who knows `OrgA`'s `webhook_secret` (e.g., an OrgA GitHub App admin), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC(OrgA_webhook_secret, raw_body)` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and the signature validates successfully. [1](#0-0) 
5. `PushHandler#process` resolves stacks via `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"`, and enqueues `GithubSyncJob`/`sync_github` against OrgB's stack — even though the request was never signed by OrgB's secret. [11](#0-10)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-16)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
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
