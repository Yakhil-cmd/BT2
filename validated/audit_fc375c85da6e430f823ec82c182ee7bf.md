### Title
Webhook signature verified against a different GitHub organization than the repository the payload writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` selects which organization's `webhook_secret` to use for HMAC verification from `repository.owner.login` (or `organization.login`), but every event `Handler` resolves the target `Repository`/`Stack` from the independent `repository.full_name` field. These two payload fields are never cross-checked, so a payload can be legitimately signed for one organization while acting on a repository belonging to a completely different, unrelated organization tracked by the same multi-tenant Shipit instance.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to verify against using: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the attacker-controlled JSON body (`repository.owner.login`, falling back to `organization.login`), and `Shipit.github(organization: repository_owner)` is used only to fetch the matching `webhook_secret` for HMAC comparison in `verify_webhook_signature`: [3](#0-2) 

Once the signature check passes, the *same raw payload* is dispatched unchanged to the event handlers: [4](#0-3) 

Every handler, however, resolves the actual `Stack`/`Repository` to act on using a **different** field, `repository.full_name`, via `Handler#stacks`/`#repository_name`: [5](#0-4) [6](#0-5) 

Because Shipit explicitly supports multiple, independently-configured GitHub organizations, each with its own GitHub App and `webhook_secret` (as documented in `docs/setup.md`), the identity used to authenticate the request (`repository.owner.login` / `organization.login`) is never required to match the identity of the repository the handler mutates (`repository.full_name`). This breaks the binding: `organization that authenticated == repository that is written`.

An attacker who legitimately owns/administers **any one** of the GitHub organizations onboarded to the shared Shipit instance (and therefore knows that org's `webhook_secret`, since they created that org's GitHub App) can compute a valid HMAC-SHA1 signature over an arbitrary JSON body. They set `repository.owner.login`/`organization.login` to their own org (so `verify_signature` picks their own known secret and the signature check succeeds), while setting `repository.full_name` to any other tenant's `owner/repo` string tracked by Shipit. The `check_if_ping`/`drop_unhandled_event`/`verify_signature` filter chain performs no additional check that these two identities agree: [7](#0-6) 

### Impact Explanation
This lets an attacker who is a legitimate but unrelated tenant forge webhook events against a victim organization's stacks that they have no GitHub authorization over, including:
- `push` events processed by `PushHandler`, which call `stack.sync_github(expected_head_sha: ...)`, forcing Shipit to resync/track an attacker-chosen commit SHA on the victim's tracked branch. [8](#0-7) 
- `status` events processed by `StatusHandler`, which create arbitrary commit `Status` records (attacker-chosen `state`, e.g. `success`) for any commit SHA already known to Shipit for the victim's stack, satisfying CI/status requirements that gate `deployable?`/`allows_merges?`/continuous-deployment triggers. [9](#0-8) 
- `pull_request` events (e.g. `ClosedHandler`) which archive/mutate the victim's `ReviewStack` state based solely on `repository.full_name`. [10](#0-9) 

Faking `success` statuses on a victim stack with `continuous_deployment: true` can drive an unauthorized deploy through the existing CD path (`Commit` status update → `ContinuousDeliveryJob`/`trigger_deploy`), matching the "unauthorized deploy" Critical-impact criterion, without the attacker ever holding write access to the victim repository or any Shipit session/API token.

### Likelihood Explanation
Requires the attacker to control at least one legitimately onboarded GitHub organization on the shared Shipit instance (i.e., they are able to create/own a GitHub App and thus know that org's `webhook_secret`) — a realistic scenario for any multi-tenant deployment of this engine as documented in `docs/setup.md`. No GitHub write access to the victim repo, no Shipit account, and no leaked secrets for the victim org are needed; only the attacker's own org's webhook secret, which they legitimately possess.

### Recommendation
After computing `repository_owner`, verify that it matches the owner segment parsed from `payload.dig('repository', 'full_name')` before dispatching to handlers, and reject the request (422) if they diverge. Alternatively, have every `Handler` receive and enforce the authenticated organization explicitly (e.g., pass `repository_owner` into `Handler.call`/`Handler#stacks` and filter `Repository.from_github_repo_name` results by that owner) rather than trusting the unauthenticated `full_name` field independently.

### Proof of Concept
Given Shipit configured with two organizations, `attacker-org` (webhook_secret known to the attacker, who created that GitHub App) and `victim-org` (tracks a stack for `victim-org/victim-repo`):

1. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(body, attacker-org's webhook_secret)>`.
3. POST to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`), verifies successfully against the attacker's own secret [11](#0-10) .
5. `StatusHandler#process` runs unchanged, resolving the target commit purely by `sha`, and `Handler#stacks`/`#repository_name` would similarly resolve `victim-org/victim-repo` from `full_name` for other event types [5](#0-4) , creating a forged `success` status on the victim's commit and potentially triggering an unauthorized deploy if continuous deployment is enabled on that stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
