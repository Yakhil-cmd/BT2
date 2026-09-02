### Title
Webhook signature is verified against `repository.owner.login`, but `pull_request` handlers provision review stacks using an unrelated `repository.full_name` field, allowing cross-tenant `ReviewStack` creation - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check using `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) , while `OpenedHandler#repository` resolves the target `Repository` from the entirely independent `params.repository.full_name` string [3](#0-2) . Since these are two separate JSON fields with no cross-validation, an attacker who controls a legitimately onboarded org (and thus knows that org's `webhook_secret`) can forge a payload where `repository.owner.login` is their own org (so the signature check passes) but `repository.full_name` names a different, review-stacks-enabled victim repository, causing `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` to provision a new `ReviewStack` under the victim repository.

### Finding Description
The broken binding, as an explicit equality that the code implicitly assumes but never enforces:
`params.repository.owner.login == owner_segment_of(params.repository.full_name)`

**Signature check** (`app/controllers/shipit/webhooks_controller.rb`):
```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)   # from repository.owner.login (or organization.login)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

**Target repository resolution** (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`):
```
def repository
  @repository ||=
    Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
    Shipit::NullRepository.new
end
```
which feeds `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` in `process` [5](#0-4) .

`Repository.from_github_repo_name` simply splits the `full_name` string on `/` and does a DB lookup, with no relation whatsoever to the `owner.login` field that was used to select the webhook secret:
```
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [6](#0-5) 

**Root cause**: the two JSON fields `repository.owner.login` and `repository.full_name` are independently attacker-controlled in the raw POST body (GitHub normally keeps them consistent, but nothing in this engine validates that consistency), and the code uses one field for authentication and a different field for authorization/target selection.

**Exploit flow**: An attacker who administers their own Shipit-onboarded org ("attacker-org", with known `webhook_secret`) crafts a `pull_request`/`opened` webhook body where `repository.owner.login = "attacker-org"` (so `verify_signature` computes the HMAC using attacker-org's secret and it matches) but `repository.full_name = "victim-org/victim-repo"`. `drop_unhandled_event` and `check_if_ping` do not inspect this field and do not block the request [7](#0-6) . `ExplicitParameters` schema in `OpenedHandler` only requires `repository.full_name` to be a `String`, with no format/consistency constraint [8](#0-7) . `OpenedHandler#repository` then resolves `victim-repo`, and if `victim-repo.review_stacks_enabled` and the provisioning behavior condition is met (`provision?`), a new `ReviewStack` is created scoped to the victim repository, using attacker-supplied `pull_request.head.ref` and `params.number` as branch/PR number [9](#0-8) .

None of the existing guards prevent this: `verify_signature` only checks org-secret correctness for whichever org name is embedded in the payload, not that the org actually owns the target repo; `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` only validates types/presence, not cross-field consistency; and `Repository` model validations only constrain `owner`/`name` character sets, not that they match a signed org.

### Impact Explanation
A successful request writes a `Shipit::ReviewStack` record for a repository the attacker's org did not authenticate for — a cross-tenant record write matching the Critical category "a payload for one repository mutating another's stack." Depending on downstream provisioning (`ProvisioningHandler`), this can trigger real infrastructure/deploy actions on the victim's environment using attacker-controlled branch ref and PR number. This is repeatable against any repository with `review_stacks_enabled` and an appropriate `provisioning_behavior`, as long as the attacker controls (or has been granted) at least one onboarded org with a known webhook secret — the attack is not limited to a single victim repo per attacker-org.

### Likelihood Explanation
Preconditions: attacker must operate at least one Shipit-onboarded GitHub org (with its `webhook_secret` known to them, as the org's own webhook administrator would normally know it), and the victim repository must have `review_stacks_enabled` with a `provisioning_behavior` that doesn't require a label the attacker cannot supply on the victim's PRs (`allow_all` trivially qualifies since the attacker never needs a real PR on the victim repo at all — the whole PR object is fabricated). The attacker never needs write access to the victim repo, only the ability to POST an HTTP request. This is highly feasible: a single crafted HTTP POST, fully scriptable and repeatable.

### Recommendation
In `WebhooksController#verify_signature` or before dispatching to handlers, ensure the org used for signature verification is bound to the same repository that handlers subsequently operate on. Concretely: derive the target `Repository` from `full_name` first, verify the signature using the secret configured for `repository.owner` (not the raw payload `owner.login`), and reject the request if the payload's `repository.owner.login` does not match the resolved repository's actual `owner`. Alternatively, in each handler's `repository` method, additionally assert `params.repository.full_name.split('/').first == params.dig('repository','owner','login')` before performing any lookup/provisioning.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (or `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create `attacker-org` config with a known `webhook_secret` in test `Shipit.github` config, and create a `victim-org/victim-repo` `Shipit::Repository` with `review_stacks_enabled: true`, `provisioning_behavior: allow_all`.
2. Build a `pull_request`/`opened` JSON payload with `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `pull_request.head.ref = "attacker-branch"`, `number = 999`.
3. Compute `X-Hub-Signature` using attacker-org's `webhook_secret` over the raw body.
4. POST to `/webhooks` with `X-Github-Event: pull_request`.
5. Assert response is `200 OK` (i.e., `verify_signature` passed).
6. Assert (equality check both sides): `params.dig('repository','owner','login') == "attacker-org"` while the created `Shipit::ReviewStack.last.stack.repository.full_name == "victim-org/victim-repo"` — proving the org verified is not the org whose repository was mutated.
7. Assert `Shipit::ReviewStack.exists?(pull_request_number: 999, stack: { repository: victim_repo })` is `true`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L5-22)
```ruby
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-39)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
