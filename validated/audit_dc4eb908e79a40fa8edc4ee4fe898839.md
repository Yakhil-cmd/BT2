Confirmed. None of the handlers cross-check `params.repository.owner.login` against the owner embedded in `params.repository.full_name` — they only use `full_name` for the DB lookup, while `WebhooksController#verify_signature` only uses `repository.owner.login` (or `organization.login`) to select which org's secret to verify the HMAC with. [1](#0-0) [2](#0-1) 

### Title
Webhook signature is verified against `repository.owner.login`'s secret while the handler mutates the repository resolved from `repository.full_name` - authentication/authorization confusion - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` is used to validate the HMAC signature using `params.dig('repository', 'owner', 'login')`, but `OpenedHandler#repository` (and sibling PR handlers) resolve the target `Shipit::Repository` using `params.repository.full_name` instead. Because these two payload fields are never checked against each other, an attacker who legitimately controls a webhook secret for `attacker-org` can forge a `pull_request` "opened" event where `repository.owner.login = "attacker-org"` (so it passes signature verification) but `repository.full_name = "victim-org/victim-repo"` (so the handler operates on the victim's repository).

### Finding Description
The broken binding: `Shipit.github(organization: params.dig('repository','owner','login'))` (the org whose secret authenticated the byte stream) should equal the owner of `Shipit::Repository.from_github_repo_name(params.repository.full_name)` (the record that gets mutated), but the code never enforces this equality.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and fetches `Shipit.github(organization: repository_owner)` to verify `X-Hub-Signature` against that organization's `webhook_secret`. [3](#0-2) 
2. Once verified, `Shipit::Webhooks.for_event(event)` dispatches the raw, attacker-controlled `params` to `OpenedHandler#process`, with no re-validation tying `repository.owner.login` to `repository.full_name`. [4](#0-3) 
3. `OpenedHandler#repository` resolves the actual DB `Repository` purely from `params.repository.full_name`, ignoring `repository.owner.login` entirely. [2](#0-1) 
4. If `repository.review_stacks_enabled` and `provisioning_behavior_allow_all?` are true for that resolved repository, `process` calls `ReviewStackAdapter#find_or_create!` scoped to `repository.review_stacks`, creating a live `Stack`/`ReviewStack` row with `branch` from the attacker-supplied `pull_request.head.ref`. [5](#0-4) [6](#0-5) 

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` (`params do ... end` block) only validates the shape/types of fields like `repository.full_name` and `repository.owner` is not even declared as a required sub-key in the `OpenedHandler` schema, so nothing forces consistency between the two `repository` sub-fields; `Shipit::Repository.from_github_repo_name` performs a plain DB lookup with no ownership check tied to the authenticated signer. [7](#0-6) [8](#0-7) 

### Impact Explanation
An attacker who owns/administers "attacker-org" (and thus knows attacker-org's own `webhook_secret` on this multi-tenant Shipit install) can forge a `pull_request` webhook naming any victim repository in `repository.full_name`, causing Shipit to create a `ReviewStack`/`Stack` row scoped to the victim's `Repository`, with a branch name and SHA fully controlled by the attacker. Because review stack creation triggers provisioning/deploy `Command` execution against the victim repository/environment, this is a cross-tenant write and provisioning trigger driven by a payload that was never authenticated for the victim organization — matching the "payload for one repository mutating another's stack" Critical category. It is repeatable against any repository configured with `review_stacks_enabled` + `provisioning_behavior_allow_all`, for any organization the attacker doesn't own, as long as the attacker holds a valid webhook secret for *some* organization on the shared Shipit instance.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where distinct GitHub organizations are configured with separate `webhook_secret`s under `Shipit.github_app_config`, and where the attacker is a legitimate operator of at least one such organization (so they know its `webhook_secret`), and the victim repository has `review_stacks_enabled` with `provisioning_behavior_allow_all`. Given those preconditions (explicitly stated as given in the audit scope), the attack is a single crafted HTTP POST to `/webhooks` with a valid HMAC computed over attacker-controlled JSON — no GitHub interaction, no privileged Shipit session, and it is fully repeatable/scriptable against any victim repo name.

### Recommendation
In `WebhooksController` (or in each `Handler`), verify that the organization used to validate the signature matches the owner parsed out of `repository.full_name` before dispatching/processing — e.g., derive `repository_owner` consistently from `full_name` (or explicitly compare `params.dig('repository','owner','login')` against `full_name.split('/').first`) and reject (422) on mismatch. Alternatively, in `Repository.from_github_repo_name`, cross-check the resolved repository's `owner` against the authenticated signing organization before returning it to handlers.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
```ruby
test "forged pull_request payload with mismatched repository.owner.login vs full_name creates a stack for victim repo" do
  victim_repo = shipit_repositories(:shipit) # owner "shopify", review_stacks_enabled + allow_all
  attacker_org = "attacker-org"

  Shipit.stubs(:github_app_config).with(attacker_org).returns(webhook_secret: "attacker-secret")
  # attacker signs body with their own secret for attacker-org
  body = payload_parsed(:pull_request_opened)
  body["repository"]["full_name"] = victim_repo.github_repo_name # "shopify/shipit-engine"
  body["repository"]["owner"]["login"] = attacker_org             # signer identity != repo owner
  raw = body.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", "attacker-secret", raw)

  request.headers["X-Github-Event"] = "pull_request"
  request.headers["X-Hub-Signature"] = signature

  assert_difference -> { victim_repo.review_stacks.count }, 1 do
    post :create, body: raw, as: :json
  end
  assert_response :ok

  # Assert: signer org (attacker_org) != owner of the repository whose review_stacks changed (victim_repo.owner)
  refute_equal attacker_org, victim_repo.owner
end
```
This asserts the exact broken equality: the organization (`attacker-org`) whose secret verified the request bytes is not equal to `victim_repo.owner` ("shopify"), yet a `ReviewStack` row was created under `victim_repo`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-69)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
