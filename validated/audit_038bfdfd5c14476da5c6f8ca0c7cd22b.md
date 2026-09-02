### Title
Push webhook `repository.full_name` is never bound to the signature-verifying `repository.owner.login`, allowing cross-tenant stack sync forgery - (File: `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a push payload using `repository_owner` (`payload.dig('repository','owner','login')` or `organization.login`) to pick the GitHub App/secret for HMAC verification, while `Handler#stacks` looks up the target `Repository`/`Stack` using a completely separate field, `payload.dig('repository','full_name')`. Nothing checks that `full_name` actually belongs to `repository_owner`. An attacker who owns a GitHub org with the Shipit app installed can sign an arbitrary JSON body with their own valid webhook secret while setting `repository.full_name` to a victim's repo, causing `PushHandler#process` to run against the victim's `Stack`.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`repository_owner (used to select the signing secret in WebhooksController#verify_signature)` **must equal** `Repository.from_github_repo_name(payload.dig('repository','full_name')).owner (used to select the target Stack in Handler#stacks)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (fallback `organization.login`) and verifies the HMAC using `Shipit.github(organization: repository_owner)`: [1](#0-0) [2](#0-1) 
- After this passes, the raw parsed JSON (same object) is handed to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`: [3](#0-2) 
- `Handler#stacks` resolves the target repository using a *different* field of that same payload, `payload.dig('repository','full_name')`, with no cross-check against `repository_owner`: [4](#0-3) 
- `PushHandler#process` filters that repository's stacks by branch and unconditionally calls `sync_github(expected_head_sha: params.after)`, where `params.after` is attacker-controlled: [5](#0-4) 

Root cause: the HMAC signature only proves "this body was signed with organization X's secret" — it says nothing about which repository's data is inside the body. `owner.login` (used for auth) and `full_name` (used for authorization/routing to a `Stack`) are two independent, attacker-supplied JSON fields that are never reconciled. `Repository.from_github_repo_name` performs a plain DB lookup by `owner`/`name` parsed out of the forged `full_name`, with no relation to the verified signer: [6](#0-5) 

Exploit flow:
1. Attacker creates/uses their own GitHub org, installs the Shipit GitHub App on it (legitimately obtaining a valid webhook secret for that org).
2. Attacker crafts a JSON push payload: `ref: "refs/heads/main"`, `after: "<attacker-chosen-sha>"`, `repository.owner.login: "attacker-org"`, `repository.full_name: "victim-org/victim-repo"`.
3. Attacker computes the `X-Hub-Signature` HMAC over this exact body using their own org's secret and POSTs it to `/webhooks`.
4. `verify_signature` looks up the GitHub App for `attacker-org`, verifies the signature against the attacker's own secret — passes.
5. `PushHandler#process` resolves `stacks` via `full_name = "victim-org/victim-repo"`, finds the victim's `Stack` with `branch == "main"`, and enqueues `GithubSyncJob` with the victim's `stack_id` and the attacker's forged `expected_head_sha`.

Existing guards that fail to stop this: `drop_unhandled_event` and `check_if_ping` only gate on event type, not payload content. The `ExplicitParameters` schema for `PushHandler` only requires `:ref` and `:after` — it does not validate or bind `repository.full_name`/`owner.login`. `Repository` model validations only constrain `owner`/`name` character format, not ownership consistency with a signing org.

### Impact Explanation
A forged push webhook signed with an attacker-controlled organization's own secret can enqueue `Shipit::GithubSyncJob` against an arbitrary victim `Stack`, passing an attacker-chosen `expected_head_sha`. This is a payload from one repository/org mutating another repository's stack state — matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team"). Repeatable against any victim stack whose `branch` value the attacker can guess or observe (commonly `main`/`master`), and repeatable indefinitely since the attacker's own org secret remains valid for further forged requests.

### Likelihood Explanation
Preconditions: the attacker needs any GitHub org (which they fully control) with the Shipit GitHub App installed — a normal, low-cost, self-service action requiring no special privilege in the victim's org or Shipit instance. The attacker needs to know (or guess) the victim's `Stack#branch` (commonly `main`) and the victim repo's `full_name`, both of which are typically public information. No secrets belonging to Shipit or the victim are required. This makes the attack highly feasible and cheap to execute repeatedly.

### Recommendation
In `Handler#stacks` (or upstream in `WebhooksController`), verify that the `Repository` resolved from `payload.dig('repository','full_name')` actually belongs to the same organization/owner used in `verify_signature` (`repository_owner`), rejecting the webhook if they diverge. Alternatively, derive the target repository directly from the GitHub App installation context (installation ID) rather than trusting arbitrary payload fields for authorization.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (proof outline)
test ":push from attacker org with forged full_name enqueues job against victim stack" do
  victim_stack = shipit_stacks(:shipit) # branch 'master', repo Shopify/shipit-engine
  attacker_org = 'attacker-org'
  attacker_secret = 'attacker-secret'

  forged_payload = JSON.parse(payload(:push_master))
  forged_payload['repository']['owner']['login'] = attacker_org
  forged_payload['repository']['full_name'] = victim_stack.repository.full_name # forged
  forged_payload['after'] = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' # attacker-chosen sha
  body = forged_payload.to_json

  # Signature computed with the ATTACKER's own valid secret for attacker_org
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    stub(verify_webhook_signature: true)
  )

  request.headers['X-Github-Event'] = 'push'
  request.headers['X-Hub-Signature'] = 'sha1=<valid-for-attacker-secret>'

  assert_enqueued_with(
    job: GithubSyncJob,
    args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef']
  ) do
    post :create, body: body, as: :json
  end
end
```
Assertion on both sides of the broken binding: `repository_owner` used in `verify_signature` == `attacker-org`, while the `Stack` actually enqueued for sync (`stack_id: victim_stack.id`) belongs to `Shopify/shipit-engine` (owner `Shopify`) — the two never match, proving the divergence between "ref approved" (signed by attacker) and "ref executed" (against victim's stack).

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
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
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
