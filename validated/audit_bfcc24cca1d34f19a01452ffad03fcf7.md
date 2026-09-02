### Title
Webhook signature is verified against `repository.owner.login` while the target Stack is resolved from the independent `repository.full_name` field, allowing cross-organization writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GithubApp`/`webhook_secret` to check the HMAC signature using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')`. `Handler#stacks` (used by `PushHandler` and inherited by all handlers) resolves the target `Repository`/`Stack` using a *different* JSON field, `payload.dig('repository', 'full_name')`. Since both fields live in the same attacker-supplied JSON body and are never cross-checked against each other, an attacker who owns a repository (and therefore knows its `webhook_secret`) can set `repository.owner.login` to their own org (to pass signature verification) while setting `repository.full_name` to an unrelated victim org's repo (to select the write target), causing `Commit`/`Stack` mutations on infrastructure they don't own.

### Finding Description
The broken binding: the code implicitly assumes
`params.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`
but nothing enforces this equality.

Trace:
- `app/controllers/shipit/webhooks_controller.rb:24-30` verifies the signature via `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, where `repository_owner` is defined at `app/controllers/shipit/webhooks_controller.rb:59-62` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1) 
- Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw parsed JSON to handlers such as `PushHandler`. [3](#0-2) 
- `Handler#stacks` (base class inherited by `PushHandler`, and the pattern is repeated independently in every PR handler via `Repository.from_github_repo_name(params.repository.full_name)`) resolves the repository using `payload.dig('repository', 'full_name')`, entirely independent of `repository.owner.login`: [4](#0-3) 
- `PushHandler#process` then queries `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`, which triggers commit-sync/`Commit.from_github` writes on whatever Stack was resolved from `full_name`. [5](#0-4) 

Exploit: the attacker owns repo `attacker-org/evil-repo`, for which Shipit has a `GithubApp` config with a known-to-them `webhook_secret`. They craft a JSON body where:
```json
{
  "ref": "refs/heads/master",
  "after": "<victim commit sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
They HMAC-sign this body with `attacker-org`'s `webhook_secret` and POST it to `/webhooks` with `X-Github-Event: push`. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')` (matches `repository.owner.login`) and the signature validates successfully because the attacker legitimately owns that secret. `Handler#stacks`, however, resolves `Repository.from_github_repo_name('victim-org/victim-repo')` — a repository the attacker does not own and whose org's `webhook_secret` was never checked — and syncs/writes `Commit` rows on victim-org's Stack.

None of the listed guards catch this: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` schema for `PushHandler` only requires `ref`/`after` to be present, not that they match `repository.owner.login`; `force_github_authentication`/`User#authorized?`/`require_permission!` are session/API-token guards irrelevant to webhook ingestion; model validations on `Repository` (owner/name format) validate the *victim's own* stored data, not that the payload's owner field matches its full_name field. There is no code path anywhere that compares `repository.owner.login` to the owner segment of `repository.full_name`.

### Impact Explanation
An attacker who owns any GitHub repository connected to Shipit (with any configured `webhook_secret`, even a trivial personal project) can forge a signed webhook that is verified under their own org but whose payload targets an arbitrary victim Stack by full name. This lets them trigger `Stack#sync_github`, which fetches commits from GitHub and writes/updates `Commit` rows (and via `Commit.from_github` → `Shipit::User.find_or_create_author_from_github_commit`, potentially creates/updates `User` records) attributed to the victim Stack, without ever authenticating against the victim organization's webhook secret. This is a cross-tenant write matching the "payload for one repository mutating another's stack/commit" Critical category. It is repeatable against any Stack/Repository whose `owner/name` slug the attacker can guess or discover (slugs are often public/predictable), and scales to any number of victim organizations configured on the same Shipit instance.

### Likelihood Explanation
Preconditions are modest: the attacker needs (a) to own or control at least one repository/org registered in Shipit's `Shipit.github_apps`/config (giving them a legitimate `webhook_secret` for their own org), and (b) to know or guess the `owner/name` of the victim repository/stack (commonly public information). No Shipit session, API token, or victim secret is required. The attack is a single crafted HTTP POST with a valid HMAC signed with the attacker's own secret — trivial and fully repeatable/scriptable.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#initialize`), enforce that the organization used to select the `webhook_secret` matches the organization implied by every repository-derived field read from the same payload before any handler runs — e.g., assert `payload.dig('repository', 'full_name')&.split('/', 2)&.first&.downcase == repository_owner&.downcase` (and similarly for `organization.login` on membership/team events), rejecting the request with 422 on mismatch. Alternatively, refactor `Handler#stacks`/`repository_name` to always derive the repository from `repository.owner.login` + repository name rather than trusting a separately-supplied `full_name` string.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push webhook signed by org A cannot mutate a stack owned by org B" do
  # Setup two orgs with distinct webhook secrets
  Shipit.stubs(:github_config).returns(
    'attacker-org' => { webhook_secret: 'attacker-secret' },
    'victim-org'   => { webhook_secret: 'victim-secret' }
  )

  victim_repo  = Repository.create!(owner: 'victim-org', name: 'victim-repo')
  victim_stack = victim_repo.stacks.create!(branch: 'master', environment: 'production')

  body = {
    'ref' => 'refs/heads/master',
    'after' => 'deadbeef' * 5,
    'repository' => {
      'owner' => { 'login' => 'attacker-org' },       # used for signature verification
      'full_name' => 'victim-org/victim-repo'          # used to resolve the target Stack
    }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', body)}"

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = signature

  # Binding under test:
  #   repository_owner (verified org)  == "attacker-org"
  #   full_name.split('/').first (mutated org) == "victim-org"
  # These MUST be equal for the write to be authorized; here they diverge.

  Stack.any_instance.expects(:sync_github).with(expected_head_sha: 'deadbeef' * 5)

  post :create, body: body, as: :json

  assert_response :ok # signature check passes using attacker's own secret
  # sync_github (and downstream Commit.from_github) fired against victim_stack,
  # despite victim-org's webhook_secret never being checked.
end
```
This demonstrates the signature-verification organization (`attacker-org`) diverging from the mutated-stack organization (`victim-org`), with the write proceeding despite the divergence.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
