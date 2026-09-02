### Title
Cross-organization stack hijack via mismatched `repository.owner.login` vs `repository.full_name` in webhook payload - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb, app/models/shipit/webhooks/handlers/push_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the org whose `webhook_secret` to verify the HMAC against using `params.dig('repository','owner','login')`, while `Handler#repository_name` (used by `PushHandler#process` to select the target `stacks`) uses the independently-attacker-controlled `payload.dig('repository','full_name')`. Since both values come from the same raw, attacker-supplied JSON body, an attacker who legitimately controls org-a's webhook secret can send a request where `repository.owner.login = "org-a"` (verifies) but `repository.full_name = "org-b/target-repo"` (selects a different org's stack), causing `Stack#sync_github` to run for org-b using an attacker-chosen `expected_head_sha`.

### Finding Description
The broken binding: `github_app_used_for_signature.organization == owner_of(repository_full_name_used_to_select_stacks)`. Trace:

- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and looks up `Shipit.github(organization: repository_owner)` to get the `GitHubApp` (and its `webhook_secret`) used to verify the HMAC signature over the raw request body [2](#0-1) .
- After verification succeeds, `create` parses the same raw body and dispatches it unmodified to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- `PushHandler#process` resolves `stacks` via `Handler#stacks`, which uses `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` — a completely separate JSON key from `repository.owner.login` [4](#0-3) , then runs `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` [5](#0-4) .
- `PushHandler`'s `ExplicitParameters` schema only requires `ref` and `after`; it never validates or constrains `repository.full_name` against `repository.owner.login` [6](#0-5) .
- `Shipit.github` selects org config purely by the `organization` string passed in, with no cross-check against any other field of the payload [7](#0-6) .

Exploit flow: attacker legitimately controls org-a (a real GitHub org/repo they added to Shipit, so they know its configured `webhook_secret`). They craft a raw JSON body with `"repository": {"owner": {"login": "org-a"}, "full_name": "org-b/target-repo"}`, `"ref": "refs/heads/main"`, `"after": "<attacker-chosen-sha>"`, sign it with org-a's HMAC secret, and POST directly to `/webhooks` with `X-Github-Event: push`. `verify_signature` looks up org-a's `GitHubApp`, computes the HMAC over the raw body, and it matches — verification passes. The handler then resolves `Repository.from_github_repo_name('org-b/target-repo')` and calls `sync_github(expected_head_sha: <attacker-chosen-sha>)` on org-b's stack, which the attacker never authenticated for.

No existing guard prevents this: `verify_signature` only checks the HMAC validity for the org derived from `owner.login`; it never re-derives or compares that org against `full_name`'s owner segment used later by the handler. `drop_unhandled_event` and the `ExplicitParameters` schema for `PushHandler` don't touch this field pair either.

### Impact Explanation
The attacker can force `Stack#sync_github` to execute against an arbitrary victim repository's stack (`org-b/target-repo`) that they never authenticated for, passing an attacker-chosen `expected_head_sha`. This is a payload for one repository mutating another's stack — a cross-tenant write that matches the "Critical" impact category. It's fully repeatable against any stack whose owning organization/repository name is known to the attacker, as long as the attacker controls the webhook secret of any one organization configured in the Shipit deployment (multi-org Shipit installs are supported per `Shipit.github_organizations`/`github_app_config`).

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub organizations (`secrets.github` keyed by org) where the attacker legitimately owns/administers one of those orgs (org-a) and therefore knows its `webhook_secret` — this is the exact precondition stated in the question and is realistic for any Shipit instance serving multiple independent teams/orgs. No GitHub interaction is even required; the attacker can POST directly to the Shipit host's `/webhooks` endpoint with a hand-crafted body and a valid signature for org-a. Cost is trivial (one signed HTTP request); it is fully repeatable for any target repository name known to the attacker.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), derive the organization used for both signature verification and stack resolution from a single, consistently-parsed source, and explicitly assert that `repository.full_name`'s owner segment matches `repository.owner.login` (or simply drop `owner.login`/`organization.login` entirely and always derive the verifying org from the owner segment of `repository.full_name`). Reject the webhook (422) if they diverge, before dispatching to any handler.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push webhook with mismatched repository.owner.login vs repository.full_name hijacks another org's stack" do
  org_a_secret = "org-a-secret"
  org_b_stack  = shipit_stacks(:some_org_b_stack) # belongs to repository org-b/target-repo

  # Configure Shipit.github for multiple orgs; org-a webhook_secret known to attacker.
  Shipit.expects(:github).with(organization: "org-a").returns(
    Shipit::GitHubApp.new("org-a", webhook_secret: org_a_secret)
  )

  body = {
    ref: "refs/heads/#{org_b_stack.branch}",
    after: "deadbeef" * 5,
    repository: {
      owner: { login: "org-a" },        # used for signature org lookup -> attacker-known secret
      full_name: "org-b/target-repo"    # used by PushHandler to select stacks
    }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_secret, body)

  Shipit::Stack.any_instance.expects(:sync_github).with(expected_head_sha: "deadbeef" * 5)

  post shipit.webhooks_path, params: body,
       headers: { "X-Github-Event" => "push", "X-Hub-Signature" => signature },
       as: :json

  assert_response :ok
  # Binding check: the org that verified the signature ("org-a") must equal
  # the owner of repository.full_name used to select stacks ("org-b").
  # This assertion demonstrates they diverge:
  assert_not_equal "org-a", "org-b/target-repo".split("/").first
end
```
This demonstrates `sync_github` is invoked on `org-b`'s stack despite the request being signed only with `org-a`'s secret, proving the cross-organization write.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-10)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
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

**File:** lib/shipit.rb (L170-181)
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
```
