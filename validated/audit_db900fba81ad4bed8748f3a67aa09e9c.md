## Title
Webhook signature verification authenticates the payload's `repository.owner` organization while all downstream handlers act on the unverified `repository.full_name`, allowing cross-organization stack manipulation with a valid signature from a different org - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Every actual handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`, `PullRequest::*Handler`, etc.) instead resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`. Nothing binds these two fields together, so a payload signed with organization A's webhook secret can carry a `repository.full_name` pointing at organization B's repository.

### Finding Description
In Shipit's multi-organization GitHub App configuration (`Shipit.github(organization:)`, `lib/shipit.rb:170-200`), each organization has its own `webhook_secret`. The controller resolves which secret to verify against purely from the JSON body: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 

`repository_owner` is read straight from attacker-controllable JSON: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`.

Once verification passes, `create` dispatches to handlers built on `Shipit::Webhooks::Handlers::Handler`, which independently derives the target repository from a *different* field of the same payload: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Because the signature is an HMAC over the entire raw JSON body, and both `repository.owner.login` and `repository.full_name` are fields *inside* that same body, an attacker who legitimately controls (owns/administers) one onboarded organization "A" in Shipit's config — and therefore knows/can compute a valid signature using org A's `webhook_secret` — can freely construct a JSON payload where `repository.owner.login = "org-a"` (satisfies signature-org selection and passes HMAC check) while `repository.full_name = "org-b/some-repo"` (a completely different, unrelated organization's repository that Shipit also tracks). The controller only checks that *some* valid organization's secret was used to sign the raw bytes — it never checks that the org used for verification matches the org referenced by `repository.full_name` that handlers subsequently act upon.

This breaks exactly the trust binding called out in scope: *"an organization that authenticated versus the repository that is written."* The equality that should hold is:

`organization used to verify signature == owner(repository.full_name) acted upon by handlers`

but nothing enforces it.

### Impact Explanation
Handlers keyed off `repository_name`/`Repository.from_github_repo_name` perform state-changing actions on the target stack:
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` on stacks matching the spoofed `full_name`+branch [4](#0-3) 
- `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler` provision, archive, or unarchive review stacks for `Repository.from_github_repo_name(params.repository.full_name)` [5](#0-4) 

An org that is legitimately onboarded (and thus knows its own webhook secret) can forge these events against any other org's repositories tracked by the same Shipit instance, causing unauthorized GitHub sync / review-stack provisioning or archiving on repositories it does not own. This crosses an organization/repository trust boundary without any Shipit session, API token, or repository write access on the target repo — matching the High-impact category "escalation ... unauthenticated read of stack state" adjacent effects, and in cases where sync leads to auto-deploy configuration (`continuous_deployment`) or review-stack provisioning, it can result in unauthorized state changes on another organization's stack.

### Likelihood Explanation
Requires the attacker to control one legitimately onboarded organization in Shipit's `secrets.github` multi-org config (an "unprivileged" actor relative to *other* organizations' repos, but a privileged actor for their own org) — this matches the required "unprivileged-attacker" framing relative to the *target* repository/org, since Shipit is explicitly designed to host many independent, mutually-distrusting GitHub organizations behind one instance. No GITHUB_TOKEN, `api_clients_secret`, or Shipit session is needed; only crafting a raw POST body with mismatched `owner.login`/`full_name` fields, signed with the attacker's own org's known secret.

### Recommendation
Bind the two fields together before dispatching: after signature verification, require that `repository_owner` (used to select the verifying org) equals the owner embedded in `repository.full_name`, and reject (422) any payload where they differ. Alternatively, resolve the target `Repository` first, verify that its `owner` matches the app/organization whose secret validated the signature, and only then invoke handlers.

### Proof of Concept
1. Organization `attacker-org` is configured in Shipit with its own `webhook_secret_A` (a legitimate, independent onboarding — e.g., a customer org in a shared Shipit deployment).
2. Organization `victim-org` also has a repository/stack tracked by the same Shipit instance.
3. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/production-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, raw_body)` using their own known `webhook_secret_A`.
5. POST to `/webhooks`. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and the HMAC check passes (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/production-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `victim-org`'s stack — despite the signature only proving authenticity for `attacker-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
