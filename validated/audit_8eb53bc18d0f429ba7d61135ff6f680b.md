Found the binding break: `WebhooksController#verify_signature` derives the HMAC secret/organization from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), but `Handler#repository_name` (used by every webhook handler, including `PushHandler` and `MembershipHandler`) reads a *different* field, `payload.dig('repository', 'full_name')`, to decide which `Repository`/`Stack` gets written. These two payload fields are never cross-checked against each other.

### Title
Webhook signature verified against `repository.owner.login` while writes are keyed on the unchecked `repository.full_name` field, allowing cross-organization stack writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
### Finding Description
`Shipit::WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` will validate the signature purely from the attacker-supplied payload field `repository.owner.login` (with a fallback to `organization.login`): [1](#0-0) [2](#0-1) 

Once the signature check passes for *that* organization's app, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the full parsed JSON body, and every handler resolves the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')`, a completely independent field from the one used to select/verify the signing secret: [3](#0-2) 

`PushHandler` uses this to trigger `stack.sync_github` for any stack matching the branch of the resolved repository: [4](#0-3) 

Nothing in the request pipeline checks that `repository.owner.login` (used to pick/verify the HMAC secret) and `repository.full_name`'s owner (used to pick the `Repository` that is actually acted upon) refer to the same organization/installation.

### Impact Explanation
In a multi-organization Shipit deployment (`docs/setup.md` "Using Multiple Github Applications" section, `config/secrets.yml` keyed per org), an attacker who controls a GitHub App installed on **OrgA** (and therefore legitimately knows OrgA's `webhook_secret`) can craft a webhook payload where `repository.owner.login` = `"OrgA"` (so the signature verifies against OrgA's secret) but `repository.full_name` = `"OrgB/some-repo"`. Because `PushHandler`/other handlers only look at `repository.full_name`, this payload would be accepted as authentic and dispatched against OrgB's stack, e.g. triggering `GithubSyncJob`/`sync_github` for a repository the attacker's app was never installed on and never authorized to affect. This breaks the intended binding "the organization that authenticated == the repository that is written," and could let an attacker with a foothold in one organization's Shipit-connected GitHub App inject sync/state events (and, depending on which handlers process the event, team/user membership changes — see `MembershipHandler`) for a repository/organization it has no legitimate relationship with.

### Likelihood Explanation
This does not require any Shipit session, `ApiClient` token, or `webhook_secret` for the *target* org — only knowledge of a `webhook_secret` for *any* org configured in the same Shipit instance (which is inherently available to anyone who administers a GitHub App pointed at that instance). The webhook endpoint (`/webhooks`) is unauthenticated apart from this signature check, so the only requirement is the ability to send a crafted POST with a valid signature computed over a payload whose `owner.login` and `full_name` fields disagree — trivial to construct.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), require that the organization used to select the webhook secret is identical to the organization embedded in `repository.full_name` before dispatching to handlers; reject the webhook (422) if they diverge.

### Proof of Concept
1. Configure Shipit with two GitHub Apps, one installed on `OrgA` (attacker-controlled) and one on `OrgB` (victim), per `docs/setup.md`'s multi-org example.
2. Attacker computes `sha1=HMAC(OrgA_webhook_secret, body)` for a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<victim-commit-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. POST to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and successfully verifies the signature against `OrgA`'s secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` (via `repository_name`) and triggers `stack.sync_github` on OrgB's stack — an action the OrgA app has no authorization for.

**Caveat**: This analysis is based on static code review of `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `push_handler.rb`, and `membership_handler.rb`; I could not execute the code to confirm no additional cross-check exists elsewhere (e.g., in `Repository.from_github_repo_name` or `sync_github`) that ties the resolved repository back to the authenticating organization. A Devin session with the full test suite would be needed to dynamically confirm the exploit end-to-end.

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
