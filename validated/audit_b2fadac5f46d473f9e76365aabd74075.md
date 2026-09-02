### Title
Webhook signature is verified against the payload's `repository.owner.login` while the target Stack/Repository to write to is resolved from the same payload's `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a signature against using a field taken from the unauthenticated JSON body itself, while every event handler resolves the `Repository`/`Stack` that will actually be mutated from a different field of that same body. Because these two fields are never cross-checked against each other, an attacker who owns any organization/GitHub App configured in `config/secrets.yml` (or an app they can install on their own org, since Shipit supports [multi-org configuration](docs/setup.md:182-209)) can produce a validly-signed webhook body whose `repository.owner.login` matches their own org (to pass signature verification with a secret they know) while `repository.full_name` names a completely different, victim repository/stack that Shipit also tracks.

### Finding Description
`verify_signature` derives the signing organization purely from the request body: [1](#0-0) [2](#0-1) 

`repository_owner` falls back to `organization.login` and is used only to pick the `GitHubApp` instance (and thus the `webhook_secret`) via `Shipit.github(organization: repository_owner)`. The signature covers only the raw bytes of the request, not any binding between "which org's secret validated this" and "which repository the payload claims to describe."

Every downstream handler, however, resolves the repository/stack to act on from a *different* field in the same untrusted JSON: `repository.full_name`, via `Shipit::Repository.from_github_repo_name`: [3](#0-2) 

This pattern repeats across `PushHandler` (which triggers `stack.sync_github`), and the pull-request handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `EditedHandler`), all of which look up the acted-upon repository via `params.repository.full_name`: [4](#0-3) [5](#0-4) 

Since Shipit explicitly supports per-organization GitHub Apps with independent `webhook_secret`s (used to authenticate distinct orgs' webhooks) as documented for multi-org setups: [6](#0-5) 

the equality that is supposed to hold is: `organization whose secret verified the signature == owner of the repository/stack that gets written`. Nothing enforces `payload.repository.owner.login == payload.repository.full_name.split('/').first`, nor is the org used for signing cross-checked against the org of the repo being mutated.

### Impact Explanation
An attacker who controls (or can create) a GitHub App on any organization configured in Shipit's `github:` secrets section knows that org's `webhook_secret`. They can forge a `push` (or `pull_request`) payload with `repository.owner.login` set to their own org (so `verify_signature` succeeds) but `repository.full_name` set to `victim-org/victim-repo`. `PushHandler` will then call `stack.sync_github(expected_head_sha: ...)` against the victim's tracked `Stack`, and PR handlers will archive/unarchive review stacks or mutate PR state belonging to the victim's repository — all without ever having write access to, or a valid signature scoped to, that repository. This crosses a repository boundary using credentials scoped to a different repository, matching the "cross-repository writes" / "unauthorized deploy" high-impact class, since `sync_github` can advance the deployable commit range that determines what gets shipped.

### Likelihood Explanation
This requires the attacker to control at least one organization/app entry configured in Shipit (a realistic scenario in the documented multi-org deployment mode, or in any installation where multiple orgs' webhook secrets are configured and are not equally trusted). No repository write access, session, or `ApiClient` token is required — only the ability to send an HTTP POST to the public `/webhooks` endpoint with a crafted, but validly HMAC-signed (using their own known secret), JSON body.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select the verification secret matches the owner segment of `repository.full_name` (and, ideally, that `repository.owner.login`/`organization.login` is derived consistently and cannot diverge from `full_name`). Reject the webhook if these do not match.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `attacker-org` (attacker knows its `webhook_secret` because they created/installed the App) and `victim-org` (tracks a Stack for `victim-org/victim-repo`).
2. Craft a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(attacker-org webhook_secret, body)>`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature validates successfully.
5. `PushHandler#process` resolves the stack via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker chosen sha>")` on the victim's stack, entirely bypassing any org-specific trust boundary.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
