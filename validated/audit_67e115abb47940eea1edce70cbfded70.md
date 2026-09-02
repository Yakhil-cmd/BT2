## Title
Webhook signature verification keys off `repository.owner.login` while handlers act on `repository.full_name` — cross-repository/cross-organization forged events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, while every webhook handler subsequently resolves the target `Repository`/`Stack` to mutate using a completely different field, `repository.full_name`, also taken from the same unverified body. This mirrors the reported bug class: a validated/authenticated identifier (the "atom" that is checked) is not the same identifier that the business logic actually acts upon (the "triple" that gets used) — i.e. the binding "organization that authenticated" ≠ "repository that is written" is broken.

### Finding Description
The controller parses the raw request body and extracts the signing scope purely from attacker-suppliable JSON, before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

`repository_owner` is used only to pick the correct `Shipit::GitHubApp` (and hence the `webhook_secret` HMAC key) via `Shipit.github(organization: repository_owner)`. Shipit explicitly supports multiple GitHub Apps/organizations configured with independent `webhook_secret` values in one installation, as shown in the multi-org secrets fixture: [3](#0-2) 

Once `verify_signature` passes, the raw JSON body (unmodified) is dispatched to the registered handler(s): [4](#0-3) 

Every handler, however, resolves the actual `Repository`/`Stack` to act on using a *different* JSON key, `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

The same pattern repeats across every pull-request handler (`opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `edited_handler.rb`, `assigned_handler.rb`, `label_capturing_handler.rb`), all of which call `Shipit::Repository.from_github_repo_name(params.repository.full_name)` to locate the repository whose stacks get archived/unarchived, whose review stacks are created, or whose `PullRequest` records are updated — e.g.: [6](#0-5) 

Because `repository.owner.login` (used for signature-key selection) and `repository.full_name` (used for the actual mutated target) are two independent, attacker-controlled fields in the same unsigned-at-parse-time JSON payload, an attacker who legitimately administers/owns *any one* organization configured in this Shipit instance (and therefore knows that organization's `webhook_secret`, since they configured the GitHub App installation for it) can craft a payload where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: repository_owner)` picks *their* app/secret, against which they compute a valid `X-Hub-Signature`), and
- `repository.full_name` = `"victim-org/victim-repo"` (a different, unrelated repository configured in the same Shipit instance under a different organization/app).

`verify_signature` succeeds (the HMAC matches the attacker's own known secret), and the handler dispatch then operates on the victim repository, because the handler never re-checks that `full_name`'s owner equals the `repository_owner` used to authenticate the request.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding explicitly called out as an in-scope class. Concretely, an attacker who controls one org boundary in a multi-org Shipit deployment can forge GitHub webhook events (`push`, `status`, `check_suite`, `pull_request`) against any other repository/stack configured in the same instance:
- `push` handler enqueues `GithubSyncJob` for the victim stack, causing Shipit to re-sync/trust attacker-timed data for that repo.
- `status` handler creates a `Status` record with an attacker-chosen `state` (e.g. `"success"`) for an arbitrary commit sha on the victim stack — this is the exact mechanism Shipit uses to gate deploys/merges on CI, so a forged "success" status can clear blocking/required CI checks and enable an **unauthorized deploy or merge** on a repository the attacker does not own.
- `pull_request` handlers can archive/unarchive review stacks or update `PullRequest` records belonging to the victim repository.

This satisfies the required Critical/High impact bar (unauthorized deploy/merge via forged CI status; cross-repository writes) without requiring any privileged Shipit session, API token, or the victim's webhook secret.

### Likelihood Explanation
Requires the attacker to control (or know the `webhook_secret` of) at least one GitHub organization/app configured in the same multi-tenant Shipit installation — a realistic scenario for self-hosted Shipit instances that back multiple orgs/teams behind one deployment, as explicitly supported and documented/tested (`secrets_double_github_app.yml`, `github(organization:)` lookup). No GitHub App private key, Shipit session, or API client token is needed; only an HTTP POST to the public `/github/webhooks` endpoint with a crafted signature computed against the attacker's own known secret.

### Recommendation
After determining `repository_owner`/`organization` for signature verification, re-validate that the `repository.full_name`'s owner matches the same organization used to select the signing key (or, better, always derive the signature-verification scope from the same field used for target resolution, i.e. `repository.full_name`'s owner segment) before dispatching to any handler. Reject the webhook if the two disagree.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` (attacker controls the GitHub App/installation, thus knows its `webhook_secret`) and `victim-org` (hosts `victim-org/victim-repo`, a stack Shipit tracks), per the supported multi-org config shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org webhook_secret, body)>` and POSTs it to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own known secret — see `app/controllers/shipit/webhooks_controller.rb` lines 24-30 and 59-62.
5. `Shipit::Webhooks::Handlers::StatusHandler` (via `Handler#repository_name`/`#stacks`, `app/models/shipit/webhooks/handlers/handler.rb` lines 32-38) resolves the stack from `repository.full_name = "victim-org/victim-repo"` and creates a forged `success` `Status` for that commit — despite the request never being signed by `victim-org`'s actual `webhook_secret`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
