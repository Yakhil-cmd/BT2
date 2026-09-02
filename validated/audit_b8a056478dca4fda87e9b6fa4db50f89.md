### Title
Webhook signature verification authenticates the wrong organization field, allowing cross-organization forged push/status/pull_request events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization used to validate the `X-Hub-Signature` HMAC from `params.dig('repository','owner','login')`, but the event handlers that perform the actual writes (creating stacks, syncing commits, changing statuses, provisioning/archiving review stacks) resolve the target repository from a *different* payload field, `payload.dig('repository','full_name')`. Because both fields live in the same attacker-controlled JSON body, an attacker who can produce a validly-signed webhook for *any* configured organization can set `repository.owner.login` to that (authenticating) organization while setting `repository.full_name` to an arbitrary repository tracked under a *different* organization, causing Shipit to act on a repository/stack it never authenticated for.

### Finding Description
The binding that should hold is:
`organization authenticated by verify_signature == organization of the repository actually written to by the handler`

`verify_signature` computes the authenticating organization purely from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` picks the per-organization `webhook_secret` (see the multi-org config documented in `docs/setup.md`) and validates the raw body's HMAC against it via `verify_webhook_signature`, which trivially returns `true` when that organization's `webhook_secret` is blank/unset: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches the *entire, attacker-supplied* JSON body to the handlers unchanged: [4](#0-3) 

But the handlers resolve which `Repository`/`Stack` to mutate using `repository.full_name`, a field never checked against the field used for signature verification: [5](#0-4) [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` looks the repo up purely by the string `owner/name` parsed out of `full_name`, with no cross-check against `repository.owner.login`/the authenticated org: [8](#0-7) 

Concretely, an attacker who controls (or who is simply able to reach, because it is left blank as the docs mark it "optional") the `webhook_secret` for **one** configured GitHub organization ("OrgA") in a multi-org Shipit deployment (see `docs/setup.md` "Using Multiple Github Applications") can POST a JSON body to `/webhooks` where:
- `repository.owner.login = "OrgA"` (or `organization.login = "OrgA"`) → causes `verify_signature` to validate/pass using OrgA's secret (or trivially pass if OrgA's secret is unset),
- `repository.full_name = "OrgB/some-other-tracked-repo"` → causes `PushHandler`, `StatusHandler` (via commit SHA lookup, which is entirely global/unscoped), or the `PullRequest::*Handler`s to act on a stack that belongs to a totally different, unrelated organization (OrgB) that the attacker never authenticated against.

This is a direct instance of the reported bug class: a value used for the security decision (the collateral/authorization check) is not the same value that the subsequent state-changing action actually acts on, allowing action on state the check never covered.

### Impact Explanation
This crosses the "organization authenticated versus repository written" trust boundary explicitly called out as in-scope, and lets an attacker with no privileges on the target organization/repository force Shipit to:
- Trigger `stack.sync_github(expected_head_sha:)` for arbitrary stacks belonging to other organizations (`PushHandler`), affecting deploy/commit sync state,
- Forge CI/commit statuses for arbitrary commits via `StatusHandler`, which looks up `Commit.where(sha: params.sha)` globally with no repository/organization scoping at all,
- Provision, archive, unarchive, or relabel Review Stacks belonging to other organizations' repositories via the `PullRequest::*Handler`s.

This matches the required "Critical" impact category of cross-repository writes / unauthorized action, since the write is performed on a repository/organization that was never the one whose signature validated the request.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (documented and supported feature) where the attacker controls or can access one organization's `webhook_secret` (which, per `docs/setup.md`, is explicitly optional and may be left blank), while other organizations have secrets configured and their repositories are tracked by the same Shipit instance. This is a realistic operational configuration for shared/central Shipit deployments serving many GitHub orgs, and needs no elevated privileges on the target org.

### Recommendation
Bind the same payload field used for signature verification to the field used to resolve the acted-upon repository: after selecting the GitHub App/organization for verification, require that `repository.full_name`'s owner (or `organization.login`) matches the exact organization whose secret validated the signature, and reject the webhook otherwise. Do not let handlers independently re-derive the target repository/organization from unrelated payload fields once verification has already anchored on a specific organization.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (webhook secret left blank/optional per docs) and `OrgB` (secret configured, hosts a tracked, sensitive repository/stack `OrgB/secret-repo`).
2. Attacker (no privileges in OrgB) POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/secret-repo"
  }
}
```
3. `verify_signature` computes `repository_owner = "OrgA"`, loads OrgA's GitHub app config, and `verify_webhook_signature` returns `true` (blank secret case, or attacker knows OrgA's secret).
4. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/secret-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on OrgB's stack — a write the attacker was never authenticated to perform.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L48-54)
```ruby
          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
