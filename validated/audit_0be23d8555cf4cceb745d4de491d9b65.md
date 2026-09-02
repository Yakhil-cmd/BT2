### Title
Webhook signature verification binds to `repository.owner.login`, but the target Stack is resolved from the unverified `repository.full_name` field, allowing cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's GitHub App/`webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but every event handler resolves the actual `Repository`/`Stack` to act on from the independent `repository.full_name` field. The HMAC only proves the raw body was signed with *some* configured organization's secret — it never proves that `repository.owner.login` and `repository.full_name` refer to the same repository/organization.

### Finding Description
`verify_signature` picks the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns a per-organization `GitHubApp` instance, each holding its own `webhook_secret`, and verification is a plain HMAC-sha1 comparison of the raw body against that org's secret: [3](#0-2) [4](#0-3) 

Once the signature passes, every handler determines which repository/stack to act on from a *different* field of the same JSON body — `repository.full_name` — with no cross-check against `repository.owner.login`: [5](#0-4) [6](#0-5) 

`PushHandler`, for example, uses that repository resolution to enqueue a sync against whatever stacks match, using an attacker-controlled `after` SHA: [7](#0-6) 

Because `repository.owner.login` (used to select the signing secret) and `repository.full_name` (used to select the acted-upon repository) are two independent JSON keys, an attacker who is an administrator of one organization onboarded into a shared/multi-tenant Shipit instance — and therefore legitimately knows that organization's own `webhook_secret` — can hand-craft a POST body where `repository.owner.login` is set to their own organization (so `verify_signature` looks up and validates against a secret they know) while `repository.full_name` names an entirely different organization's repository. The signature check passes even though the acted-upon repository was never authenticated by that signature.

### Impact Explanation
This breaks the equality the engine implicitly relies on: `organization authenticated by verify_signature == organization whose repository is written`. An attacker who controls only their own onboarded organization can force `GithubSyncJob`/`stack.sync_github` to run against another organization's `Stack` with an attacker-chosen `after` SHA, and (for `pull_request` handlers) can similarly manipulate archive/unarchive/label-capture logic on foreign review stacks. If the victim stack has continuous deployment enabled, this can trigger deploys of attacker-influenced state on a stack the attacker was never authorized to touch — a cross-organization, cross-repository write that was never covered by the signature that authorized the request.

### Likelihood Explanation
Exploitability requires the Shipit instance to serve more than one GitHub organization each with its own `webhook_secret` (supported via `Shipit.github(organization:)` and the `GithubOrganizationUnknown` rescue path in the controller). Given that precondition, no special privilege beyond ordinary admin control of one onboarded org is needed — the attacker crafts a raw HTTP POST directly (not routed through GitHub) with a body they fully control and a signature computed with their own known secret.

### Recommendation
Cross-validate that the organization used to select the signing secret matches the owner encoded in `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers, or select/resolve the target `Repository` using the same field that was used to compute/verify the signature.

### Proof of Concept
1. Attacker administers `attacker-org`, onboarded into a shared Shipit instance with its own configured `webhook_secret`.
2. Attacker computes `sha1=HMAC(webhook_secret_attacker, body)` over a hand-crafted JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. POST to `/webhooks` (`WebhooksController#create`) with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` and validates the signature successfully [1](#0-0) .
5. `PushHandler` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues sync/deploy activity on the victim's `Stack` using the attacker-supplied `after` SHA [8](#0-7) .

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-61)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
