### Title
Webhook signature verification is keyed by an unverified `repository.owner.login`/`organization.login` field, decoupling the authenticated organization from the repository the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify the HMAC signature against by reading `repository_owner`, which is extracted from the **unverified** JSON body, before the signature has been checked. [1](#0-0) [2](#0-1)  Handlers then act on a *different* field of the same unverified body — `repository.full_name` — to look up the `Stack`/`Repository` to sync, archive, or label. [3](#0-2) [4](#0-3) 

### Finding Description
In a multi-organization Shipit deployment (a documented, supported configuration where `secrets.github` has one sub-config per organization, each with its own optional `webhook_secret`), `Shipit.github_app_config(organization)` picks the app config by looking up the organization name in `secrets.github`. [5](#0-4)  `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is not configured for the selected org: `return true unless webhook_secret`. [6](#0-5) 

The binding that should hold is: *the organization whose secret authenticates the request* == *the organization owning the repository the payload will mutate*. In `WebhooksController`, the org used to select the verification secret is `params.dig('repository','owner','login') || params.dig('organization','login')` — read straight out of the unverified `raw_post` before any cryptographic check. [2](#0-1)  The org that ends up being *acted on* is derived independently, from `payload.dig('repository', 'full_name')` in `Handler#repository_name`/`#stacks`, and used to resolve a `Repository`/`Stack` via `Repository.from_github_repo_name`, which parses `owner/name` straight out of that same string. [3](#0-2) [7](#0-6)  There is no code anywhere that asserts `repository.owner.login == repository.full_name.split('/').first`, nor that the app selected via `repository_owner` is the one that legitimately owns `full_name`.

If any one organization configured on the instance has no `webhook_secret` set (the setup docs explicitly call it "optional"), an unauthenticated attacker can send a POST to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) set to that unsecured organization, so `verify_signature` selects the `GitHubApp` whose `verify_webhook_signature` always returns `true`,
- `repository.full_name` set to `"<victim-org>/<victim-repo>"`, an entirely different, secured organization's repository.

The signature check passes unconditionally (no secret to validate against), yet the handler dispatch (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) operates on the attacker-chosen `repository.full_name`, driving `PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc. against the victim repository's stacks with a forged `after` SHA / labels / PR state. [8](#0-7) [4](#0-3) [9](#0-8) 

### Impact Explanation
This is a cross-repository/cross-organization write: an unprivileged, unauthenticated internet requester can trigger `stack.sync_github(expected_head_sha: params.after)` on a victim's tracked stack, forcing Shipit to fast-forward its idea of the deployable HEAD to an attacker-chosen SHA (`PushHandler`), or manipulate review-stack provisioning/archival via `PullRequest` handlers on repositories the attacker has no access to — all without holding any GitHub credential, `ApiClient` token, or webhook secret for the victim organization. This matches the Critical bucket "unauthorized deploy... or cross-repository writes" since the attacker controls which stack's sync/deploy pipeline gets driven while borrowing a different organization's (unsecured) trust.

### Likelihood Explanation
Exploitability is fully conditioned on the specific deployment having at least two GitHub organizations configured under `secrets.github`, with at least one of them lacking a `webhook_secret`. That is a documented, supported topology (`docs/setup.md` "Using Multiple Github Applications") and `webhook_secret` is explicitly called "optional" in the App-creation instructions, so this is not a case of the host application deviating from documented setup — it is the intersection of two individually-documented, supported features (multi-org support + optional webhook secret) producing an unintended cross-org trust break. However, real-world likelihood depends on an operator actually leaving one org's secret unset while relying on another org's, which cannot be verified from the engine code alone.

### Recommendation
After signature verification succeeds, re-derive the organization from the verified payload's `repository.full_name` (not `repository.owner.login`/`organization.login`) and assert it matches the organization whose secret validated the signature before dispatching to handlers. Alternatively, require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and/or bind handler `repository_name` resolution to the same organization used for signature verification.

### Proof of Concept
Given `secrets.github` configured with two orgs, `secured-org` (has `webhook_secret`) and `open-org` (no `webhook_secret`):

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # not checked because open-org has no secret

{
  "ref": "refs/heads/master",
  "after": "deadbeefattackerchosen",
  "repository": {
    "owner": { "login": "open-org" },
    "full_name": "secured-org/victim-repo"
  }
}
```
`verify_signature` computes `repository_owner == "open-org"`, loads that org's `GitHubApp`, and `verify_webhook_signature` returns `true` unconditionally since `webhook_secret` is blank. [1](#0-0) [6](#0-5)  `PushHandler#process` then resolves stacks via `Repository.from_github_repo_name("secured-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeefattackerchosen")` on the victim org's stack — despite the request never being validated against `secured-org`'s secret. [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
