### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but every handler acts on `repository.full_name` — allowing cross-repository status/commit spoofing - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC using `repository_owner` (`repository.owner.login`, falling back to `organization.login`), while every `Shipit::Webhooks::Handlers::Handler` subclass resolves the target `Stack`/`Repository` using a *different* field of the same attacker-controlled JSON body: `repository.full_name`. These two fields are never checked for consistency, so a signature that is valid for organization A can be delivered with a `repository.full_name` pointing at a stack owned by organization B.

### Finding Description
`verify_signature` picks the secret purely from `repository.owner.login`/`organization.login`: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GithubApp` instance configured for that specific organization, whose `verify_webhook_signature` HMACs the *entire raw body* with that organization's own `webhook_secret`: [3](#0-2) 

Because the HMAC covers the whole raw JSON body, an attacker who legitimately owns/administers a repository under organization "attacker-org" (and therefore knows or controls "attacker-org"'s webhook secret, e.g. by configuring the webhook on their own repo) can craft an arbitrary payload — including a `repository.full_name` referring to a repository under a *different* organization — sign it with "attacker-org"'s secret, and send it to Shipit's webhook endpoint. `verify_signature` will look up `repository.owner.login == "attacker-org"`, fetch attacker-org's `GithubApp`, and successfully verify the signature, because the signature was computed with that same secret over that same body.

Downstream, every handler ignores `repository.owner.login` entirely and instead resolves the affected `Stack` via `repository.full_name`: [4](#0-3) 
`Repository.from_github_repo_name` splits `owner/name` straight out of this attacker-controlled `full_name` string and looks up the actual `Repository` record, with no relation to the organization used for signature verification: [5](#0-4) 

This is exactly the "userCode not updated" class of bug generalized to this codebase: one field (`repository.owner.login`) is the field the signature-verification trust decision is bound to, while a different field (`repository.full_name`) is the field actually acted upon — breaking the equality `verified_organization == acted_upon_repository.owner` that the security model implicitly assumes.

Concretely, `PushHandler` and `StatusHandler` both use `stacks`/`repository_name` from `handler.rb`, meaning an attacker with a validly-signed webhook for their own organization can: [6](#0-5) [7](#0-6) 
- Forge a `push` event that sets `repository.full_name` to a victim stack and triggers `stack.sync_github(expected_head_sha: ...)`, forcing Shipit to sync to an attacker-chosen SHA on the victim's tracked branch.
- Forge a `status` event with `repository.full_name` pointing at the victim's repo and an arbitrary `sha`, injecting fabricated commit statuses (`state`, `description`, `target_url`, `context`) onto the victim's commits via `Commit#create_status_from_github!`, which can flip deployability/merge gating (e.g., turn a failing CI check "green").

### Impact Explanation
Fabricated commit statuses can satisfy Shipit's deploy/merge-gating checks on a victim stack, and forged push/sync events can force syncing to an attacker-chosen SHA — both are cross-organization/cross-repository writes that influence "unauthorized deploy" gating logic, matching the in-scope High-severity impact category (escalation causing an unauthorized deploy via manipulated commit status / cross-repository writes to victim stack state), achieved purely by an attacker who only controls their own organization's webhook secret/repository — no session, `ApiClient` token, or victim credentials required.

### Likelihood Explanation
Likelihood is significant for any Shipit deployment serving multiple GitHub organizations, since the whole trust check is a single field mismatch: the attacker needs only to register/administer one repository (in any organization onboarded to this Shipit instance) capable of delivering GitHub webhooks with a secret they control, then substitute `repository.full_name` while keeping `repository.owner.login`/`organization.login` as their own org. No special privileges on the victim org are required.

### Recommendation
In `verify_signature`, after verifying the HMAC, additionally assert that the organization used to select the secret (`repository.owner.login`/`organization.login`) matches the owner segment parsed from `repository.full_name` (and, for handlers that resolve a `Stack` via `Repository.from_github_repo_name`, re-validate that the resolved `Repository#owner` equals the organization the signature was verified against) before dispatching to any handler. Reject the request (422) on mismatch.

### Proof of Concept
1. Shipit instance has two configured GitHub orgs: `attacker-org` (attacker administers a repo there and knows/controls its webhook secret) and `victim-org` (has a Shipit `Stack` tracking `victim-org/victim-repo`).
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs it to Shipit's `/github/webhooks`.
4. `WebhooksController#verify_signature` resolves `repository_owner == "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check passes because attacker signed with that same secret over the same raw body. [1](#0-0) 
5. `StatusHandler#process` runs, using `repository.full_name` ("victim-org/victim-repo") via `Handler#stacks`/`#repository_name` to locate the victim's commit and inject a fabricated `success` status, unaffiliated with the organization whose secret actually authenticated the request. [4](#0-3) [7](#0-6)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
