### Title
Webhook signature is verified using a GitHub-App secret selected from the *same untrusted payload* that names the repository to act on, allowing a signed payload for one organization to be replayed as an event for a different organization's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body, before the signature has been checked. Every downstream handler (`push`, `pull_request`, `membership`, `status`, etc.) then re-reads repository/organization identifiers from that same body to decide which `Stack`/`Repository`/`Team` to mutate. Because the field used to choose the verification key and the fields used to select the target record are both attacker-supplied and are never cross-checked against each other, an attacker who legitimately controls a webhook secret for *any* one organization configured on the instance (e.g. by installing the Shipit GitHub App on their own org, which `docs/setup.md` explicitly supports multi-tenant-style via `config/secrets.yml`) can forge a payload that is *signed* with that known secret while its `repository`/`organization` fields point at a completely different, victim organization/repository tracked by the same Shipit instance.

### Finding Description
`verify_signature` computes the org used for verification from the raw body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves per-organization configuration (webhook secret, app credentials) as documented for multi-org setups (see `test/dummy/config/secrets_double_github_app.yml`), and `verify_webhook_signature` HMACs the raw body with that org's secret: [3](#0-2) 

Once the signature check passes, `create` re-parses the very same body and hands it to the registered handlers: [4](#0-3) 

The handlers resolve their target purely from payload fields such as `repository.full_name`, `repository.owner.login`, `team.id`, or `member.login` - with no re-validation that these fields are internally consistent with the organization whose secret produced a valid signature: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is: `organization-that-authenticated (secret used to verify HMAC) == organization-that-owns-the-repository/team being written`. Because `repository_owner`/`organization.login` is read from the same untrusted JSON that also supplies `repository.full_name` / `team.id` / `member.login`, an attacker can make these two sides diverge: sign the body with Org A's secret (which they legitimately possess because the App is installed on their own Org A) while setting `repository.full_name` (or `organization.login` for membership events, or `team.id`) to point at Org B's repository/team that is also tracked by the same Shipit instance. `verify_signature` only checks "is this a valid signature for *some* org named in the payload," never "does the org that signed this event actually own the resource the payload claims to modify."

This exactly mirrors the `PoolManager.addTranche()` bug class: `addTranche()` trusted the `poolId`/`trancheId` supplied by the caller without checking they already belonged to a deployed tranche, letting an unprivileged caller overwrite an existing, unrelated tranche's token binding. Here, Shipit trusts the `repository.owner.login`/`organization.login` supplied by the payload to select the verification key, then trusts the *unrelated* `repository.full_name`/`team.id` fields in the same payload to select the record to mutate, without checking the two agree.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary named in scope. Concretely, with a forged, validly-signed-for-Org-A payload that names Org B's repository:
- `push` events can enqueue `GithubSyncJob` for a `Stack` belonging to Org B, forcing unwanted sync/deploy-spec cache activity on a repository the attacker doesn't control - an unauthorized action on another organization's stack.
- `pull_request`/`opened` events can auto-create `ReviewStack`s and trigger provisioning for Org B's repositories.
- `membership` events (`MembershipHandler`) can add an arbitrary GitHub login (attacker-controlled) to a `Team` keyed by `github_id`, and team membership feeds `User#authorized?`, which gates access via `Shipit.github_teams` - i.e., an attacker can escalate into `Shipit.github_teams` authorization for the whole app by forging a membership webhook signed with an org secret they legitimately hold.

This satisfies the "High - escalation into `Shipit.github_teams` authorization" / "unauthorized deploy" impact bar, since it lets a party who only has (legitimate) control over one tenant's webhook secret manipulate state belonging to another tenant of the same Shipit instance.

### Likelihood Explanation
Requires the instance to be configured for multiple GitHub organizations/apps (the officially documented multi-org configuration shown in `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`), and requires the attacker to control (or know) one organization's `webhook_secret` - which is realistic for anyone who can install/configure the Shipit GitHub App on their own org while other, unrelated orgs are also tracked by the same deployment. No GITHUB_TOKEN, session, or ApiClient token is needed - only knowledge of one org's webhook secret, which is a normal artifact of legitimately administering that org's GitHub App installation.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after establishing which organization's secret validated the signature, enforce that every organization/repository-owner field referenced later in the payload (`repository.owner.login`, `organization.login`, and by extension the resources looked up by handlers) matches that same, already-authenticated organization. Concretely, pass the verified `repository_owner` down to handlers and reject/ignore any payload where a handler's resolved `Repository`/`Team`/`Stack` does not belong to that verified owner, analogous to adding the missing "does this resource already belong to someone else" check recommended in the PoolManager fix.

### Proof of Concept
1. Configure Shipit (as per `docs/setup.md`) with two GitHub Apps/orgs, e.g. `OrgA` and `OrgB`, each with its own `webhook_secret`, both trackable by the same Shipit instance (multi-org support demonstrated in `test/dummy/config/secrets_double_github_app.yml`).
2. As the legitimate admin of `OrgA`'s GitHub App installation, obtain `OrgA`'s `webhook_secret`.
3. Craft a `push` (or `membership`) webhook JSON body whose `repository.owner.login`/`organization.login` is `"OrgA"` but whose `repository.full_name` (or `team.id`/`member.login`) references a `Stack`/`Team` belonging to `OrgB`.
4. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgA_webhook_secret, body)` per `Hook::DeliverySigner`/`verify_webhook_signature` in `lib/shipit/github_app.rb`.
5. POST to `/webhooks` (`WebhooksController#create`). `verify_signature` resolves `Shipit.github(organization: "OrgA")`, validates the signature successfully (since it was signed with `OrgA`'s real secret), and the request proceeds.
6. The relevant handler (e.g. `Shipit::Webhooks::Handlers::MembershipHandler` or the push handler feeding `GithubSyncJob`) then acts on the `OrgB` resource named in the payload's `repository`/`team`/`member` fields, mutating state that belongs to `OrgB`, despite the request never being authenticated by `OrgB`'s secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
