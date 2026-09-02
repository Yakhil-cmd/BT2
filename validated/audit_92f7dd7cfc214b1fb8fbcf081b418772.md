### Title
Scoped ApiClient tokens bypass stack authorization in CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly from `Stack.from_param!(params[:stack_id])` instead of going through the `ApiClient`-scoped `stacks`/`stack` resolution used everywhere else in the API namespace. This breaks the binding "the stack a token authorizes" == "the stack the endpoint touches," letting a token scoped to one stack read the deploy status of any other stack.

### Finding Description
Every other controller inheriting from `Shipit::Api::BaseController` resolves the target stack through the token-scoped relation: [1](#0-0) 

`current_api_client.stack_id?` gates the `stacks` relation to the single `Stack` the `ApiClient` record's `belongs_to :stack, optional: true` association points to (see `ApiClient` model), and `stack` (used by `OutputsController`, `Api::StacksController`, etc.) is derived from that relation: [2](#0-1) 

This scoping is a real, tested authorization control — `stacks_controller_test.rb` explicitly asserts "an api client scoped to a stack will only see that one stack" using the `here_come_the_walrus` fixture client: [3](#0-2) 

However, `CCMenuController` overrides `stack` to bypass this relation entirely and query the unscoped `Stack` table: [4](#0-3) 

`require_permission :read, :stack` only checks that `"read:stack"` is present in `current_api_client.permissions` — a global boolean, not a check on which stack ID the permission applies to: [5](#0-4) 

So any valid `ApiClient` token that carries `read:stack` (including a token whose `stack_id` restricts it to Stack A) can be replayed against `GET /api/*stack_id/ccmenu?token=...` with any other stack's identifier in `stack_id` and successfully render that stack's CCTray XML — an authorization boundary ("token authorizes stack A" vs. "endpoint touches stack B") is broken.

### Impact Explanation
The leaked `project.xml.builder` view discloses deploy/build state for the targeted stack — `lastBuildStatus` (merge status), `activity` (running/sleeping), `lastBuildTime`, `lastBuildLabel` (deploy id), and `webUrl`: [6](#0-5) 

This is an unauthorized read of stack/deploy state for a stack outside the presenting token's granted scope, matching the "escalation into ... unauthenticated read of stack state, task streams or deploy output" High-impact category — the scoping mechanism that is supposed to confine a token to one stack is defeated for this specific endpoint.

### Likelihood Explanation
Exploitation requires possession of any valid `ApiClient` token with `read:stack` permission (no special privilege beyond a legitimately issued scoped token, e.g. one meant only for a single stack's CI/CD integration). No signature or session is forged; the attacker simply supplies a different `stack_id` in the URL than the one the token was scoped for. Given `read:stack` is the least-privileged permission and scoped tokens are an explicit, documented/tested feature (`api_client.rb`, `stacks_controller_test.rb`), this is a straightforward misuse path for anyone holding such a token.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the same `stacks` (or equivalent scoped) relation as `BaseController`, e.g. `stacks.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` cannot be used to query stacks outside its `stack_id` binding. Apply the same scoped lookup in `CCMenuUrlController` if scoped tokens are ever introduced there.

### Proof of Concept
1. Admin/integration issues (or the DB already contains, per fixtures) an `ApiClient` with `stack_id = <Stack A>.id` and `permissions = ["read:stack"]`, and mints its token via `authentication_token`.
2. Attacker (or the legitimate holder of that scoped token) requests:
   `GET /api/<stack_B_owner>/<stack_B_repo>/<stack_B_env>/ccmenu?token=<token_scoped_to_stack_A>`
3. `authenticate_api_client` in `BaseController` succeeds (token is valid). `require_permission :read, :stack` passes (`"read:stack"` is present). `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` on Stack B directly, ignoring `current_api_client.stack_id`.
4. Response renders Stack B's deploy status (`lastBuildStatus`, `activity`, `lastBuildLabel`, `webUrl`), even though the token was only meant to authorize reads on Stack A — confirming the binding "token's authorized stack" ≠ "stack actually touched."

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L4-21)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
```

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/views/shipit/ccmenu/project.xml.builder (L6-15)
```text
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
```
