# =============================================================================
# ruby/app.rb – TigerGate CNAPP Test: Ruby Sinatra Vulnerable Application
# =============================================================================
# PURPOSE: Intentionally vulnerable Sinatra app for SAST + DAST testing.
#
# ⚠️  EDUCATIONAL USE ONLY — Never deploy in production.
#
# VULNERABILITIES COVERED:
#   CWE-78  – OS Command Injection via backtick execution
#   CWE-89  – SQL Injection via string interpolation
#   CWE-918 – SSRF via Net::HTTP.get(URI(url))
#   CWE-502 – Insecure Deserialization via Marshal.load
#   CWE-22  – Path Traversal via File.read(params[:file])
#   CWE-798 – Hardcoded JWT secret + database credentials
#   CWE-94  – eval() with user input
#   CWE-330 – Weak random token generation using rand()
#   CWE-79  – XSS via unescaped user input in HTML response
# =============================================================================

require 'sinatra'
require 'json'
require 'sqlite3'
require 'net/http'
require 'uri'
require 'base64'
require 'digest'

# VULN: CWE-798 – Hardcoded credentials and secrets
# SonarQube Rule: S6418 "Credentials should not be hardcoded"
# FIX: ENV['JWT_SECRET'] or Rails credentials
JWT_SECRET   = 'rubysupersecret123'         # 🔴 Hardcoded JWT secret!
DB_PASSWORD  = 'root123'                    # 🔴 Hardcoded DB password!
API_KEY      = 'sk-ruby-internal-key-9999'  # 🔴 Hardcoded API key!
ADMIN_TOKEN  = 'admin-token-AAAA-BBBB'      # 🔴 Hardcoded admin token!

# VULN: CORS wildcard — accepts requests from any origin
# FIX: Allow only specific origins you control
before do
  headers 'Access-Control-Allow-Origin' => '*'        # 🔴 CORS wildcard!
  headers 'Access-Control-Allow-Methods' => 'GET, POST, PUT, DELETE, OPTIONS'
  content_type :json
end

# Database setup
DB = SQLite3::Database.new('megadb.sqlite')
DB.results_as_hash = true


# =============================================================================
# ENDPOINT 1: GET /exec?cmd=...
# VULN: CWE-78 – OS Command Injection via Ruby backtick operator
# ATTACK: curl "http://localhost:4567/exec?cmd=id"
# ATTACK: curl "http://localhost:4567/exec?cmd=cat+/etc/passwd"
# FIX: Never execute user input as shell commands.
#      Use an allowlist and system(cmd, *args) with separate args (no shell).
# =============================================================================
get '/exec' do
  cmd = params[:cmd] || 'echo hello'
  # 🔴 CRITICAL: Backtick operator passes string to shell — command injection!
  result = `#{cmd}`                                   # 🔴 CWE-78!
  # Also vulnerable: system(cmd), exec(cmd), IO.popen(cmd), %x{cmd}
  { command: cmd, output: result }.to_json
end


# =============================================================================
# ENDPOINT 2: GET /search?q=...
# VULN: CWE-89 – SQL Injection via string interpolation
# ATTACK: curl "http://localhost:4567/search?q=x' OR '1'='1"
# ATTACK: curl "http://localhost:4567/search?q=x' UNION SELECT username,password,3 FROM users--"
# FIX: Use prepared statements: DB.prepare("SELECT * FROM items WHERE name LIKE ?").execute("%#{q}%")
# =============================================================================
get '/search' do
  q = params[:q] || ''
  # 🔴 BAD: String interpolation directly into SQL!
  sql = "SELECT * FROM products WHERE name LIKE '%#{q}%'"   # 🔴 CWE-89!
  begin
    results = DB.execute(sql)
    results.to_json
  rescue SQLite3::Exception => e
    { error: e.message, sql: sql }.to_json   # 🔴 SQL error + query exposed!
  end
end


# =============================================================================
# ENDPOINT 3: GET /user/:id
# VULN: CWE-89 – SQL Injection + IDOR (no authorization check)
# ATTACK: /user/1 OR 1=1 → returns all users
# ATTACK: Any user ID accessible without authentication
# FIX: Parameterized query + verify requester has access to that user
# =============================================================================
get '/user/:id' do
  id = params[:id]
  # 🔴 BAD: SQL injection AND IDOR — no auth check
  sql = "SELECT id, username, email, password, ssn FROM users WHERE id = #{id}" # 🔴 SQLi+IDOR!
  begin
    user = DB.execute(sql).first
    user ? user.to_json : { error: 'Not found' }.to_json
  rescue => e
    { error: e.message }.to_json
  end
end


# =============================================================================
# ENDPOINT 4: POST /login
# VULN: CWE-89 – SQL Injection in authentication
# ATTACK: username = "admin'--" (any password)
# FIX: Prepared statements + bcrypt password verification
# =============================================================================
post '/login' do
  data     = JSON.parse(request.body.read) rescue {}
  username = data['username'] || ''
  password = data['password'] || ''
  # VULN: CWE-327 – MD5 used for password hashing (easily crackable)
  pwd_md5  = Digest::MD5.hexdigest(password)      # 🔴 MD5 is broken for passwords!
  puts "[LOG] Login: user=#{username} password=#{password}"  # 🔴 Password logged!
  # 🔴 CRITICAL: SQL injection in auth!
  sql = "SELECT * FROM users WHERE username='#{username}' AND password='#{pwd_md5}'"  # 🔴 SQLi!
  user = DB.execute(sql).first
  if user
    # VULN: CWE-330 – Weak token generated with rand()
    token = rand(36**32).to_s(36)              # 🔴 Predictable! Use SecureRandom.hex
    { status: 'success', token: token, user: user }.to_json  # 🔴 Returns full user+password!
  else
    halt 401, { status: 'failure' }.to_json
  end
end


# =============================================================================
# ENDPOINT 5: GET /fetch?url=...
# VULN: CWE-918 – Server-Side Request Forgery via Net::HTTP.get
# ATTACK: /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
#         → Steals AWS IAM credentials from instance metadata!
# ATTACK: /fetch?url=http://internal-redis:6379
#         → Reaches internal services
# FIX: Validate URL, deny requests to private/link-local IP ranges
# =============================================================================
get '/fetch' do
  url = params[:url] || ''
  begin
    uri    = URI(url)
    # 🔴 CRITICAL: No validation — fetches any URL including internal/metadata
    result = Net::HTTP.get(uri)                # 🔴 CWE-918 SSRF!
    { url: url, body: result[0..2000] }.to_json
  rescue => e
    { error: e.message }.to_json
  end
end


# =============================================================================
# ENDPOINT 6: POST /deserialize
# VULN: CWE-502 – Insecure Deserialization via Marshal.load
# WHY: Marshal.load executes arbitrary Ruby code embedded in the payload
# ATTACK: Build malicious Marshal payload that runs `system('id')`
# FIX: Never Marshal.load untrusted data. Use JSON.parse with strict schema validation.
# =============================================================================
post '/deserialize' do
  encoded = params[:data] || request.body.read
  begin
    raw = Base64.decode64(encoded)
    # 🔴 CRITICAL: Marshal.load is equivalent to eval() — arbitrary Ruby!
    obj = Marshal.load(raw)                    # 🔴 CWE-502 RCE via Marshal!
    { result: obj.inspect }.to_json
  rescue => e
    { error: e.message }.to_json
  end
end


# =============================================================================
# ENDPOINT 7: GET /file?path=...
# VULN: CWE-22 – Path Traversal via File.read
# ATTACK: /file?path=/etc/passwd
# ATTACK: /file?path=../../.env
# FIX: Use File.expand_path + verify it starts with the allowed base directory
# =============================================================================
get '/file' do
  file_path = params[:path] || 'index.html'
  begin
    # 🔴 CRITICAL: No path restriction — reads any file!
    content = File.read(file_path)             # 🔴 CWE-22 Path Traversal!
    { path: file_path, content: content }.to_json
  rescue => e
    { error: e.message }.to_json
  end
end


# =============================================================================
# ENDPOINT 8: GET /evaluate?code=...
# VULN: CWE-94 – eval() with user input → arbitrary Ruby execution
# ATTACK: /evaluate?code=system('cat /etc/shadow')
# ATTACK: /evaluate?code=require 'open3'; Open3.capture2("id")
# FIX: NEVER eval() user input. Use a math expression parser.
# =============================================================================
get '/evaluate' do
  code = params[:code] || '1 + 1'
  begin
    # 🔴 CRITICAL: eval() executes arbitrary Ruby code!
    result = eval(code)                        # 🔴 CWE-94!
    { expression: code, result: result }.to_json
  rescue => e
    # 🔴 BAD: Full backtrace returned — reveals server file paths and code
    { error: e.message, backtrace: e.backtrace }.to_json  # 🔴 Stack trace exposed!
  end
end


# =============================================================================
# ENDPOINT 9: GET /xss?name=...
# VULN: CWE-79 – Reflected XSS via unescaped output in HTML response
# ATTACK: /xss?name=<script>alert(document.cookie)</script>
# FIX: Use Rack::Utils.escape_html(name) or ERB::Util.html_escape
# =============================================================================
get '/xss' do
  name = params[:name] || 'World'
  content_type 'text/html'
  # 🔴 BAD: User input directly embedded in HTML — XSS!
  "<html><body><h1>Hello, #{name}!</h1></body></html>"  # 🔴 CWE-79 XSS!
end


# =============================================================================
# ENDPOINT 10: GET /admin
# VULN: No authentication on admin endpoint
# Returns all users including hashed passwords
# IDOR: accessible to any user without authorization
# =============================================================================
get '/admin' do
  # 🔴 BAD: No authentication! Anyone can call this!
  puts "[LOG] Admin panel accessed. API_KEY=#{API_KEY} ADMIN_TOKEN=#{ADMIN_TOKEN}" # 🔴 Secrets logged!
  users = DB.execute("SELECT * FROM users")
  {
    admin: true,
    db_password: DB_PASSWORD,        # 🔴 CRITICAL: Returns DB password in API response!
    users: users,                    # 🔴 Returns all users including password hashes
    jwt_secret: JWT_SECRET,          # 🔴 Returns JWT secret!
  }.to_json
end


# =============================================================================
# HANDLE 404 – Information Disclosure
# VULN: CWE-200 – Exposes server technology and Ruby/Sinatra version
# FIX: Return generic "Not Found" without technology details
# =============================================================================
not_found do
  content_type :json
  # 🔴 BAD: Provides tech stack info to attackers
  {
    error:   'Not found',
    server:  "Sinatra #{Sinatra::VERSION}",   # 🔴 Reveals Sinatra version!
    ruby:    RUBY_VERSION,                    # 🔴 Reveals Ruby version!
    path:    request.path_info,               # BAD: Confirms path structure
  }.to_json
end
