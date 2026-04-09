require 'sinatra'

# Vulnerability 1: Remote Code Execution / Command Injection
get '/exec' do
  cmd = params[:cmd]
  # Flaw: Executing commands straight from user input
  result = `#{cmd}`
  "Command output: #{result}"
end

# Vulnerability 2: SQL Injection
get '/search' do
  query = params[:q]
  # Assuming form of database interface where this is unsafe
  # Flaw: Unsafe string interpolation in SQL
  results = db.execute("SELECT * FROM items WHERE name = '#{query}'")
  results.to_json
end
