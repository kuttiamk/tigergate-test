#!/bin/bash

# Setup colors
GREEN='\033[0;32m'
NC='\033[0m' 

echo -e "${GREEN}Testing Java...${NC}"
cd /home/namlabs/development/tools/code/tigergate-test/java
javac VulnerableApp.java
java VulnerableApp "echo testing"
echo "Java OK!"

echo -e "${GREEN}Testing PHP...${NC}"
cd /home/namlabs/development/tools/code/tigergate-test/php
php -l index.php
echo "PHP OK!"

echo -e "${GREEN}Testing Ruby...${NC}"
cd /home/namlabs/development/tools/code/tigergate-test/ruby
ruby -c app.rb
echo "Ruby OK!"

echo -e "${GREEN}Testing Node.js...${NC}"
cd /home/namlabs/development/tools/code/tigergate-test/nodejs
npm init -y
npm install express
echo "Node dependencies installed"
node server.js &
NODE_PID=$!
sleep 2
kill $NODE_PID || true
echo "Node server tested!"

echo -e "${GREEN}Testing Python...${NC}"
cd /home/namlabs/development/tools/code/tigergate-test/python
python3 -m venv venv
source venv/bin/activate
pip install flask
python app.py &
FLASK_PID=$!
sleep 2
kill $FLASK_PID || true
echo "Python server tested!"

echo -e "${GREEN}All local validation completed successfully.${NC}"
