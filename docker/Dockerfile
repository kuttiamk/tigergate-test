# Vulnerability 1: Using an outdated, vulnerable base image
FROM node:10-alpine 

# Vulnerability 2: Hardcoded secrets in build instructions
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerability 3: Running as root user (lack of User directive)
WORKDIR /app
COPY . .

RUN npm install

# Expose port and start
EXPOSE 3000
CMD ["node", "server.js"]
