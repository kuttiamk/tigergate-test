# Outdated image vulnerable to multiple CVEs
FROM tomcat:8.0.36-jre8

USER root
# Hardcoded credentials in CWPP host container
ENV DB_PASS="root_password_123"

# Expose admin port explicitly
EXPOSE 8080
CMD ["catalina.sh", "run"]
