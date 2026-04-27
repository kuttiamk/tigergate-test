# =============================================================================
# vulnerable-php/Dockerfile
# =============================================================================
# PURPOSE: Builds the PHP app using Apache web server.
#
# ⚠️  INTENTIONAL ISSUES:
#   1. BAD: php:7.4-apache — PHP 7.4 is EOL (end-of-life, many known CVEs)
#   2. BAD: Running as root
#   3. BAD: display_errors=On leaks errors to browser
#   4. BAD: No security headers configured
# =============================================================================

# BAD: PHP 7.4 is EOL. Should use php:8.2-apache
FROM php:7.4-apache

# BAD: display_errors ON in production — shows PHP errors to users
RUN echo "display_errors = On" >> /usr/local/etc/php/php.ini         # BAD!
RUN echo "error_reporting = E_ALL" >> /usr/local/etc/php/php.ini     # BAD: Too verbose!
RUN echo "expose_php = On" >> /usr/local/etc/php/php.ini             # BAD: Shows PHP version in headers!

# Install MySQL extension
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copy app files — BAD: No file permission restriction
COPY . /var/www/html/

# BAD: Creates upload dir with 777 permissions (world-writable!)
RUN mkdir -p /tmp/uploads && chmod 777 /tmp/uploads                   # BAD: World writable!

EXPOSE 80

# BAD: Runs Apache as root
CMD ["apache2-foreground"]
