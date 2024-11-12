# Use an official PHP runtime as a parent image
FROM php:8.1-apache

# Set working directory
WORKDIR /var/www/html

# Copy the current directory contents into the container at /var/www/html
COPY . /var/www/html

# Install PHP extensions if needed
# Uncomment and add any necessary extensions here based on your app requirements
# RUN docker-php-ext-install mysqli pdo pdo_mysql

# Update permissions to ensure Apache can serve files correctly
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Expose port 80 to the outside world
EXPOSE 80

# Start Apache in the foreground (default behavior)
CMD ["apache2-foreground"]
