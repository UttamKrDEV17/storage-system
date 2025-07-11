# nginx-custom-config/Dockerfile

# Use the official Nginx base image
FROM nginx:latest

# Remove the default Nginx configuration file
# This ensures your custom config is used without conflicts
RUN rm /etc/nginx/conf.d/default.conf

# Copy your custom nginx.conf into the container
# It will replace the default nginx.conf
# Note: The destination is /etc/nginx/nginx.conf, which Nginx reads by default.
COPY ./nginx-conf/nginx.conf /etc/nginx/nginx.conf

# Copy your HTML files into the container
# The destination /app/html must match the 'root' directive in your nginx.conf
COPY ./html/ /app/html

# Expose port 80 to the outside world.
# This is a documentation step, Nginx base image already exposes it.
EXPOSE 80

# Command to run Nginx when the container starts.
# 'daemon off;' keeps Nginx running in the foreground, which is necessary for Docker.
CMD ["nginx", "-g", "daemon off;"]