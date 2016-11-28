# Use the barebones version of Ruby 2.3.1.
FROM ruby:2.3.1-slim

# Optionally set a maintainer name to let people know who made this image.
MAINTAINER Maria Pilar Guerra Arias <pguerra@redhat.com>

# Install dependencies:
# - build-essential: To ensure certain gems can be compiled
RUN apt-get update && apt-get install -y build-essential net-tools --fix-missing --no-install-recommends 

# Set an environment variable to store where the app is installed to inside
# of the Docker image.
ENV INSTALL_PATH /auth-server
RUN mkdir -p $INSTALL_PATH

# This sets the context of where commands will be ran in and is documented
# on Docker's website extensively.
WORKDIR $INSTALL_PATH

# Ensure gems are cached and only get updated when they change. This will
# drastically increase build times when your gems do not change.
COPY Gemfile Gemfile
RUN bundle install

# Copy in the application code from your work station at the current directory
# over to the working directory.
COPY . .

# Expose a volume so that nginx will be able to read in assets in production.
VOLUME ["$INSTALL_PATH/public"]

# Start server
ENV PORT 3000
EXPOSE 3000
CMD ["ruby", "auth-server.rb"]