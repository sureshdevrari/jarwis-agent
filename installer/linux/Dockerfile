# Dockerfile for building Jarwis Agent Linux packages
# Usage: docker build -t jarwis-linux-builder . && docker run -v $(pwd)/../../dist:/dist jarwis-linux-builder

FROM python:3.11-slim-bookworm

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ruby \
    ruby-dev \
    rpm \
    dpkg-dev \
    && gem install fpm --no-document \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the entire project
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir pyinstaller

# Install project dependencies
RUN pip install --no-cache-dir -r requirements.txt || true

# Build script
COPY installer/linux/docker-build.sh /build.sh
RUN chmod +x /build.sh

# Output directory
VOLUME /dist

CMD ["/build.sh"]
