# Use the official Ubuntu 22.04 image as the base
FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and install basic utilities
RUN apt-get update && apt-get install -y \
    sudo \
    python3 \
    python3-pip \
    python3-dev \
    libopenscap8 \
    pkg-config \
    libsystemd-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Create reports directory with proper permissions
RUN mkdir -p reports && \
    chown -R testuser:testuser /app && \
    chmod 777 reports

# Create benchmarks directory with proper permissions
RUN mkdir -p benchmarks && \
    chown -R testuser:testuser benchmarks && \
    chmod -R 755 benchmarks

# Create a directory for STIG files
RUN mkdir -p /app/stig_files && \
    chown -R testuser:testuser /app/stig_files && \
    chmod 755 /app/stig_files

# Copy any STIG zip files from the build context
COPY *.zip /app/stig_files/

# Copy Python script and requirements
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY stig_scanner.py .
RUN chown testuser:testuser stig_scanner.py requirements.txt /app/stig_files/*

# Switch to non-root user
USER testuser

# Set environment variable for STIG files location
ENV STIG_FILES_DIR=/app/stig_files

# Run the scanner
CMD ["python3", "stig_scanner.py"]
