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

# Copy STIG files and extract them
COPY U_CAN_Ubuntu_22-04_LTS_V2R2_STIG.zip .
RUN mkdir -p benchmarks && \
    unzip U_CAN_Ubuntu_22-04_LTS_V2R2_STIG.zip -d benchmarks/ && \
    chown -R testuser:testuser benchmarks && \
    chmod -R 755 benchmarks

# Copy Python script and requirements
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY stig_scanner.py .
RUN chown testuser:testuser stig_scanner.py requirements.txt

# Switch to non-root user
USER testuser

# Run the scanner
CMD ["python3", "stig_scanner.py"]
