FROM kalilinux/kali-rolling:2026.1

ARG TRACEE_VERSION=0.22.2

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        iproute2 \
        jq \
        procps \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
        amd64) tracee_arch="x86_64" ;; \
        arm64) tracee_arch="arm64" ;; \
        *) echo "Unsupported architecture: $arch" && exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/aquasecurity/tracee/releases/download/v${TRACEE_VERSION}/tracee_${TRACEE_VERSION}_linux_${tracee_arch}.tar.gz" -o /tmp/tracee.tgz \
    && tar -xzf /tmp/tracee.tgz -C /tmp \
    && install -m 0755 /tmp/tracee/tracee /usr/local/bin/tracee \
    && rm -rf /tmp/tracee /tmp/tracee.tgz

WORKDIR /workspace
CMD ["sleep", "60"]
