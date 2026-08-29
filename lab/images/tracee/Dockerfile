FROM kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1

ARG TRACEE_VERSION=0.22.6
ARG TRACEE_SHA256_X86_64=1a0e6ded27d84a0e5be6f8711ad62e1f1c486497048060119736f0e3907636fd
ARG TRACEE_SHA256_AARCH64=4fc516386cf3899ba575166f9c33814397549ab2296e163e5fb66c940a23b0a5

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
        amd64) tracee_arch="x86_64"; tracee_sha256="$TRACEE_SHA256_X86_64" ;; \
        arm64) tracee_arch="aarch64"; tracee_sha256="$TRACEE_SHA256_AARCH64" ;; \
        *) echo "Unsupported architecture: $arch" && exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/aquasecurity/tracee/releases/download/v${TRACEE_VERSION}/tracee-${tracee_arch}.v${TRACEE_VERSION}.tar.gz" -o /tmp/tracee.tgz \
    && echo "${tracee_sha256}  /tmp/tracee.tgz" | sha256sum -c - \
    && mkdir -p /tmp/tracee-release \
    && tar --no-same-owner -xzf /tmp/tracee.tgz -C /tmp/tracee-release \
    && tracee_binary="$(find /tmp/tracee-release -type f -name tracee -perm -u+x -print -quit)" \
    && test -n "$tracee_binary" \
    && install -m 0755 "$tracee_binary" /usr/local/bin/tracee \
    && rm -rf /tmp/tracee-release /tmp/tracee.tgz

WORKDIR /workspace
CMD ["sleep", "60"]
