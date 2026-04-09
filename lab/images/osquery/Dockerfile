FROM kalilinux/kali-rolling:2026.1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -d /etc/apt/keyrings \
    && curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /etc/apt/keyrings/osquery.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends osquery \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace && chmod 0777 /workspace

WORKDIR /workspace

CMD ["sleep", "600"]
