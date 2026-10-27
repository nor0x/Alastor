# syntax=docker/dockerfile:1
# Alastor server image: the dashboard + API, the agent binary it hands out to hosts, and freshclam (from Debian's
# repositories) for the ClamAV signature mirror. Agents still run on the hosts themselves, under systemd.
#
#   docker build -t alastor .
#   docker run -d -p 127.0.0.1:8080:8080 -v alastor-data:/data -e ALASTOR_ADMINPASSWORD=… -e ALASTOR_PUBLICURL=https://… alastor
#
# Build args:
#   WITH_AGENT=false   skip the Native AOT agent build (faster; hosts then download the agent from GitHub releases)
#   VERSION=0.2.0      stamped into both binaries

ARG DOTNET_VERSION=10.0

# ---- 1. dashboard (Svelte SPA) -------------------------------------------------------------------------------------
FROM node:22-bookworm-slim AS web
WORKDIR /src/src/alastor-web
COPY src/alastor-web/package.json src/alastor-web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY src/alastor-web/ ./
# vite writes to ../Alastor.Server/wwwroot
RUN mkdir -p ../Alastor.Server/wwwroot && npm run build

# ---- 2. server and agent (.NET) ------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG WITH_AGENT=true
ARG VERSION=0.1.0
ARG TARGETARCH
# clang + zlib for the agent's Native AOT build.
RUN if [ "$WITH_AGENT" = "true" ]; then apt-get update -q && apt-get install -y -q --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*; fi
WORKDIR /src
COPY Directory.Build.props Alastor.slnx ./
COPY src/Alastor.Core/Alastor.Core.csproj src/Alastor.Core/
COPY src/Alastor.Server/Alastor.Server.csproj src/Alastor.Server/
COPY src/Alastor.Agent/Alastor.Agent.csproj src/Alastor.Agent/
RUN rid=linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64) \
 && dotnet restore src/Alastor.Server -r $rid \
 && if [ "$WITH_AGENT" = "true" ]; then dotnet restore src/Alastor.Agent -r $rid; fi
COPY policy/ policy/
COPY install/ install/
COPY src/ src/
COPY --from=web /src/src/Alastor.Server/wwwroot/ src/Alastor.Server/wwwroot/
RUN rid=linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64) \
 && dotnet publish src/Alastor.Server -c Release -r $rid -p:SkipWebBuild=true -p:Version=$VERSION -o /out/server \
 && mkdir -p /out/server/agent \
 && if [ "$WITH_AGENT" = "true" ]; then \
      dotnet publish src/Alastor.Agent -c Release -r $rid -p:Version=$VERSION -o /out/agent \
      && cp /out/agent/alastor-agent /out/server/agent/alastor-agent-$rid \
      && (cd /out/server/agent && sha256sum alastor-agent-* > SHA256SUMS); \
    fi

# ---- 3. runtime ----------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_VERSION}
# freshclam mirrors ClamAV's signatures for agents (used only once some host has malware.scanSchedule on).
# The package's own update service never runs here: there is no init system, and the server calls freshclam itself.
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends clamav-freshclam ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin alastor \
 && mkdir -p /data && chown alastor:alastor /data
COPY --from=build /out/server/ /app/
# Inside the container every interface is fine: publish the port on the host's loopback (see compose.yaml).
# ALASTOR_DASHBOARDALLOWFROM / ALASTOR_AGENTALLOWFROM default to loopback,private,tailnet.
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 \
    ALASTOR_DATADIR=/data \
    ALASTOR_AGENTDOWNLOADDIR=/app/agent \
    DOTNET_gcServer=0
USER alastor
WORKDIR /data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/app/alastor-server", "healthcheck"]
ENTRYPOINT ["/app/alastor-server"]
