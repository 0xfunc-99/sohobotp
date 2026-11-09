FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && apt-get update -qq && apt-get install -y -qq --no-install-recommends wine wine64 xvfb xdotool imagemagick x11-utils procps >/dev/null && rm -rf /var/lib/apt/lists/*
