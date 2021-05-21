FROM debian:stable

COPY ci/ /tmp/ci/
RUN /tmp/ci/install-libs.sh
