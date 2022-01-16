# syntax=docker/dockerfile:1

FROM python:3.9-slim-bullseye
ENV TZ UTC

ARG TF_USER_ID=1001
ARG TF_GROUP_ID=1001
ARG http_proxy
ARG https_proxy
ARG ISLAND_API_KEY
ENV http_proxy $http_proxy
ENV https_proxy $https_proxy
ENV THREATFOX_API_KEY $THREATFOX_API_KEY

RUN groupadd threatfox -g $TF_GROUP_ID \
    && useradd -g threatfox -G sudo -m -s /bin/bash -u $TF_USER_ID threatfox

SHELL ["/bin/bash", "-c"]

WORKDIR /SIP-ThreatFox-Collector

# Copy install requirements
COPY --chown=threatfox:threatfox collector/requirements.txt requirements.txt

# Insall the application.
COPY --chown=threatfox:threatfox collector/etc/config.ini etc/config.ini
COPY --chown=threatfox:threatfox collector/etc/logging.ini etc/logging.ini
COPY --chown=threatfox:threatfox collector/sip_threatfox_collector.py .

# the .empty files are so that there is something for the VOLUME command to copy
# so that the right permissions are applied to the mounted volumes
RUN  rm -rf var && mkdir -p var && touch var/.empty \
     && rm -rf error_reports && mkdir -p error_reports && touch error_reports/.empty \
     && rm -rf logs && mkdir -p logs && touch logs/.empty

RUN chown -R threatfox:threatfox /SIP-ThreatFox-Collector/
USER threatfox

# Install python dependancies
RUN python3 -m pip install -r requirements.txt --no-warn-script-location
RUN rm requirements.txt
