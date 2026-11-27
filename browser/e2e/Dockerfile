# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# make browser-e2e: the specs, Chromium and the harness (built for linux by
# the target, in e2e/.harness/linux) in one container, so the run is the
# same on a Mac and on the Linux runner (whose image has no Chromium libs).
FROM mcr.microsoft.com/playwright:v1.56.1-noble
WORKDIR /w
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY dist dist
COPY e2e e2e
ENV NF1_HARNESS=/w/e2e/.harness/linux/harness
CMD ["./node_modules/.bin/playwright", "test", "-c", "e2e/playwright.config.ts"]
