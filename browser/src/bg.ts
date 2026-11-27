// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// The toolbar button opens the extension's page (Chrome and Firefox both
// answer to chrome.*).
declare const chrome: { action: { onClicked: { addListener(f: () => void): void } }; tabs: { create(o: { url: string }): void } };
chrome.action.onClicked.addListener(() => chrome.tabs.create({ url: "open.html" }));
