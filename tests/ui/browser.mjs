// Starts Chromium for the UI tests: the one Playwright finds, or CHROMIUM_PATH.
import { chromium } from 'playwright-core';

export async function launch() {
  const executablePath = process.env.CHROMIUM_PATH || undefined;
  return chromium.launch({ executablePath, args: ['--font-render-hinting=none'] });
}
