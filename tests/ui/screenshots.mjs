// The README screenshots, from the simulated phone (a made-up "Example Phone 12").
//   npm run shots   ->  docs/images/*.png
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { launch } from './browser.mjs';
import { serve } from './server.mjs';

const OUT = fileURLToPath(new URL('../../docs/images/', import.meta.url));
await mkdir(OUT, { recursive: true });
const server = await serve();
const browser = await launch();

async function shoot(name, { colorScheme = 'dark', scenario = '', steps = async () => {} } = {}) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1, colorScheme, locale: 'en-US' });
  const page = await context.newPage();
  await page.goto(`${server.url}?fast${scenario ? `&scenario=${scenario}` : ''}`);
  await page.getByRole('navigation', { name: 'Pages' }).waitFor();
  await steps(page);
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${OUT}${name}.png` });
  await context.close();
  console.log(`docs/images/${name}.png`);
}

const nav = (page, name) => page.getByRole('navigation', { name: 'Pages' }).getByRole('button', { name: new RegExp(`^${name}`) }).click();
const camera = async (page) => {
  await page.getByRole('heading', { name: 'Example Phone 12' }).waitFor();
  await page.getByRole('row', { name: /VID_/ }).first().waitFor();
};

await shoot('phone', {
  steps: async (page) => {
    await camera(page);
    for (const n of [0, 1, 2, 4]) await page.getByRole('row').nth(n + 1).getByRole('checkbox').check();
  },
});
await shoot('review', {
  colorScheme: 'light',
  steps: async (page) => {
    await camera(page);
    await page.getByRole('button', { name: 'Copy everything shown to this PC' }).click();
    await page.getByText(/files? \(.*\) are already there/).waitFor();
  },
});
await shoot('copy', { scenario: 'copying', steps: async (page) => {
  await nav(page, 'Copy');
  await page.getByRole('progressbar').waitFor();
} });
await shoot('history', {
  colorScheme: 'light',
  steps: async (page) => {
    await nav(page, 'History');
    await page.getByRole('button', { name: 'Show the 2 files that were not copied' }).click();
  },
});

await browser.close();
server.close();
