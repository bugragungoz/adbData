// The built interface in Chromium against the simulated phone (src/api/mock.ts): every page opens
// without an error, browsing and filters work, nothing is copied before the review, a copy lands in
// History, copying a folder again skips what is there, options re-plan, a copy can be stopped,
// files can be sent to the phone, adb can be downloaded, and the smallest window has no sideways
// scroll.
//   npm run test:ui   (builds first; CHROMIUM_PATH picks a browser when Playwright finds none)
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { launch } from './browser.mjs';
import { serve } from './server.mjs';

let server;
let browser;

before(async () => {
  server = await serve();
  browser = await launch();
});
after(async () => {
  await browser?.close();
  server?.close();
});

async function open({ scenario, width = 1280, height = 800, locale = 'en-US', colorScheme = 'dark', ready = true } = {}) {
  const context = await browser.newContext({ viewport: { width, height }, locale, colorScheme });
  const page = await context.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') problems.push(m.text());
  });
  page.on('response', (r) => {
    if (r.status() >= 400) problems.push(`${r.status()} ${r.url()}`);
  });
  await page.goto(`${server.url}?fast${scenario ? `&scenario=${scenario}` : ''}`);
  await page.getByRole('navigation', { name: /^(Pages|Sayfalar)$/ }).waitFor();
  if (ready) await page.getByRole('row', { name: /IMG_/ }).first().waitFor();
  return { page, context, problems };
}

const nav = (page, name) => page.getByRole('navigation', { name: /^(Pages|Sayfalar)$/ }).getByRole('button', { name: new RegExp(`^${name}`) }).click();
const dialog = (page) => page.getByRole('dialog');
const historyCount = async (page) => Number((await page.getByRole('navigation', { name: 'Pages' }).getByRole('button', { name: /^History/ }).textContent()).replace(/\D/g, '') || 0);

test('every page opens without an error', async () => {
  const { page, context, problems } = await open();
  await page.getByRole('heading', { name: 'Example Phone 12' }).waitFor();
  for (const [name, heading] of [
    ['Copy', 'Copy'],
    ['History', 'History'],
    ['Settings', 'Settings'],
  ]) {
    await nav(page, name);
    await page.getByRole('heading', { name: heading, exact: true }).waitFor();
  }
  await nav(page, 'Phone');
  await page.getByRole('heading', { name: 'Example Phone 12' }).waitFor();
  assert.deepEqual(problems, []);
  await context.close();
});

test('browsing: places, folders, the breadcrumb, kinds and hidden files', async () => {
  const { page, context } = await open();
  // The phone opens at the camera folder; its trashed photo is hidden.
  await page.getByText('148 items').waitFor();
  assert.equal(await page.getByRole('row', { name: /trashed/ }).count(), 0);
  // Only videos.
  await page.getByRole('button', { name: 'Videos', exact: true }).click();
  await page.getByText('13 items').waitFor();
  assert.equal(await page.getByRole('row', { name: /IMG_/ }).count(), 0);
  await page.getByRole('button', { name: 'Videos', exact: true }).click();
  // Up to DCIM through the breadcrumb, then into a place.
  await page.getByRole('navigation', { name: 'Folder' }).getByRole('button', { name: 'DCIM' }).click();
  await page.getByRole('row', { name: /Camera/ }).waitFor();
  await page.getByRole('navigation', { name: 'Places on the phone' }).getByRole('button', { name: 'Documents' }).click();
  await page.getByRole('row', { name: /Devre Analizi Ödev 3\.pdf/ }).waitFor();
  await page.getByRole('button', { name: 'Up one folder' }).click();
  await page.getByRole('row', { name: /Download/ }).waitFor();
  // Hidden files appear when the setting says so.
  await nav(page, 'Settings');
  await page.getByRole('switch', { name: 'Show hidden files' }).click();
  await nav(page, 'Phone');
  await page.getByRole('navigation', { name: 'Places on the phone' }).getByRole('button', { name: 'Camera' }).click();
  await page.getByRole('row', { name: /trashed/ }).waitFor();
  await context.close();
});

test('nothing is copied before the review, and a copy lands in History', async () => {
  const { page, context } = await open();
  const before = await historyCount(page);
  await page.getByRole('navigation', { name: 'Places on the phone' }).getByRole('button', { name: 'Screenshots' }).click();
  await page.getByRole('row', { name: /Screenshot_/ }).first().waitFor();
  await page.getByRole('row').nth(1).getByRole('checkbox').check();
  await page.getByRole('row').nth(2).getByRole('checkbox').check();
  await page.getByText('2 selected').waitFor();
  await page.getByRole('button', { name: 'Copy to this PC' }).click();
  await dialog(page).getByText(/^2 files, /).waitFor();
  await dialog(page).getByRole('button', { name: 'Cancel' }).click();
  assert.equal(await historyCount(page), before, 'cancelling copies nothing');

  await page.getByRole('button', { name: 'Copy to this PC' }).click();
  await dialog(page).getByRole('button', { name: 'Start copying 2 files' }).click();
  await page.getByRole('heading', { name: 'Copied to this PC' }).waitFor();
  await page.getByText('Done', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Show the folder' }).waitFor();
  assert.equal(await historyCount(page), before + 1);
  await nav(page, 'History');
  await page.getByRole('listitem').filter({ hasText: 'From Example Phone 12 to this PC' }).first().getByText(/2 files/).waitFor();
  await context.close();
});

test('copying a folder again skips what is there, and options re-plan', async () => {
  const { page, context } = await open();
  await page.getByRole('button', { name: 'Copy everything shown to this PC' }).click();
  await dialog(page).getByText('90 files (2.3 GB) are already there and are skipped.').waitFor();
  await dialog(page).getByText(/^58 files, /).waitFor();
  // Keep both copies every file again.
  await dialog(page).getByRole('radio', { name: 'Keep both' }).click();
  await dialog(page).getByText(/^148 files, /).waitFor();
  assert.equal(await dialog(page).getByText(/are already there and are skipped/).count(), 0);
  await dialog(page).getByRole('radio', { name: 'Skip files already there' }).click();
  await dialog(page).getByRole('button', { name: 'Start copying 58 files' }).click();
  await page.getByText('Done', { exact: true }).waitFor();
  // Everything is on the PC now.
  await nav(page, 'Phone');
  await page.getByRole('button', { name: 'Copy everything shown to this PC' }).click();
  await dialog(page).getByText('Nothing to copy: everything is already there.').waitFor();
  assert.equal(await dialog(page).getByRole('button', { name: 'Nothing to copy' }).isDisabled(), true);
  await context.close();
});

test('the destination can be changed for one copy', async () => {
  const { page, context } = await open();
  await page.evaluate(() => {
    window.__adbdataPickFolder = 'E:\\Yedek\\Telefon';
  });
  await page.getByRole('row').nth(1).getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Copy to this PC' }).click();
  await dialog(page).getByText('C:\\Users\\Bugra\\Desktop\\adbData').waitFor();
  await dialog(page).getByRole('button', { name: 'Change' }).click();
  await dialog(page).getByText('E:\\Yedek\\Telefon').waitFor();
  await context.close();
});

test('a running copy can be stopped', async () => {
  const { page, context } = await open({ scenario: 'copying' });
  await nav(page, 'Copy');
  await page.getByRole('progressbar').waitFor();
  await page.getByRole('main').getByText('42%').waitFor();
  await page.getByRole('button', { name: 'Stop' }).click();
  await page.getByText('Stopped', { exact: true }).waitFor();
  await context.close();
});

test('files are sent to the folder shown', async () => {
  const { page, context } = await open();
  await page.getByRole('navigation', { name: 'Places on the phone' }).getByRole('button', { name: 'Music' }).click();
  await page.getByRole('row', { name: /Recordings/ }).waitFor();
  await page.evaluate(() => {
    window.__adbdataPickFiles = ['C:\\Users\\Bugra\\Music\\Şarkı 1.mp3', 'C:\\Users\\Bugra\\Music\\Şarkı 2.mp3'];
  });
  await page.getByRole('button', { name: 'Send files here' }).click();
  await dialog(page).getByRole('heading', { name: 'Send to the phone' }).waitFor();
  await dialog(page).getByText('/sdcard/Music').waitFor();
  await dialog(page).getByRole('button', { name: 'Start copying 2 files' }).click();
  await page.getByRole('heading', { name: 'Sent to the phone' }).waitFor();
  await page.getByRole('button', { name: 'Back to the phone' }).click();
  await page.getByRole('button', { name: 'Read the folder again' }).click();
  await page.getByRole('row', { name: /Şarkı 2\.mp3/ }).waitFor();
  await context.close();
});

test('without adb it offers to download platform-tools', async () => {
  const { page, context } = await open({ scenario: 'noadb', ready: false });
  await page.getByRole('heading', { name: 'adbData needs adb' }).waitFor();
  await page.getByRole('button', { name: 'Download platform-tools' }).click();
  await page.getByText('adb 36.0.0 is ready.').waitFor();
  await page.getByRole('heading', { name: 'Example Phone 12' }).waitFor();
  await context.close();
});

test('a phone that has not allowed this computer says what to do', async () => {
  const { page, context } = await open({ scenario: 'unauthorized', ready: false });
  await page.getByText('Allow USB debugging on the phone').waitFor();
  await page.getByRole('heading', { name: 'Connect your phone' }).waitFor();
  await context.close();
});

test('the default for files already there is kept', async () => {
  const { page, context } = await open();
  await nav(page, 'Settings');
  await page.getByRole('radio', { name: 'Keep both' }).click();
  await nav(page, 'Phone');
  await page.getByRole('row').nth(1).getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Copy to this PC' }).click();
  assert.equal(await dialog(page).getByRole('radio', { name: 'Keep both' }).getAttribute('aria-checked'), 'true');
  await context.close();
});

test('the interface speaks Turkish', async () => {
  const { page, context } = await open({ locale: 'tr-TR' });
  await page.getByRole('button', { name: 'Gösterilen her şeyi bu bilgisayara kopyala' }).waitFor();
  await page.getByRole('navigation', { name: 'Sayfalar' }).getByRole('button', { name: /^Geçmiş/ }).click();
  await page.getByRole('heading', { name: 'Geçmiş', exact: true }).waitFor();
  await context.close();
});

test('the smallest window has no sideways scroll', async () => {
  const { page, context } = await open({ width: 960, height: 620 });
  for (const name of ['Phone', 'Copy', 'History', 'Settings']) {
    await nav(page, name);
    await page.waitForTimeout(150);
    const wide = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    assert.equal(wide, false, name);
  }
  await context.close();
});
