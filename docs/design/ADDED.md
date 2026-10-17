# What adbData adds to Bugra

Bugra was drawn for a website. adbData reuses its tokens, fonts and components (copied from the
owner's component-inventory app through netSwitch and adbDebloat) and adds the pieces a file copier
for a phone needs. Each one is built from Bugra tokens and shapes and is marked "(added)" in the
code. No color is added: every color comes from `src/styles/tokens.css`, which
`npm run check:colors` enforces.

## Components

| Piece | Where | Notes |
|---|---|---|
| Button `quiet` and `danger` | `components/Button.tsx` | Quiet has no outline until hovered; danger uses the `warn` outline and text. |
| Checkbox | `components/Switch.tsx` | Native input, 3:1 outline, accent fill with a check; an indeterminate state for "some selected". |
| Badge | `components.css` | A small outlined pill. `badge-ok` and `badge-warn` use the status tokens and always carry a word and an icon, never color alone. |
| Chip | `components/Chip.tsx` | Bugra's filter chip; the check on a chosen one is drawn by CSS with empty alternative text, so a screen reader hears the name and "pressed", not the check mark. |
| Segmented control | `components/Misc.tsx`, `.tabs` | A pill group with `role="radiogroup"`; the chosen option wears the accent tint. |
| Text field | `components/Misc.tsx` | Bugra's field with a label above and a hint below; monospace for paths. |
| Meter | `components/Misc.tsx` | A thin accent bar with `role="progressbar"`; the text beside it carries the value. |
| Empty state | `components/Misc.tsx` | Icon, sentence and optional actions, centered in the view. |
| Breadcrumb | `pages/Phone.tsx`, `.crumbs` | An up button and the folders above the one shown, as links; the current folder in bold. |
| File table | `layout.css`, `.file-table` | The table of adbDebloat with a checkbox, name, date and size; folders open on click, files toggle. |
| Selection bar | `layout.css` | A bordered bar under the table with what is selected and the copy actions. |
| Review dialog | `pages/Review.tsx`, `.review-*` | Bugra's dialog at 760 px: where from and to, the options, and what the copy will do. |
| Progress card | `pages/Copy.tsx`, `.copy-*` | A large percentage, the meter, files, speed and time left, the file being copied and Stop. |
| Snackbar stack | `components/Snackbars.tsx` | Bugra's snackbar, stacked at the bottom left with a close button. |
| Status bar | `App.tsx`, `layout.css` | adb, the phone, a running copy, the version and the GitHub link. |

## Icons (`components/icons.ts`)

Bugra-style line icons on a 24 px grid, 1.6 px stroke with round caps. adbData adds `folder`,
`file`, `photo`, `video`, `audio`, `document`, `archive`, `package`, `camera`, `screenshot`, `chat`,
`mic`, `home`, `toPc`, `toPhone`, `up`, `stop` and `open`, the mark beside the name in the sidebar
(`App.tsx`), and keeps the GitHub mark from Primer Octicons (MIT) for the link in the status bar.

The app icon (`docs/design/icon.svg`, `npm run icons` makes `src-tauri/icons` from it) is the
sidebar mark in the accent on the dark background: adbDebloat's phone, with a down arrow (files
coming off the phone) where adbDebloat has a minus.
