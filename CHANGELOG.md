# Changelog

## 2.0.0

adbData is now a Windows app with a window instead of a PowerShell menu.

- Copies over adb's own protocol, one connection for a whole folder, instead of starting programs
  for every file.
- Browse the phone, jump to the camera, screenshots, downloads and other usual places, filter by
  kind, and send files to the phone as well.
- A review before every copy: how many files, how much, what is already on the PC, which names
  change for Windows, and whether there is room.
- Copying again skips files already on the PC, so an interrupted copy picks up where it stopped;
  keeping both or replacing is a choice.
- Copies keep the phone's dates. Every name works, including ones with `&` or `$`; names Windows
  refuses get `_` in place of the characters it does not allow.
- No partial files: each copy is written under a temporary name and renamed when complete. A
  dropped connection is retried; a phone that is gone stops the copy with a list of what is left.
- An optional MD5 check of every copy, in batches.
- A history of every copy, English and Turkish, light and dark theme, on the Bugra design system.
- platform-tools are downloaded from Google when needed instead of being kept in the repository.
