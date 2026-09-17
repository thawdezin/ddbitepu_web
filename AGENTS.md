# Project Instructions

- This is the DD BitePu website and APK distribution project.
- Keep credentials out of source control and keep static hosting/deployment configuration documented in `README.md`.



## SECURITY — PERMISSION APPROVAL POLICY

Before performing any operation that may request macOS permissions,
including Full Disk Access, Files & Folders, Accessibility,
Screen Recording, Automation, Contacts, Photos, Camera, or Microphone:

1. STOP before triggering the permission request.
2. Explain exactly:
   - Which macOS permission is required
   - Why it is required for my current request
   - Which files, folders, apps, or data will be accessed
   - What command/tool/action will use it
   - Whether a safer, narrower alternative exists
   - What functionality will fail if permission is denied
3. Do not ask me to click Allow yet.
4. Tell me to consult ChatGPT Codex for an independent security review.
5. Continue only after I explicitly approve that specific permission.

Never request Full Disk Access when access to a specific project folder,
file, or temporary directory is sufficient.
Never treat a previous permission approval as approval for a new task.

## STUDIO-WIDE ATT REJECTION PREVENTION — RELEASE-BLOCKING

This project is covered by the August 30, 2026 App Review rejection: Guideline 2.1, because App Review could not locate the App Tracking Transparency prompt on iPadOS 26.6. This must never recur.

- If this project contains or later adds AdMob, Google Mobile Ads, IDFA access, personalized advertising, or any SDK/data use declared as tracking, iOS/iPadOS must implement ATT before that tracking-related work starts.
- On a fresh install, ATT must be the first native permission prompt. Wait until the app is active/resumed, read the current tracking status, and request authorization only when it is not determined.
- Mandatory order: app active/resumed → check ATT status → request and await ATT if not determined → enable analytics/crash reporting or other tracking-related collection → request Location/Notification/Media or any other native permission → run UMP consent → initialize Mobile Ads and load ads.
- Never race ATT with another permission, call it from an inactive launch state, initialize Mobile Ads first, or use an unawaited/parallel startup call.
- Keep `NSUserTrackingUsageDescription` accurate in the built iOS artifact. When Firebase Analytics exists, keep automatic iOS collection disabled in `Info.plist` with `FIREBASE_ANALYTICS_COLLECTION_ENABLED = false` and enable it only after ATT settles.
- If the app does not track, do not add a fake ATT prompt merely to satisfy review; keep App Store privacy answers accurate. AdMob introduced later triggers a fresh privacy/ATT audit before release.
- Before every iOS submission, test a release build on a physical iPhone/iPad from a fresh install or reset tracking state with “Allow Apps to Request to Track” enabled. Record launch → ATT appearing before other permissions/tracking collection → user choice → usable post-prompt flow, and attach the recording to App Review Notes.
- Simulator-only, debug-only, or previously authorized/denied testing does not verify this requirement. An iOS release that has not passed the physical-device ATT recording check must not be submitted.
