# A11Y-030 / WCAG walkthrough — exactly what to do

**Machine:** your Mac (the one you are reading this on).
**Browser:** Safari for the VoiceOver parts, Chrome for the zoom parts.

## Before you start — get the console running

In Terminal on your Mac:

```
cd /Users/edierks/projects/codex-test/phishing-awareness-platform
./scripts/operator/dep010/start-console.sh
```

It prints the URL, username and password at the end. Open that URL in Safari.
When you are finished with the whole walkthrough:

```
cd /Users/edierks/projects/codex-test/phishing-awareness-platform
./scripts/operator/dep010/stop-console.sh
```

Write findings in this form, one line each — that is all I need to fix them:

```
SCREEN | CONTROL | what happened | what should have happened
```

---

## Test 1 — keyboard only (10 min)

Put the mouse aside. Do not touch it. From the login page:

1. Press `Tab` once. **Expect:** a "Skip to main content" link appears as the
   very first stop. Write it down if nothing appears.
2. Keep pressing `Tab`. **Expect:** every stop shows a clearly visible outline.
   Note any control that gets focus with no visible ring.
3. Log in using only `Tab` and `Return`.
4. `Tab` to the navigation, press `Return` on **Campaigns**.
5. Inside Campaigns press `Tab` through the whole page. **Expect:** focus never
   gets stuck — you can always `Tab` back out to the navigation.
6. Open any dialog, press `Esc`. **Expect:** it closes and focus returns to the
   control that opened it.
7. Repeat 4–6 for **People**, **Reports**, and **Settings**.

## Test 2 — VoiceOver screen reader (20 min)

Turn VoiceOver on with `Cmd + F5`. (Same keys turn it off.)
Useful keys: `VO` means `Control + Option`.

1. `VO + Cmd + H` repeatedly. **Expect:** headings read out in a sensible order
   and describe the section. Note any heading that is blank or meaningless.
2. `VO + U`, then arrow to **Landmarks**. **Expect:** a `main` landmark exists.
3. `VO + Right Arrow` through the page. For **every** control, expect it to say
   both a name and a role — for example "Create campaign, button". Note anything
   that reads as just "button", "clickable", or stays silent.
4. Go to **People → Import CSV**. Move to each form field. **Expect:** the field
   announces its label. Submit it empty. **Expect:** the error is announced, not
   only shown in red.
5. Go to **Campaigns → create**. Same check on every field.
6. Turn VoiceOver off with `Cmd + F5`.

## Test 3 — contrast and motion (5 min)

1. Apple menu → **System Settings** → **Accessibility** → **Display**.
2. Switch **Increase contrast** on. Return to the console and reload.
   **Expect:** nothing disappears; all text stays readable; buttons still look
   like buttons.
3. Switch **Increase contrast** off, switch **Reduce motion** on, reload.
   **Expect:** no spinning, sliding, or animated transitions.
4. Turn both back off.

## Test 4 — zoom and small screens (5 min)

Use Chrome for this one.

1. Press `Cmd + +` until the zoom indicator reads **200%**.
   **Expect:** no content is cut off and the page does not scroll sideways.
2. Press `Cmd + 0` to reset.
3. Open the Web Inspector with `Cmd + Option + I`, click the phone/tablet icon,
   set the width to **320**. **Expect:** the same — everything reachable, no
   sideways scrolling of the page itself.

## Test 5 — dark and light (2 min)

System Settings → **Appearance**. Switch between **Light** and **Dark**.
Reload the console in each. **Expect:** text stays readable in both.

---

When you are done, send me your findings list and run
`./scripts/operator/dep010/stop-console.sh`.
