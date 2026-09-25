# Start here: run your first campaign

Written for someone who has just signed in and wants a campaign out the door.
Do these in order. Anything not listed is optional — the console now keeps those
behind **More** in the sidebar.

**You fill in four things in total.** Everything else is either already known to
the platform or has a sensible default you can change.

---

## 1. Prove you own the sending domain — *Domains & RoE*

**What you supply:** the domain you will send from, e.g. `corp-training.example`.
Optionally your mail relay and its IP.

**Where to get it:** it must be a domain you control the DNS for. Not your real
corporate domain unless you intend the mail to appear to come from it.

**What happens:** the console gives you the exact DNS records to paste into your
registrar. **That paste is the one step nobody can do for you** — it needs write
access to your zone, and this platform deliberately does not hold registrar
credentials.

**Then it is automatic.** Leave the panel open. The console checks DNS every 15
seconds, shows each record as it appears, and records the verification itself the
moment ownership is provable. You do not click anything.

If something is wrong it tells you which of two things it is:

- **not visible yet** — normal, DNS takes minutes and sometimes hours; wait
- **wrong value published** — it shows you what is published next to what it
  expected, which is usually enough to spot a stale record from a previous try

> If the records looked right when you saved them but keep reading as missing,
> check your registrar has not silently removed them. Turning on an
> email-forwarding feature does exactly that on some providers.

## 2. Confirm the domain owner said yes — *Domains & RoE*

**What you supply:** one tick, plus the name of who authorized it
(e.g. `Example Corp`).

**Where to get it:** the person or organisation that owns the domain. This is a
statement only you can make, so it stays a human action — but it costs one tick.

Everything else is filled for you: the target domains are the ones you just
verified, the terms are standard, the window is the next twelve months. "Set
custom terms or window instead" reopens the full form if you need it.

## 3. Import your recipients — *Recipients*

**What you supply:** a CSV.

**Where to get it:** your HR or directory export. **Email address alone is
enough.** A name column is used if present; everything else is ignored. Open
*"How should my spreadsheet be laid out?"* on that page for the exact headers —
common variants like `email`, `e-mail`, `mail` are all understood.

> Recipients must be inside a domain your signed RoE covers, or they will be
> refused at send time. That is the authorization boundary and it cannot be
> turned off.

## 4. Get a template — *Template review*

**What you supply:** nothing, if you let the AI write it.

Approve a threat pattern and the generation worker writes a draft for you; it
appears here for review. You read it and approve it. In a single-operator
deployment you can approve your own — the decision is recorded against you.

You only need to write a template yourself if you want something specific.

## 5. Create the campaign — *Campaigns*

**What you supply:** in the normal case, **nothing** — check the draft and press
Create.

The form arrives prefilled:

| Field | Where the value comes from |
| --- | --- |
| Title | Generated from the pattern and the month |
| Sender mailbox | `security-awareness@` your verified domain |
| Training domain | `training.` your verified domain |
| Start | The next whole hour |
| End | Two weeks after the start |
| Max recipients | However many you imported |
| Pattern / Template / Lesson | The approved ones |

Change anything that is wrong — it is a draft, not a lock. The two worth a look
are the **template** (is this the lure you want?) and the **dates**.

> Sender and training domain are only filled in when you have exactly one
> verified domain. With several, the console leaves them blank rather than guess
> — a wrong From address on real mail is worse than an empty field.

## 6. Submit it — *Campaigns*

One button. This freezes the campaign so what was approved is exactly what sends.

In a single-operator deployment, submitting **is** the approval — there is no
second person to wait for, and the decision is recorded against you.

## 7. Send the canary — *Campaigns*

One button. A small cohort of test accounts goes first. Check the mail looks
right before anything wider goes out. This gate is deliberate and cannot be
skipped.

## 8. Publish, watch, and stop if you need to — *Campaigns*

Publish sends to the rest. The campaign page shows opens, clicks and reports as
they arrive, and **Recall** stops it at any point — it also revokes every
tracking link already sent.

---

## What you never have to touch

These are real features, not clutter, but nothing above needs them. They are
under **More** in the sidebar:

- **Repeat on a schedule** — quarterly refreshers, once you have run one campaign
- **Patterns, Sources, Threat aggregation** — where lure material comes from, if
  you want to curate it rather than take what is generated
- **Executive trends, Audit, Privacy, Failed jobs, AI model, Settings**

## If a button is greyed out

It is almost always an earlier step. The Campaigns page lists exactly what is
missing and links straight to it. The order above is the order the platform
enforces.
