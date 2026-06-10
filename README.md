# Exorcist

A Discord bot that detects and cleans up the scams posted by hacked accounts.

Exorcist detects and takes action on MrBeast crypto giveaways, casino promo codes, free Nitro
links, sketchy server invites, and more. It allows you to configure the types of detection,
the leniency, and the punishments. The bot also includes many useful utilities, such as the
ability to test media for detections, detailed logging to a channel with account info and the
reason for each detection, and a self-unmute system for users who secure their account.

The bot runs fully locally, meaning there is no paid API and your images are never sent off
to anyone.

## Detection methods

Exorcist uses four detection methods, and you can choose which ones to run per server in
`/setup`:

- **Behavior** detects when the same message is sprayed across several channels in under a
  minute. It also flags `@everyone` pings from accounts that have no business sending them.
- **Image match** stores perceptual hashes of known scam images, so it still catches reposts
  after they have been recompressed, recolored, or rearranged. It goes off how an image looks
  instead of the exact file, and you set how loose that match is in `/settings`, from strict
  to very loose. It also picks up new images as you confirm them.
- **Keywords** reads the message text and the text inside the image (OCR), and scores it
  against scam wording and fake invites. It relies on the language these scams reuse, such as
  "withdrawal success", "specified wallet", "promo code", and "free Nitro", instead of a
  domain blocklist. This is because the domains rotate constantly while the wording stays
  mostly the same.
- **Honeypot** is a trap channel. You make an empty channel that members have no reason to
  use and select it in setup. Exorcist posts a warning there, and anyone who posts in the
  channel anyway is caught on the spot and has their recent messages cleaned up across the
  server. A real person reads the warning and leaves the channel alone, while a hacked
  account spraying every channel posts right into it.

The first three methods add up to a score, and crossing a threshold counts as a detection.
One strong signal, such as a known image or a flagged link, is enough on its own, while
weaker signals need to stack up. This means that a real member sharing a normal screenshot
does not get punished. The honeypot skips the scoring entirely, since posting there is an
instant catch.

Detection also looks past how the scam is delivered. It follows **forwarded messages** into
the original they carry, pulls images and text out of **Tenor/Giphy GIFs and pasted image
links** (which arrive as embeds rather than uploads), reads the text in **link previews**, and
samples a few frames of **animated GIFs** so a scam shown only partway through still matches.

## Setup

### 1. Make the bot

1. Head to the Discord developer portal, make a new application, and add a bot to it.
2. Under the bot tab, enable **Message Content Intent** and **Server Members Intent**.
3. Set the app description / about me to something like "catches scams from hacked accounts
   and cleans them up" so it shows on the profile.
4. Copy the token.
5. Invite it with the `bot` and `applications.commands` scopes and these permissions:
   Manage Messages, Moderate Members, Kick Members, Ban Members. The bot's role needs to sit
   above anyone it acts on, so place it high enough in the list.

### 2. Install

Requires Python 3.10 or newer.

```
pip install -r requirements.txt
```

For the keyword method to read text out of images, you will need Tesseract installed:

- **Windows:** grab an installer from https://digi.bib.uni-mannheim.de/tesseract/ and run it.
  If it isn't on your PATH, point `TESSERACT_CMD` in your `.env` at the `tesseract.exe` it
  installed.
- **Linux:** `sudo apt install tesseract-ocr`

OCR only matters for pulling text out of images. Skip it and the keyword method still reads
message text, while the other methods don't touch it anyway.

### 3. Run

```
cp .env.example .env      # then fill in DISCORD_TOKEN
python main.py
```

Or with Docker, which bundles Tesseract for you:

```
docker build -t exorcist .
docker run -e DISCORD_TOKEN=your-token -v exorcist-data:/data exorcist
```

The `exorcist-data` volume keeps your per-server settings (and the learned hash pool) between
restarts. Mount a host folder instead with `-v "$(pwd)/data:/data"` if you'd rather see the
file directly. (Mounting a single `config.json` file doesn't work — the bot writes settings by
swapping a temp file into place, which a bind-mounted file blocks.)

### 4. Configure

In your server, run `/setup`. The wizard walks you through the channels, the detection
methods, the log channel, whether to act on its own or wait for a mod, the punishments, and
the honeypot. Nothing turns on until you finish the wizard.

Every setting can be changed afterward with `/settings`, which allows you to pick a single
setting and edit it without rerunning the whole wizard. `/status` shows the current
configuration, and `/toggle` turns detection on or off.

The resecure DM is just one of the punishments, so to stop Exorcist messaging users in a
single server, drop **DM them to resecure** from that server's punishments in `/settings`. To
turn DMs off everywhere at once, set `EXORCIST_DISABLE_DMS=1` in your `.env` and restart;
Exorcist then won't DM anyone on any server, regardless of each server's punishments.

### Self-unmute

Since these are usually hacked accounts, you can allow a timed-out user to clear their own
timeout once they have actually secured their account. You can enable it in setup (or
`/settings`), and the resecure DM includes a button that they press after changing their
password and turning on 2FA. It only applies when the punishment is a timeout, not a kick or
a ban.

### Test channel

You can set a test channel in `/settings` to test media against the detector. Drop an image
or message in there and Exorcist tells you whether it would be flagged, the score against your
threshold, and a breakdown of what each method caught and missed. That breakdown even covers
methods you don't have turned on, so you can see what they would add.
Nothing gets deleted or punished in the test channel, since it is only meant for tuning. It
also works while detection is off, which means you can try things out before going live.

### Analyze a message

`/analyze` runs that same breakdown on a message that has already been posted, without a test
channel and without reposting it. Pass a message ID or a message link (right-click a message,
then Copy Message ID or Copy Message Link) and Exorcist replies with the score and the
per-method breakdown, visible only to you. If the message is in a different channel from where
you run the command, add the `channel` option or just paste the link. Like the test channel it
only reads, it never deletes or punishes.

## Who can use it

Server admins can always run the commands, so you can set the bot up out of the box. To let
your mods use it without giving them admin, add them to the access list:

```
/access add user:@someone
/access add role:@mods
```

Anyone not on the list (and not an admin) is told they don't have access.

## The scam data

Image match runs off two things: a **pretrained seed** that ships with the bot, and a
**shared pool** that it builds while running. Every server reads both, and the only
difference is whether a server adds to the pool.

In `/setup`, each server picks one of two modes:

- **Use existing data** (the default, and best for most servers) reads the seed and pool but
  never adds to them. This means that a bad catch in your server can't spread to everyone
  else.
- **Train** also feeds this server's catches into the shared pool.

You can also right-click any scam message, go to Apps, and select **Mark as scam** to teach
the bot by hand. That always adds the image no matter which mode you are in, since it is a
deliberate call. The **False alarm** button on a log entry does the opposite, forgetting an
image the bot learned and lifting the punishment.

`/data show` lists the counts and your mode, `/data train` switches the mode, and `/data
wipe` (bot owner only) clears the shared pool. The seed is never touched by a wipe.

## Training the seed beforehand

You can build the pretrained seed before you deploy with `train.py`. Point it at a folder of
scam screenshots and it hashes them in:

```
python train.py images ./scam_pics           # add them to the seed
python train.py images ./scam_pics --reset   # or replace the seed
python train.py keywords ./more_words.txt    # add scam wording, one per line
python train.py stats                        # see what you have
```

The seed lives in `data/seed_hashes.json` and the wording in `data/keywords.json`. Both are
committed so they ship with the repo.

## Coming soon

A few things on the roadmap:

- **Shared cloud scam database.** Today the image hashes ship with the repo and the shared
  pool lives in each server's own `config.json`. The plan is an opt-in cloud database that
  anyone can contribute confirmed scam images to, so a scam caught in one server is recognized
  everywhere within minutes instead of being relearned server by server. You'll be able to
  pull from it read-only, contribute back, or stay fully local like today, since contributing
  is always a choice.
- **Cloud keyword feed.** The same idea for the scam wording, so new phrasing gets picked up
  without editing `keywords.json` and redeploying.
- **Web dashboard.** Manage settings, browse the detection log, and review the action queue
  from a browser instead of slash commands.
- **Appeals and review queue.** Let punished users appeal and have a mod approve or deny from
  the log, alongside the existing self-unmute.
- **Multilingual detection.** OCR and scam wording in more languages, since these campaigns
  are not English-only.

## Config

Everything else lives in `config.json`, which is written as you use the wizard. There is a
`config.example.json` showing the shape. The token stays in `.env` and is never put in the
config.
