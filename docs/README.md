# PLGames Svoboda — Landing Page

This folder contains the GitHub Pages landing site for the project.

## Files

- `index.html` — main landing page (hero, features, bypass chain, roadmap, install, privacy)
- `style.css` — dark theme with violet/blue gradients, mobile-responsive
- `_config.yml` — GitHub Pages config (Jekyll bypassed; we serve plain HTML/CSS)

## Enabling GitHub Pages

In the repo settings (https://github.com/Leonid1095/PLGames-Svoboda/settings/pages):

1. **Source**: Deploy from a branch
2. **Branch**: `main` / folder: `/docs`
3. Click **Save**

Site goes live at: **https://leonid1095.github.io/PLGames-Svoboda/**

First deploy takes 1-2 minutes; updates are usually live in 30-60 seconds.

## Local preview

Open `docs/index.html` directly in a browser — no build step needed. All styles are vanilla CSS, no frameworks.

## Adding screenshots

When you have screenshots/GIFs of the running tool:

1. Drop them into `docs/assets/`
2. Reference in `index.html` as `<img src="assets/screenshot.png" alt="...">`
3. Recommended: WebP for static screenshots (~70% smaller than PNG), MP4/WebM for demos (autoplay muted loop)

## Updates checklist

When shipping a new feature:
- [ ] Update the "What's new" section badges in hero
- [ ] Move item between roadmap columns (Planned → In Progress → Shipped)
- [ ] Bump the test count in stats if test suite grew
- [ ] Update strategy count if KNOWN_STRATEGIES expanded

## Custom domain (future)

To use `svaboda-shwe.online`:

1. Add `CNAME` file in `docs/` with the domain
2. Configure DNS: `CNAME` record pointing to `leonid1095.github.io`
3. Enable HTTPS in repo Pages settings (waits for cert provisioning, ~10 min)
