<img width="1672" height="941" alt="CW-new" src="https://github.com/user-attachments/assets/19e8bad7-79d3-450c-b9a7-de086cc68ffd" />

</center>

> ## 🍴 This is a fork
>
> This repository is a fork of [**cenodude/CrossWatch**](https://github.com/cenodude/CrossWatch),
> kept in sync with upstream. It tracks upstream releases and layers the changes below on top.
> For general usage, the upstream documentation and [wiki](https://wiki.crosswatch.app/) still apply.
>
> **Differences from upstream:**
>
> - **Authentication** — OIDC/SSO login, static API-key auth via an `x-api-key` header for
>   programmatic access, and a first-run setup-token gate. None of these exist upstream.
> - **Security hardening** — secrets are redacted from config output/logs, outbound provider
>   requests are guarded against SSRF (including on every redirect hop, which also covers
>   Jellyfin Quick Connect), and an unrecognized webhook profile token is rejected with a
>   logged 401 rather than a silent 200.
> - **Bug fixes** — ID-mapping fixes (prefer IMDb over TMDb in match priority; map Jellyfin
>   `ProviderIds`).
> - **CI & automation** — a GitHub Actions test suite (pytest), automated Docker image and
>   GitHub Release publishing, semantic-release versioning, and Renovate for dependency
>   updates with SHA-pinned actions.
> - **Hardened container** — the image is built on the shell-less, nonroot Docker Hardened
>   Image Python runtime rather than `python:slim`.
> - **No Android companion app** — dropped upstream in v0.10.3; this fork follows suit and
>   purges any leftover paired-device tokens on the next credential rotation.

<p align="center" style="font-size:14px;">
<b>⭐ Star this repository to get updates</b><br>
</p>


<p align="center">
  <a href="https://github.com/cenodude/CrossWatch/releases/latest">
    <img src="https://img.shields.io/github/v/release/cenodude/CrossWatch?display_name=release&amp;sort=semver&amp;logo=github&amp;label=Latest%20Release&amp;style=for-the-badge" alt="Latest Release">
  </a>
  <a href="https://github.com/cenodude/CrossWatch/pkgs/container/crosswatch">
    <img src="https://img.shields.io/badge/dynamic/json?url=https://ghcr-badge.elias.eu.org/api/cenodude/CrossWatch/crosswatch&amp;query=%24.downloadCount&amp;style=for-the-badge&amp;logo=github&amp;label=GHCR%20Pulls" alt="GHCR Pulls">
  </a>
  <a href="https://wiki.crosswatch.app/getting-started/first-time-setup">
    <img src="https://img.shields.io/badge/Quick%20Start-Must%20read!-d93c4a?style=for-the-badge&amp;logo=gitbook" alt="Must-read: Quick Start">
  </a>
  <br>
  <a href="https://hub.docker.com/r/cenodude/crosswatch">
    <img src="https://img.shields.io/docker/pulls/cenodude/crosswatch?style=for-the-badge&amp;logo=docker&amp;label=Docker%20Pulls" alt="Docker Pulls">
  </a>
  <a href="https://hub.docker.com/r/cenodude/crosswatch">
    <img src="https://img.shields.io/docker/image-size/cenodude/crosswatch/latest?style=for-the-badge&amp;logo=docker&amp;label=Image%20Size" alt="Image Size">
  </a>
  <a href="https://hub.docker.com/r/cenodude/crosswatch/tags">
    <img src="https://img.shields.io/docker/v/cenodude/crosswatch?sort=semver&amp;style=for-the-badge&amp;logo=docker&amp;label=Docker%20Version" alt="Docker Version">
  </a>
</p>
<p align="center">

  <a href="https://www.crosswatch.app/" style="margin: 0 6px;">
    <img alt="Website" src="https://img.shields.io/badge/Website-crosswatch.app-B026FF?style=for-the-badge">
  </a>
  <a href="https://wiki.crosswatch.app/" style="margin: 0 6px;">
    <img alt="Wiki" src="https://img.shields.io/badge/Wiki-wiki.crosswatch.app-B026FF?style=for-the-badge">
  </a>
  <a href="https://www.reddit.com/r/CrossWatchApp/" style="margin: 0 6px;">
    <img alt="Reddit" src="https://img.shields.io/badge/Reddit-r%2FCrossWatchApp-ff4500?style=for-the-badge&logo=reddit&logoColor=white">
  </a>
</p>


**CrossWatch (CW)** is a synchronization engine that act as a bridge and keeps your **Plex, Jellyfin, Emby, SIMKL, Floppy, Trakt, AniList, TMDb, MDBList, PublicMetaDB, PunchPlay, Scrob, Tautulli, Kodi, Nuvio, Stremio and CW local tracker** in sync. It runs locally with a web UI where you link accounts, define sync pairs, run them manually or on a schedule, and review stats and history. CW also includes its own tracker to keep your data safe with snapshots. With Profiles, you can manage separate sync setups for yourself and for friends or family too, with their own servers and/or tracker API's.

### CW in a nutshell:
* **One brain for all your media syncs** A single place to configure everything.
* **Be your own Sync Hub** Create profiles for seperate media servers/users/trackers.
  * Managed user support (multi-users)
* **Multi media-server** and **multi tracker** support with profiles.
* **Synchronization**
  * Watchlists, Ratings, History and Progress
  * Rewatches: keep separate plays in sync for supported trackers.
  * Anime ID mapping (powered by AniBridge and animeApi) for AniList and SIMKL pairs, with custom mappings.
* **Scrobble (tracks your activity)**
  * **Watcher** (Plex/Emby/Jellyfin/Kodi/Scrob to supported trackers)
    * Does not require Plex Pass or Emby Premiere. Yay!
  * **Webhooks** (Plex/Emby/Jellyfin to supported trackers)
* **Tools**
  * Analyzer: Finds items that are **stuck** or inconsistent between providers.
  * Playback Progress Manager: View and edit unfinished playback sessions across providers.
  * Editor: Inspect and adjust your items and add or block items.
  * Events Viewer: Search and inspect sync runs.
  * Captures: Rollback tool for provider watchlist, ratings, and history.

And much, much more...such as:
* Simple and advanced scheduling: From standard to more detailed pair schedules
* CW Tracker Keeps snapshots/backups from your media servers and trackers.
* Unified Watchlist: View all watchlist items in one place.
* Player card: Shows what you are currently watching in real time.
* Fallback GUID: Revives old items from  your Plex library.

### Download
[![Guide: Installation](https://img.shields.io/badge/Guide-INSTALLATION-0d6efd?style=for-the-badge)](https://wiki.crosswatch.app/getting-started/installation)


*   **Docker:**

    ```bash
    docker pull ghcr.io/jabrown93/crosswatch:latest
    ```

### Run as Container

```bash
docker run -d \
  --name crosswatch \
  -p 8787:8787 \
  -v crosswatch_config:/config \
  -e TZ=Europe/Amsterdam \
  --restart unless-stopped \
  ghcr.io/jabrown93/crosswatch:latest
```

or

```bash
services:
  crosswatch:
    image: ghcr.io/jabrown93/crosswatch:latest
    container_name: crosswatch
    ports:
      - "8787:8787"
    environment:
      TZ: Europe/Amsterdam
    volumes:
      - type: volume
        source: crosswatch_config
        target: /config
    restart: unless-stopped

volumes:
  crosswatch_config:
```

> The container exposes the web UI at:\
> http://localhost:8787

### Configuration from the environment

Any setting can be supplied as an environment variable instead of being typed into the UI.
Environment values win over `config.json` and are **never written to it**, so a secret from a
Docker secret or Kubernetes Secret stays out of the config volume. Unset the variable and the
field reverts to whatever the file held.

Fields owned by the environment are shown disabled in the UI, labelled with the variable that
owns them; a save that tried to change one reports which fields it discarded.

Single sign-on and machine access have short names:

| Variable | Setting |
| --- | --- |
| `CW_OIDC_ENABLED` | Offer OIDC login (`true` / `false`) |
| `CW_OIDC_ISSUER` | Issuer URL — trailing slash is significant |
| `CW_OIDC_CLIENT_ID` | Client ID |
| `CW_OIDC_CLIENT_SECRET` | Client secret |
| `CW_OIDC_PUBLIC_BASE_URL` | External base URL of this instance |
| `CW_OIDC_GROUPS_CLAIM` | ID token claim holding group membership (default `groups`) |
| `CW_OIDC_ALLOWED_GROUPS` | Groups allowed to sign in — **empty means no group restriction**: every account the IdP authenticates may sign in |
| `CW_OIDC_SESSION_HOURS` | Lifetime of an OIDC session, 1–168 |
| `CW_API_KEY` | Static key accepted in the `X-API-Key` header |

Every other setting uses `CW_CFG__` followed by the config path, with `__` between each part:

```yaml
environment:
  CW_OIDC_ENABLED: "true"
  CW_OIDC_ISSUER: "https://auth.example.com/application/o/crosswatch/"
  CW_OIDC_CLIENT_ID: "crosswatch"
  CW_OIDC_CLIENT_SECRET: "${CROSSWATCH_OIDC_SECRET}"
  CW_OIDC_PUBLIC_BASE_URL: "https://crosswatch.example.com"
  CW_OIDC_ALLOWED_GROUPS: "crosswatch-admins,crosswatch-users"
  # Any other path:
  CW_CFG__plex__server_url: "http://plex:32400"
  CW_CFG__runtime__debug: "true"
```

Values are read as JSON when they parse as JSON and as plain text otherwise, so `true` is a
boolean, `12` a number, and `["a","b"]` a list, while a URL is just a string. `CW_OIDC_ALLOWED_GROUPS`
also accepts a comma-separated list. Setting a variable to an empty string sets the field to
empty — to hand a field back to `config.json`, remove the variable.

Two limits follow from the `__` path form: list entries cannot be addressed, so sync pairs and
scrobbler routes are not configurable this way, and keys beginning with an underscore are out of
reach. Values are read at startup, so changes need a restart.

## Sponsors

<div align="center">

<a href="https://www.buymeacoffee.com/cenodude">
  <img alt="Buy Me a Coffee" src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=000000">
</a><center><br>
Every cent goes to the <b>ALS Foundation</b> in the Netherlands</center>
<br/>
<br/>

<a href="https://www.gitbook.com/">
  <img alt="GitBook" src="https://img.shields.io/badge/GitBook-sponsored-3884ff?style=for-the-badge&logo=gitbook&logoColor=white">
</a>

</div>

<p align="center">
  Huge thanks to our sponsors for keeping this project moving.
</p>
