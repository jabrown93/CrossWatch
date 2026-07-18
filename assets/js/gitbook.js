/* CrossWatch - GitBook integration */
(() => {
  const enabled = (() => {
    try {
      if (typeof window.__cwUiShowAI === "boolean") return window.__cwUiShowAI;
      const cfg = window._cfgCache;
      const ui = (cfg && typeof cfg === "object") ? (cfg.ui || cfg.user_interface || {}) : {};
      if (ui && typeof ui === "object" && typeof ui.show_AI === "boolean") return !!ui.show_AI;
    } catch (_) {}
    return true;
  })();
  if (!enabled) return;

  const CFG = window.__cwGitBookConfig || {};
  const SITE_URL = String(CFG.siteUrl || "https://wiki.crosswatch.app");
  const REPORT_URL = String(CFG.reportUrl || "https://github.com/cenodude/CrossWatch/issues/new");
  const DISCUSS_URL = String(CFG.discussUrl || "https://github.com/cenodude/CrossWatch/discussions");
  if (window.__cwGitBookBooted) return;
  window.__cwGitBookBooted = true;

function boot() {
    const GB = window.GitBook;
    if (typeof GB !== "function") return;
    try { GB("unload"); } catch (_) {}

    try {
      GB("init", { siteURL: SITE_URL });
    } catch (e) {
      console.warn("[docs] GitBook init failed:", e);
    }

    // Customize Assistant (UI)
    try {
      GB("configure", {
        tabs: ["assistant", "docs"],
        greeting: {
          title: "Welcome to CrossWatch",
          subtitle: "Alright, what’s broken this time?"
        },
        suggestions: [
          "How do I connect Plex?",
          "How do I run a sync?",
          "How does two-way mode work?"
        ],
        actions: [
          {
            icon: "messages",
            label: "Discussions",
            onClick: () => window.open(DISCUSS_URL, "_blank", "noopener,noreferrer")
          },
          {
            icon: "bug",
            label: "Report issue",
            onClick: () => window.open(REPORT_URL, "_blank", "noopener,noreferrer")
          }
        ]
      });
} catch (e) {
      console.warn("[docs] GitBook configure failed:", e);
    }

    try { GB("show"); } catch (e) { console.warn("[docs] GitBook show failed:", e); }
  }

  if (typeof window.GitBook === "function") { boot(); return; }

  let tries = 0;
  const t = setInterval(() => {
    tries += 1;
    if (typeof window.GitBook === "function") {
      clearInterval(t);
      boot();
    } else if (tries > 120) {
      clearInterval(t);
      console.warn("[docs] GitBook embed timed out");
    }
  }, 50);
})();
