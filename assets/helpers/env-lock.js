// Locks config fields the environment owns.
// The server discards edits to them either way; this makes that visible before
// the user types instead of after the save silently reverts.
(function () {
  const NS = (window.CW ||= {});

  // Mirrors ALIASES in cw_platform/config_env.py; only affects the tooltip text.
  const ALIASES = {
    "app_auth.oidc.enabled": "CW_OIDC_ENABLED",
    "app_auth.oidc.issuer": "CW_OIDC_ISSUER",
    "app_auth.oidc.client_id": "CW_OIDC_CLIENT_ID",
    "app_auth.oidc.client_secret": "CW_OIDC_CLIENT_SECRET",
    "app_auth.oidc.public_base_url": "CW_OIDC_PUBLIC_BASE_URL",
    "app_auth.oidc.groups_claim": "CW_OIDC_GROUPS_CLAIM",
    "app_auth.oidc.allowed_groups": "CW_OIDC_ALLOWED_GROUPS",
    "app_auth.oidc.session_hours": "CW_OIDC_SESSION_HOURS",
    "security.api_key": "CW_API_KEY",
  };

  const LOCKED_CLASS = "cw-env-locked";
  const CHIP_CLASS = "cw-env-chip";
  const MARKER = "cwEnvLocked";

  let locked = new Set();

  function envVarFor(path) {
    return ALIASES[path] || "CW_CFG__" + String(path).split(".").join("__");
  }

  /** Provider credentials live under `<provider>.instances.<name>` unless the
   *  selected instance is the default one. Mirrors _cwSelectedInst. */
  function selectedInstance(root) {
    try {
      const raw = document.getElementById(`${root}_instance`)?.value;
      const inst = String(raw || "").trim();
      return inst || "default";
    } catch {
      return "default";
    }
  }

  function effectivePath(el) {
    const path = String(el.getAttribute("data-cfg-path") || "").trim();
    if (!path) return "";
    const root = String(el.getAttribute("data-cfg-instance-root") || "").trim();
    if (!root || !path.startsWith(root + ".")) return path;
    const inst = selectedInstance(root);
    if (inst === "default") return path;
    return `${root}.instances.${inst}.${path.slice(root.length + 1)}`;
  }

  function addChip(el, path) {
    if (el.nextElementSibling?.classList?.contains(CHIP_CLASS)) return;
    const chip = document.createElement("span");
    chip.className = CHIP_CLASS;
    chip.textContent = "Set by environment";
    chip.title = `Set by ${envVarFor(path)}; edits here are ignored.`;
    el.insertAdjacentElement("afterend", chip);
  }

  function removeChip(el) {
    const next = el.nextElementSibling;
    if (next?.classList?.contains(CHIP_CLASS)) next.remove();
  }

  function lock(el, path) {
    if (el.dataset[MARKER] === "1") return;
    el.dataset[MARKER] = "1";
    el.disabled = true;
    el.classList.add(LOCKED_CLASS);
    addChip(el, path);
  }

  function unlock(el) {
    // Only undo what this module did -- other code disables fields for its own
    // reasons and must keep them disabled.
    if (el.dataset[MARKER] !== "1") return;
    delete el.dataset[MARKER];
    el.disabled = false;
    el.classList.remove(LOCKED_CLASS);
    removeChip(el);
  }

  function apply(cfg) {
    if (cfg && Array.isArray(cfg._env_locked)) locked = new Set(cfg._env_locked);
    if (!document.body) return;
    for (const el of document.querySelectorAll("[data-cfg-path]")) {
      const path = effectivePath(el);
      if (path && locked.has(path)) lock(el, path);
      else unlock(el);
    }
  }

  function isLocked(path) {
    return locked.has(String(path || ""));
  }

  let pending = 0;
  function scheduleApply() {
    if (pending) return;
    pending = requestAnimationFrame(() => {
      pending = 0;
      apply();
    });
  }

  function watch() {
    if (!document.body) return;
    // Settings panes, provider blocks, and modals all render on demand; watching
    // is cheaper than hooking every render site and cannot go stale.
    new MutationObserver(scheduleApply).observe(document.body, { childList: true, subtree: true });
    document.addEventListener("change", (ev) => {
      if (/_instance$/.test(String(ev.target?.id || ""))) scheduleApply();
    });
    scheduleApply();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", watch);
  else watch();

  NS.EnvLock = { apply, isLocked, envVarFor, scheduleApply };
})();
