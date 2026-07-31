// Minimal DOM stub for exercising assets/helpers/env-lock.js under node.
// Only the handful of APIs env-lock.js touches are implemented.
const fs = require("fs");

function makeEl(attrs) {
  const el = {
    attrs: { ...attrs },
    dataset: {},
    classes: new Set(),
    disabled: false,
    nextElementSibling: null,
    getAttribute: (k) => (k in el.attrs ? el.attrs[k] : null),
    classList: {
      add: (c) => el.classes.add(c),
      remove: (c) => el.classes.delete(c),
      contains: (c) => el.classes.has(c),
    },
    insertAdjacentElement: (_pos, node) => {
      node.nextElementSibling = el.nextElementSibling;
      el.nextElementSibling = node;
    },
    remove: () => {},
  };
  return el;
}

const elements = [];
const byId = {};

global.requestAnimationFrame = (fn) => fn();
global.window = {};
global.document = {
  readyState: "complete",
  body: {},
  addEventListener: () => {},
  getElementById: (id) => byId[id] || null,
  querySelectorAll: () => elements,
  createElement: () => {
    const node = makeEl({});
    node.classList = {
      add: (c) => node.classes.add(c),
      remove: (c) => node.classes.delete(c),
      contains: (c) => node.classes.has(c),
    };
    return node;
  },
};
global.MutationObserver = class {
  observe() {}
};

const spec = JSON.parse(process.argv[2]);
for (const item of spec.elements) {
  const el = makeEl(item.attrs);
  el.id = item.id;
  elements.push(el);
  if (item.id) byId[item.id] = el;
}
for (const [id, value] of Object.entries(spec.instances || {})) {
  byId[id] = { value };
}

eval(fs.readFileSync(spec.source, "utf8"));

window.CW.EnvLock.apply({ _env_locked: spec.locked });

console.log(
  JSON.stringify(
    elements.map((el) => ({
      id: el.id,
      disabled: el.disabled,
      locked: el.classes.has("cw-env-locked"),
      chip: el.nextElementSibling ? el.nextElementSibling.title : null,
    }))
  )
);
