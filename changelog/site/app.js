(async function () {
  const timeline = document.getElementById("timeline");
  const filters = document.getElementById("filters");
  const state = document.getElementById("state");
  const repoLink = document.getElementById("repo-link");

  const SECTION_ORDER = ["New", "Improved", "Fixed", "Breaking"];
  const SECTION_CLASS = {
    New: "sec-new",
    Improved: "sec-improved",
    Fixed: "sec-fixed",
    Breaking: "sec-breaking",
  };

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      node.append(c instanceof Node ? c : document.createTextNode(c));
    }
    return node;
  }

  function timeAgo(dateStr) {
    const days = Math.round((Date.now() - new Date(dateStr + "T12:00:00Z")) / 86400000);
    if (days < 1) return "today";
    if (days === 1) return "yesterday";
    if (days < 30) return days + " days ago";
    if (days < 365) return Math.round(days / 30) + " months ago";
    return (days / 365).toFixed(1) + " years ago";
  }

  function anchorId(version) {
    return version.toLowerCase().replaceAll(".", "-").replaceAll(" ", "-");
  }

  function showState(html) {
    timeline.replaceChildren();
    state.innerHTML = html;
    state.hidden = false;
  }

  let data;
  try {
    const res = await fetch("changelog.json");
    if (!res.ok) throw new Error("HTTP " + res.status);
    data = await res.json();
  } catch {
    showState("Couldn't load <code>changelog.json</code>.<br>Run <code>broly changelog build</code> and refresh.");
    return;
  }

  if (repoLink && data.repo && data.repo.url) repoLink.href = data.repo.url;

  const entries = data.entries || [];
  if (entries.length === 0) {
    showState("No changelog entries yet.<br>Run <code>broly changelog generate --write</code> and <code>broly changelog build</code>.");
    return;
  }

  const counts = { All: 0 };
  for (const e of entries) {
    for (const s of e.sections || []) {
      counts[s.name] = (counts[s.name] || 0) + (s.items || []).length;
      counts.All += (s.items || []).length;
    }
  }

  const sectionNames = [...SECTION_ORDER.filter((n) => counts[n]), ...Object.keys(counts).filter((n) => n !== "All" && !SECTION_ORDER.includes(n))];

  let active = "All";

  function renderFilters() {
    const chips = sectionNames.map((name) =>
      el("button", {
        class: "chip",
        "aria-pressed": String(name === active),
        style: name === "Breaking" ? "--chip-color: var(--breaking)" : name === "New" ? "--chip-color: var(--new)" : name === "Fixed" ? "--chip-color: var(--fixed)" : name === "Improved" ? "--chip-color: var(--improved)" : "",
        onclick: () => {
          active = name;
          renderFilters();
          renderTimeline();
        },
      }, name, el("span", { class: "count" }, String(counts[name] || 0)))
    );
    filters.replaceChildren(
      el("button", {
        class: "chip",
        "aria-pressed": String(active === "All"),
        onclick: () => {
          active = "All";
          renderFilters();
          renderTimeline();
        },
      }, "All", el("span", { class: "count" }, String(counts.All))),
      ...chips
    );
  }

  function itemNode(item, sectionName) {
    const body = el("div", { class: "item-body" },
      el("p", { class: "item-title" }, item.title || ""));
    if (item.detail) {
      body.append(el("p", { class: "item-detail" }, item.detail));
    }
    if (item.commits && item.commits.length) {
      const chips = item.commits.map((c) =>
        c.url
          ? el("a", { class: "sha", href: c.url, title: "View commit " + c.sha }, c.sha.slice(0, 9))
          : el("span", { class: "sha" }, c.sha.slice(0, 9))
      );
      body.append(el("div", { class: "commits" }, chips));
    }
    return el("div", { class: "item" },
      el("span", { class: "item-badge " + (SECTION_CLASS[sectionName] || "") }, sectionName.slice(0, 3)),
      body);
  }

  function renderTimeline() {
    const nodes = [];
    for (const e of entries) {
      const sections = (e.sections || []).slice().sort(
        (a, b) => {
          const ai = SECTION_ORDER.indexOf(a.name);
          const bi = SECTION_ORDER.indexOf(b.name);
          return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
        }
      );
      const hasBreaking = sections.some((s) => s.name === "Breaking");
      const visible = sections
        .map((s) => ({ ...s, items: (s.items || []).filter(() => active === "All" || s.name === active) }))
        .filter((s) => s.items.length);

      if (!visible.length) continue;

      const card = el("article", { class: "release-card" });
      const head = el("div", { class: "release-head" },
        el("a", { class: "version", id: anchorId(e.version), href: "#" + anchorId(e.version) }, e.version),
        el("span", { class: "release-date" }, e.date + " · " + timeAgo(e.date)),
        el("span", { class: "release-stats" },
          el("span", { class: "add" }, "+" + (e.stats ? e.stats.insertions : 0).toLocaleString()), " ",
          el("span", { class: "del" }, "−" + (e.stats ? e.stats.deletions : 0).toLocaleString()), " · ",
          (e.stats ? e.stats.commits : 0) + " commits"));
      card.append(head);
      card.append(el("h2", { class: "release-title" }, e.title || ""));
      if (e.description) {
        for (const p of e.description.split("\n\n")) {
          if (p.trim()) card.append(el("p", { class: "release-desc" }, p.trim()));
        }
      }

      const sectionsEl = el("div", { class: "sections" });
      for (const s of visible) {
        const sectionHead = el("h3", { class: "section-head " + (SECTION_CLASS[s.name] || "") }, s.name);
        const section = el("section", { class: "section " + (SECTION_CLASS[s.name] || "") },
          sectionHead,
          s.items.map((item) => itemNode(item, s.name)));
        sectionsEl.append(section);
      }
      card.append(sectionsEl);

      nodes.push(el("li", {
        class: "release",
        "data-breaking": String(hasBreaking),
        "data-default-dot": sections.some((s) => s.name === "New") ? "new" : "",
      }, card));
    }
    timeline.replaceChildren(...nodes);
    if (!nodes.length) {
      showState("No <strong>" + active + "</strong> changes yet.");
    } else {
      state.hidden = true;
    }
  }

  renderFilters();
  renderTimeline();

  if (location.hash) {
    const target = document.getElementById(location.hash.slice(1));
    if (target) target.scrollIntoView({ block: "start" });
  }
})();