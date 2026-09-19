(async function () {
  const timeline = document.getElementById("timeline");
  const filters = document.getElementById("filters");
  const state = document.getElementById("state");
  const repoLink = document.getElementById("repo-link");
  const pagination = document.getElementById("pagination");

  const PAGE_SIZE = 4;
  const SECTION_ORDER = ["New", "Improved", "Fixed", "Breaking"];
  const SECTION_CLASS = {
    New: "sec-new",
    Improved: "sec-improved",
    Fixed: "sec-fixed",
    Breaking: "sec-breaking",
  };
  const CHIP_COLOR = {
    New: "var(--new)",
    Improved: "var(--improved)",
    Fixed: "var(--fixed)",
    Breaking: "var(--breaking)",
  };

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined) continue;
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
    const months = Math.round(days / 30);
    if (months < 12) return months + (months === 1 ? " month ago" : " months ago");
    const years = (days / 365).toFixed(1);
    return years + (years === "1.0" ? " year ago" : " years ago");
  }

  function anchorId(version) {
    return version.toLowerCase().replaceAll(".", "-").replaceAll(" ", "-");
  }

  function showState(html) {
    timeline.replaceChildren();
    pagination.replaceChildren();
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
  let page = 1;

  function setHash(hash) {
    history.replaceState(null, "", hash);
  }

  function visibleReleases() {
    const out = [];
    for (const e of entries) {
      const sections = (e.sections || [])
        .slice()
        .sort((a, b) => {
          const ai = SECTION_ORDER.indexOf(a.name);
          const bi = SECTION_ORDER.indexOf(b.name);
          return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
        })
        .map((s) => ({ ...s, items: (s.items || []).filter(() => active === "All" || s.name === active) }))
        .filter((s) => s.items.length);
      if (sections.length) out.push({ entry: e, sections });
    }
    return out;
  }

  function renderFilters() {
    const chip = (name, color) =>
      el("button", {
        class: "chip",
        "aria-pressed": String(name === active),
        style: color ? "--chip-color: " + color : "",
        onclick: () => {
          active = name;
          page = 1;
          renderFilters();
          renderTimeline();
        },
      }, name, el("span", { class: "count" }, String(counts[name] || 0)));

    filters.replaceChildren(chip("All"), ...sectionNames.map((n) => chip(n, CHIP_COLOR[n])));
  }

  function itemNode(item, sectionName) {
    const body = el("div", { class: "item-body" }, el("p", { class: "item-title" }, item.title || ""));
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

  function releaseNode({ entry: e, sections }) {
    const hasBreaking = sections.some((s) => s.name === "Breaking");
    const card = el("article", { class: "release-card" });
    card.append(el("div", { class: "release-head" },
      el("a", { class: "version", id: anchorId(e.version), href: "#" + anchorId(e.version) }, e.version),
      el("span", { class: "release-date" }, e.date + " · " + timeAgo(e.date)),
      el("span", { class: "release-stats" },
        el("span", { class: "add" }, "+" + (e.stats ? e.stats.insertions : 0).toLocaleString()), " ",
        el("span", { class: "del" }, "−" + (e.stats ? e.stats.deletions : 0).toLocaleString()), " · ",
        (e.stats ? e.stats.commits : 0) + " commits")));
    card.append(el("h2", { class: "release-title" }, e.title || ""));
    if (e.description) {
      for (const p of e.description.split("\n\n")) {
        if (p.trim()) card.append(el("p", { class: "release-desc" }, p.trim()));
      }
    }

    const sectionsEl = el("div", { class: "sections" });
    for (const s of sections) {
      sectionsEl.append(el("section", { class: "section " + (SECTION_CLASS[s.name] || "") },
        el("h3", { class: "section-head " + (SECTION_CLASS[s.name] || "") }, s.name),
        s.items.map((item) => itemNode(item, s.name))));
    }
    card.append(sectionsEl);

    return el("li", {
      class: "release",
      "data-breaking": String(hasBreaking),
      "data-default-dot": sections.some((s) => s.name === "New") ? "new" : "",
    }, card);
  }

  function pageWindow(total) {
    if (total <= 7) {
      return Array.from({ length: total }, (_, i) => i + 1);
    }
    const w = new Set([1, 2, page - 1, page, page + 1, total - 1, total]);
    return [...w].filter((n) => n >= 1 && n <= total).sort((a, b) => a - b);
  }

  function renderPagination(total) {
    if (total <= 1) {
      pagination.replaceChildren();
      return;
    }
    const go = (n) => () => {
      page = n;
      setHash("#page/" + n);
      renderTimeline();
      document.querySelector("main").scrollIntoView({ behavior: "smooth", block: "start" });
    };
    const btn = (n, opts) =>
      el("button", {
        class: "page-btn",
        "aria-current": opts && opts.current ? "page" : null,
        "aria-label": opts && opts.ariaLabel,
        disabled: opts && opts.disabled ? "" : null,
        onclick: opts && opts.disabled ? null : go(n),
      }, opts && opts.label ? [opts.label] : [String(n)]);

    const parts = [
      el("button", {
        class: "page-btn page-nav",
        "aria-label": "Newer releases",
        disabled: page === 1 ? "" : null,
        onclick: page === 1 ? null : go(page - 1),
      }, "← Newer"),
    ];
    let prev = 0;
    for (const n of pageWindow(total)) {
      if (prev && n - prev > 1) parts.push(el("span", { class: "page-dots" }, "…"));
      parts.push(btn(n, { current: n === page, disabled: n === page }));
      prev = n;
    }
    parts.push(el("button", {
      class: "page-btn page-nav",
      "aria-label": "Older releases",
      disabled: page === total ? "" : null,
      onclick: page === total ? null : go(page + 1),
    }, "Older →"));

    pagination.replaceChildren(...parts);
  }

  function renderTimeline() {
    const vr = visibleReleases();
    const total = Math.max(1, Math.ceil(vr.length / PAGE_SIZE));
    if (page > total) page = total;
    if (page < 1) page = 1;
    const slice = vr.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

    timeline.replaceChildren(...slice.map(releaseNode));
    if (!slice.length) {
      showState("No <strong>" + active + "</strong> changes yet.");
      return;
    }
    state.hidden = true;
    renderPagination(total);
  }

  renderFilters();

  const hash = decodeURIComponent(location.hash.slice(1));
  if (/^page\/\d+$/.test(hash)) {
    page = parseInt(hash.split("/")[1], 10) || 1;
    renderTimeline();
  } else {
    const idx = entries.findIndex((e) => anchorId(e.version) === hash);
    if (idx >= 0) {
      const vr = visibleReleases();
      const vrIdx = vr.findIndex((v) => v.entry.version === entries[idx].version);
      page = Math.floor(vrIdx / PAGE_SIZE) + 1;
      renderTimeline();
      const target = document.getElementById(hash);
      if (target) target.scrollIntoView({ block: "start" });
    } else {
      renderTimeline();
    }
  }
})();