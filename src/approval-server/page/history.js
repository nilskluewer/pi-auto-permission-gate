window.createApprovalHistory = (view) => {
	const { $, h, baseName, projectBlock, pathDetails } = view;
	// ----- history -----
	const HMAX = 500;
	let hist = []; // newest first
	let histIds = {}; // id -> true
	let rows = {}; // id -> <li>
	let hFilter = "all",
		hQuery = "",
		expandedId = null;
	const hlistEl = $("hlist"),
		hemptyEl = $("hempty"),
		showingEl = $("showing"),
		tabHistoryEl = $("tab-history"),
		searchEl = $("search");
	const panelPending = $("panel-pending"),
		panelHistory = $("panel-history");
	const SRC = { auto: "Auto", human: "You", rule: "Rule", "hard-deny": "Hard deny", grant: "Grant" };

	function pad(n) {
		return n < 10 ? `0${n}` : `${n}`;
	}
	function clock(d) {
		return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
	}

	function matches(e) {
		if (hFilter !== "all" && e.status !== hFilter) return false;
		if (!hQuery) return true;
		const hay =
			e.command +
			"\n" +
			e.tldr +
			"\n" +
			e.sessionLabel +
			"\n" +
			e.cwd +
			"\n" +
			e.reasons.join("\n") +
			"\n" +
			(e.paths || []).map((p) => p.path).join("\n");
		return hay.toLowerCase().indexOf(hQuery) !== -1;
	}

	function buildDetail(e) {
		const d = h("div", "hdetail");
		d.appendChild(projectBlock(e.cwd));
		d.appendChild(pathDetails(e));
		const box = h("div", "cmd");
		box.appendChild(h("pre", "cmd-text scroll", e.command));
		d.appendChild(box);
		if (e.reasons.length) {
			const chips = h("div", "chips");
			e.reasons.forEach((x) => {
				chips.appendChild(h("span", "chip", x));
			});
			d.appendChild(chips);
		}
		const meta = h("div", "meta");
		meta.appendChild(h("span", "", new Date(e.ts).toLocaleString()));
		const folder = baseName(e.cwd),
			label = e.sessionLabel || "Session";
		meta.appendChild(h("span", "", `Session: ${label}${folder === label ? "" : ` (${folder})`}`));
		if (e.model) meta.appendChild(h("span", "", `Model: ${e.model}`));
		if (e.via) meta.appendChild(h("span", "", `Via: ${e.via}`));
		if (e.recommendation) meta.appendChild(h("span", "", `Recommended: ${e.recommendation}`));
		if (e.scope) meta.appendChild(h("span", "", `Scope: ${e.scope}`));
		if (e.grantId) meta.appendChild(h("span", "", `Grant: ${e.grantId}`));
		if (Number.isFinite(e.shownAt)) meta.appendChild(h("span", "", `Shown: ${new Date(e.shownAt).toLocaleString()}`));
		if (Number.isFinite(e.answeredAt))
			meta.appendChild(h("span", "", `Answered: ${new Date(e.answeredAt).toLocaleString()}`));
		d.appendChild(meta);
		if (e.note) d.appendChild(h("div", "hnote", `Note: ${e.note}`));
		return d;
	}

	function setOpen(li, open) {
		li.classList.toggle("open", open);
		li.firstChild.setAttribute("aria-expanded", open ? "true" : "false");
		const det = li.querySelector(".hdetail");
		if (open && !det) li.appendChild(buildDetail(li._e));
		if (!open && det) det.remove();
	}

	function buildRow(e) {
		const li = h("li", "hrow");
		li._e = e;
		const head = h("button", "hhead");
		head.type = "button";
		head.setAttribute("aria-expanded", "false");
		const d = new Date(e.ts);
		const t = h("span", "htime", clock(d));
		if (d.toDateString() !== new Date().toDateString()) {
			t.appendChild(h("small", "", d.toLocaleDateString([], { day: "numeric", month: "short" })));
		}
		head.appendChild(t);
		const statusStyle = { approved: "approve", denied: "deny", redirected: "redirected", expired: "expired" };
		const statusText = { approved: "Approved", denied: "Denied", redirected: "Redirected", expired: "Expired" };
		head.appendChild(h("span", `pill ${statusStyle[e.status] || "review"}`, statusText[e.status] || "Unknown"));
		head.appendChild(h("span", "hsrc", SRC[e.source] || e.source || "Unknown"));
		head.appendChild(h("span", `badge b-${e.risk}`, e.risk.toUpperCase()));
		const main = h("span", "hmain");
		main.appendChild(h("span", "htldr", e.tldr));
		const sub = h("span", "hsub");
		sub.appendChild(h("span", "lbl", e.sessionLabel));
		sub.appendChild(h("code", "", e.command.split("\n")[0]));
		main.appendChild(sub);
		head.appendChild(main);
		head.addEventListener("click", () => {
			const open = !li.classList.contains("open");
			const prev = hlistEl.querySelector(".hrow.open");
			if (prev && prev !== li) setOpen(prev, false);
			setOpen(li, open);
			expandedId = open ? e.id : null;
		});
		li.appendChild(head);
		rows[e.id] = li;
		return li;
	}

	function updateHistoryMeta() {
		const total = hist.length,
			shown = hlistEl.children.length;
		tabHistoryEl.textContent = `History (${total})`;
		showingEl.textContent = `Showing ${shown} of ${total}`;
		hlistEl.hidden = shown === 0;
		hemptyEl.hidden = shown > 0;
		$("hempty-t").textContent = total === 0 ? "No decisions yet" : "No matching decisions";
		$("hempty-s").textContent = total === 0 ? "Decisions will be listed here." : "Try another filter or search.";
	}

	function renderHistory() {
		const frag = document.createDocumentFragment();
		rows = {};
		hist.forEach((e) => {
			if (!matches(e)) return;
			const li = buildRow(e);
			if (e.id === expandedId) setOpen(li, true);
			frag.appendChild(li);
		});
		hlistEl.textContent = "";
		hlistEl.appendChild(frag);
		updateHistoryMeta();
	}

	function setHistory(list) {
		hist = list.slice(0, HMAX);
		histIds = {};
		hist.forEach((e) => {
			histIds[e.id] = true;
		});
		renderHistory();
	}

	// Insert one new entry at the top. Keep scroll position and open rows.
	function addHistoryEntry(e) {
		if (histIds[e.id]) {
			const index = hist.findIndex((entry) => entry.id === e.id);
			if (index >= 0) hist[index] = e;
			renderHistory();
			return;
		}
		histIds[e.id] = true;
		hist.unshift(e);
		if (hist.length > HMAX) {
			const old = hist.pop();
			delete histIds[old.id];
			if (rows[old.id]) {
				rows[old.id].remove();
				delete rows[old.id];
			}
		}
		if (matches(e)) {
			const before = document.documentElement.scrollHeight;
			hlistEl.insertBefore(buildRow(e), hlistEl.firstChild);
			if (!panelHistory.hidden && window.scrollY > 0)
				window.scrollBy(0, document.documentElement.scrollHeight - before);
		}
		updateHistoryMeta();
	}

	const filterBtns = document.querySelectorAll(".seg button");
	Array.prototype.forEach.call(filterBtns, (b) => {
		b.addEventListener("click", () => {
			hFilter = b.getAttribute("data-f");
			Array.prototype.forEach.call(filterBtns, (o) => {
				o.setAttribute("aria-pressed", o === b ? "true" : "false");
			});
			renderHistory();
		});
	});
	searchEl.addEventListener("input", () => {
		hQuery = searchEl.value.trim().toLowerCase();
		renderHistory();
	});

	return { setHistory, addHistoryEntry, updateHistoryMeta, tabHistoryEl, panelPending, panelHistory };
};
