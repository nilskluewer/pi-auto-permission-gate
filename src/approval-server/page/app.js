(() => {
	const TITLE = "Permission Gate";
	let token = null;
	try {
		const m = /[#&]a=([^&]+)/.exec(location.hash);
		if (m) {
			token = decodeURIComponent(m[1]);
			sessionStorage.setItem("pg-token", token);
			history.replaceState(null, "", location.pathname + location.search);
		} else {
			token = sessionStorage.getItem("pg-token");
		}
	} catch (_e) {}

	const $ = (id) => document.getElementById(id);
	const listEl = $("list"),
		emptyEl = $("empty"),
		bannerEl = $("banner"),
		dotEl = $("dot"),
		countEl = $("count"),
		notifyEl = $("notify"),
		themeEl = $("theme");
	const tabPendingEl = $("tab-pending");
	const cards = {}; // id -> card object
	const groups = {}; // sessionId -> group element
	let connected = false;
	let flashTimer = null,
		flashOn = false;

	function h(tag, cls, text) {
		const el = document.createElement(tag);
		if (cls) el.className = cls;
		if (text !== undefined) el.textContent = text;
		return el;
	}

	function pendingCount() {
		let n = 0;
		for (const id in cards) if (!cards[id].leaving) n++;
		return n;
	}

	function baseName(p) {
		const parts = String(p).split(/[\\/]/).filter(Boolean);
		return parts.length ? parts[parts.length - 1] : String(p);
	}

	function rel(ms) {
		const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
		if (s < 10) return "just now";
		if (s < 60) return `${s}s ago`;
		if (s < 3600) return `${Math.floor(s / 60)}m ago`;
		return `${Math.floor(s / 3600)}h ago`;
	}

	function left(ms) {
		const s = Math.round((ms - Date.now()) / 1000);
		if (s <= 0) return "expired";
		const mm = Math.floor(s / 60),
			ss = s % 60;
		return `expires in ${mm}:${ss < 10 ? "0" : ""}${ss}`;
	}

	// ----- title, favicon, notifications -----
	function setIcon(n) {
		const color = n ? "#f85149" : "#6e7681";
		const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="13" fill="${color}"/></svg>`;
		const icon = /** @type {HTMLLinkElement} */ ($("icon"));
		icon.href = `data:image/svg+xml,${encodeURIComponent(svg)}`;
	}
	function updateTitle() {
		const n = pendingCount();
		document.title = n ? (flashOn ? "\u26A0 Needs approval" : `(${n}) ${TITLE}`) : TITLE;
		setIcon(n);
	}
	function startFlash() {
		if (flashTimer) return;
		flashTimer = setInterval(() => {
			flashOn = !flashOn;
			updateTitle();
		}, 1000);
	}
	function stopFlash() {
		if (flashTimer) clearInterval(flashTimer);
		flashTimer = null;
		flashOn = false;
		updateTitle();
	}
	document.addEventListener("visibilitychange", () => {
		if (!document.hidden) stopFlash();
	});

	function refreshNotifyLink() {
		notifyEl.hidden = !("Notification" in window) || Notification.permission !== "default";
	}
	notifyEl.addEventListener("click", () => {
		if ("Notification" in window) Notification.requestPermission().then(refreshNotifyLink, refreshNotifyLink);
	});
	refreshNotifyLink();

	// ----- theme toggling (sharp, pastel, dark/light) -----
	let savedTheme = null;
	try {
		savedTheme = localStorage.getItem("pg-theme");
	} catch (_e) {}
	function applyTheme(t) {
		if (t === "light" || t === "dark") {
			document.documentElement.setAttribute("data-theme", t);
			if (themeEl) themeEl.textContent = t === "light" ? "Dark mode" : "Light mode";
		} else {
			document.documentElement.removeAttribute("data-theme");
			const isLight = window.matchMedia?.("(prefers-color-scheme: light)").matches;
			if (themeEl) themeEl.textContent = isLight ? "Dark mode" : "Light mode";
		}
	}
	if (savedTheme) applyTheme(savedTheme);
	else applyTheme("auto");
	if (themeEl) {
		themeEl.addEventListener("click", () => {
			let current = document.documentElement.getAttribute("data-theme");
			if (!current) {
				const isLight = window.matchMedia?.("(prefers-color-scheme: light)").matches;
				current = isLight ? "light" : "dark";
			}
			const next = current === "light" ? "dark" : "light";
			applyTheme(next);
			try {
				localStorage.setItem("pg-theme", next);
			} catch (_e) {}
		});
	}
	if (window.matchMedia) {
		window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
			try {
				if (!localStorage.getItem("pg-theme")) applyTheme("auto");
			} catch (_e) {}
		});
	}

	function notifyNew(r) {
		if (!document.hidden) return;
		startFlash();
		try {
			if ("Notification" in window && Notification.permission === "granted") {
				new Notification(`Permission Gate: ${r.risk}`, { body: r.tldr, tag: r.id });
			}
		} catch (_e) {}
	}

	const cardView = window.createApprovalCards({
		h,
		baseName,
		rel,
		left,
		cards,
		groups,
		listEl,
		emptyEl,
		countEl,
		tabPendingEl,
		pendingCount,
		updateTitle,
		token,
		isConnected: () => connected,
	});
	const { syncDisabled, projectBlock, pathDetails, measure, render, addCard, removeCard, updateTimes } = cardView;
	// ----- connection -----
	function setConnected(on) {
		connected = on;
		dotEl.classList.toggle("on", on);
		dotEl.setAttribute("aria-label", on ? "Connected" : "Disconnected");
		bannerEl.hidden = on;
		syncDisabled();
	}

	let es = null,
		backoff = 1000,
		retryTimer = null;
	function connect() {
		if (!token) {
			bannerEl.textContent = "No access token. Open the link that pi opened for you.";
			bannerEl.hidden = false;
			return;
		}
		es = new EventSource(`/api/events?a=${encodeURIComponent(token)}`);
		es.onopen = () => {
			backoff = 1000;
			setConnected(true);
		};
		es.onerror = () => {
			es.close();
			setConnected(false);
			clearTimeout(retryTimer);
			retryTimer = setTimeout(connect, backoff);
			backoff = Math.min(backoff * 2, 15000);
		};
		es.addEventListener("snapshot", (e) => {
			const data = JSON.parse(e.data),
				seen = {};
			data.pending.forEach((r) => {
				seen[r.id] = true;
				addCard(r);
			});
			Object.keys(cards).forEach((id) => {
				if (!seen[id]) removeCard(id);
			});
			render();
			setHistory(data.history || []);
		});
		es.addEventListener("added", (e) => {
			const r = JSON.parse(e.data);
			if (addCard(r)) {
				render();
				notifyNew(r);
			}
		});
		es.addEventListener("parked", (e) => {
			const c = cards[JSON.parse(e.data).id];
			if (c) {
				c.req.parked = true;
				c.parked.hidden = false;
			}
		});
		es.addEventListener("resolved", (e) => {
			removeCard(JSON.parse(e.data).id);
		});
		es.addEventListener("history", (e) => {
			addHistoryEntry(JSON.parse(e.data));
		});
		es.addEventListener("replaced", () => {
			// The server restarts with new code on a new port. This tab cannot reconnect.
			es.close();
			clearTimeout(retryTimer);
			es.onerror = null;
			setConnected(false);
			bannerEl.textContent =
				"The approval server was updated. Pi opens a new tab with the next request. You can close this tab.";
			bannerEl.hidden = false;
		});
	}

	const historyView = window.createApprovalHistory({ $, h, baseName, projectBlock, pathDetails });
	const { setHistory, addHistoryEntry, updateHistoryMeta, tabHistoryEl, panelPending, panelHistory } = historyView;
	// ----- tabs -----
	const tabs = { pending: tabPendingEl, history: tabHistoryEl };
	const panels = { pending: panelPending, history: panelHistory };
	const tabNames = ["pending", "history"];
	function selectTab(name, focus) {
		tabNames.forEach((k) => {
			const on = k === name;
			tabs[k].setAttribute("aria-selected", on ? "true" : "false");
			tabs[k].tabIndex = on ? 0 : -1;
			panels[k].hidden = !on;
		});
		try {
			sessionStorage.setItem("pg-tab", name);
		} catch (_e) {}
		if (focus) tabs[name].focus();
		if (name === "pending") for (const id in cards) measure(cards[id]);
	}
	tabNames.forEach((name, i) => {
		tabs[name].addEventListener("click", () => {
			selectTab(name, false);
		});
		tabs[name].addEventListener("keydown", (ev) => {
			const next =
				ev.key === "ArrowRight"
					? (i + 1) % 2
					: ev.key === "ArrowLeft"
						? (i + 1) % 2
						: ev.key === "Home"
							? 0
							: ev.key === "End"
								? 1
								: -1;
			if (next < 0) return;
			ev.preventDefault();
			selectTab(tabNames[next], true);
		});
	});
	let savedTab = null;
	try {
		savedTab = sessionStorage.getItem("pg-tab");
	} catch (_e) {}

	setInterval(() => {
		for (const id in cards) updateTimes(cards[id]);
	}, 1000);
	window.addEventListener("resize", () => {
		for (const id in cards) measure(cards[id]);
	});

	render();
	updateHistoryMeta();
	selectTab(savedTab === "history" ? "history" : "pending", false);
	setConnected(false);
	connect();
})();
