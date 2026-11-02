window.createApprovalCards = (view) => {
	const {
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
	} = view;
	// ----- cards -----
	function setBusy(c, busy) {
		c.busy = busy;
		syncDisabled();
	}
	function syncDisabled() {
		for (const id in cards) {
			const c = cards[id],
				off = !view.isConnected() || c.busy;
			for (let i = 0; i < c.buttons.length; i++) c.buttons[i].disabled = off;
			if (c.redirect) c.redirect.disabled = off || !c.note.value.trim();
		}
	}

	function send(c, decision, scope, confirm) {
		setBusy(c, true);
		c.err.textContent = "";
		const body = { decision: decision, scope: scope, note: c.note.value.trim() || undefined };
		if (scope === "intent")
			body.intent = {
				label: c.intentLabel.value,
				access: c.intentAccess.value,
				reasons: c.req.intentProposal.reasons.slice(),
				targets: c.intentTargets.value
					.split("\n")
					.map((v) => v.trim())
					.filter(Boolean),
			};
		if (confirm) body.confirm = true;
		fetch(`/api/requests/${encodeURIComponent(c.req.id)}/decision`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-approver-token": token || "" },
			body: JSON.stringify(body),
		})
			.then((res) => {
				if (res.ok) return; // the resolved event removes the card
				return res
					.json()
					.catch(() => ({}))
					.then((j) => {
						c.err.textContent =
							res.status === 401
								? "Not authorized. Open the link from pi again."
								: j.error || `Request failed (${res.status})`;
						setBusy(c, false);
					});
			})
			.catch(() => {
				c.err.textContent = "Network error. Try again.";
				setBusy(c, false);
			});
	}

	function approveButton(c, label, scope, primary) {
		const b = h("button", `btn${primary ? " primary" : ""}`, label);
		b.type = "button";
		let timer = null;
		function reset() {
			timer = null;
			b.classList.remove("armed");
			b.textContent = label;
		}
		b.addEventListener("click", () => {
			if (c.req.risk === "critical" && !timer) {
				b.classList.add("armed");
				b.textContent = "Confirm: run this critical command";
				timer = setTimeout(reset, 5000);
				return;
			}
			if (timer) {
				clearTimeout(timer);
				reset();
			}
			send(c, "approve", scope, c.req.risk === "critical");
		});
		return b;
	}

	function intentEditor(c) {
		const proposal = c.req.intentProposal;
		const panel = h("div", "intent-editor");
		panel.hidden = true;
		panel.appendChild(h("p", "intent-session", `This session only: ${c.req.sessionLabel} · ${c.req.sessionId}`));
		function field(text, control) {
			const label = h("label", "field", text);
			label.appendChild(control);
			panel.appendChild(label);
			return control;
		}
		c.intentLabel = field("Intent label", h("input"));
		c.intentLabel.type = "text";
		c.intentLabel.maxLength = 160;
		c.intentLabel.value = proposal.label;
		c.intentAccess = field("Access", h("select"));
		["read", "write"].forEach((access) => {
			const option = h("option", "", access === "read" ? "Read only" : "Read and write");
			option.value = access;
			c.intentAccess.appendChild(option);
		});
		c.intentAccess.value = proposal.access;
		c.intentTargets = field("Intent targets (one per line)", h("textarea"));
		c.intentTargets.value = proposal.targets.join("\n");
		c.intentTargets.rows = Math.min(8, Math.max(3, proposal.targets.length));
		panel.appendChild(
			h(
				"p",
				"intent-session",
				"You can narrow this intent. The gate checks the final scope before the command can run.",
			),
		);
		const approve = approveButton(c, "Approve intent", "intent", true);
		c.buttons.push(approve);
		panel.appendChild(approve);
		return panel;
	}

	function projectBlock(cwd) {
		const block = h("div", "project");
		block.appendChild(h("span", "section-label", "Project"));
		block.appendChild(h("strong", "", baseName(cwd) || cwd));
		block.appendChild(h("code", "", cwd));
		return block;
	}

	function pathDetails(r) {
		const details = h("details", "path-details");
		const paths = r.paths || [];
		details.appendChild(h("summary", "", `Files and paths${r.paths ? ` (${paths.length})` : " — unavailable"}`));
		const body = h("div", "path-body");
		const groups = new Map();
		paths.forEach((entry) => {
			const slash = entry.path.lastIndexOf("/");
			const directory = entry.unresolved ? "Unresolved paths" : slash === 0 ? "/" : `${entry.path.slice(0, slash)}/`;
			const name = entry.unresolved ? entry.path : entry.path.slice(slash + 1) || "/";
			if (!groups.has(directory)) groups.set(directory, []);
			groups.get(directory).push({ entry: entry, name: name });
		});
		groups.forEach((files, directory) => {
			const group = h("div", "path-group");
			group.appendChild(h("code", "path-directory", directory));
			const list = h("ul", "path-list");
			files.forEach((file) => {
				const row = h("li");
				row.appendChild(h("span", "", file.name));
				row.appendChild(h("span", "path-role", file.entry.role));
				if (file.entry.inspected) row.appendChild(h("span", "path-status", "Code inspected"));
				if (file.entry.unresolved) row.appendChild(h("span", "path-role", "Unresolved"));
				list.appendChild(row);
			});
			group.appendChild(list);
			body.appendChild(group);
		});
		body.appendChild(
			h(
				"p",
				"path-note",
				r.paths
					? "Static references only. Runtime code can construct additional paths. File contents are not stored here."
					: "This request did not include a path inspection. Review the exact command.",
			),
		);
		(r.pathNotes || []).forEach((note) => {
			body.appendChild(h("p", "path-note", note));
		});
		details.appendChild(body);
		return details;
	}

	function buildCard(r) {
		const c = { req: r, busy: false, expanded: false, leaving: false, buttons: [] };
		const el = h("article", `card risk-${r.risk}`);
		c.el = el;

		const top = h("div", "top");
		top.appendChild(h("span", "badge", r.risk === "critical" ? "CRITICAL" : `${r.risk.toUpperCase()} RISK`));
		if (r.kind !== "lockdown") {
			if (r.recommendation === "approve") top.appendChild(h("span", "pill approve", "Recommended: APPROVE"));
			else if (r.recommendation === "deny") top.appendChild(h("span", "pill deny", "Recommended: DENY"));
			else top.appendChild(h("span", "pill review", "Needs your review"));
		}
		c.timeEl = h("span", "time");
		top.appendChild(c.timeEl);
		el.appendChild(top);
		c.parked = h("div", "parked", "Agent stopped waiting — your answer is still delivered");
		c.parked.hidden = !r.parked;
		el.appendChild(c.parked);

		el.appendChild(projectBlock(r.cwd));
		el.appendChild(h("span", "section-label", "Execution summary"));
		el.appendChild(h("p", "tldr", r.tldr));
		el.appendChild(pathDetails(r));
		if (r.kind === "lockdown") {
			el.appendChild(
				h(
					"div",
					"lock",
					"Lockdown: the agent was blocked several times. Every command needs your approval until you lift it.",
				),
			);
		}

		const cw = h("div", "cmd-wrap");
		c.cmd = h("pre", "cmd-text", r.command);
		const box = h("div", "cmd");
		box.appendChild(c.cmd);
		c.toggle = h("button", "link toggle", "Show more");
		c.toggle.type = "button";
		c.toggle.hidden = true;
		c.toggle.addEventListener("click", () => {
			c.expanded = !c.expanded;
			c.cmd.classList.toggle("open", c.expanded);
			c.toggle.textContent = c.expanded ? "Show less" : "Show more";
		});
		cw.appendChild(box);
		cw.appendChild(c.toggle);
		el.appendChild(cw);

		if (r.reasons.length) {
			const chips = h("div", "chips");
			r.reasons.forEach((x) => {
				chips.appendChild(h("span", "chip", x));
			});
			el.appendChild(chips);
		}

		const meta = h("div", "meta");
		if (r.model) meta.appendChild(h("span", "", `Model: ${r.model}`));
		c.expEl = h("span");
		meta.appendChild(c.expEl);
		el.appendChild(meta);

		const actions = h("div", "actions");
		c.note = h("input", "note");
		c.note.type = "text";
		c.note.maxLength = 500;
		c.note.placeholder = "Note for the agent (optional)";
		c.note.setAttribute("aria-label", "Note for the agent (optional)");
		const noteLabel = h("label", "field note-field", "Note or redirect instruction");
		noteLabel.appendChild(c.note);
		el.appendChild(noteLabel);
		c.note.addEventListener("input", syncDisabled);
		const approve = approveButton(c, r.kind === "lockdown" ? "Approve this command" : "Approve once", "once", true);
		c.buttons.push(approve);
		actions.appendChild(approve);
		if (r.kind === "lockdown") {
			const lift = approveButton(c, "Approve and lift lockdown", "session", false);
			c.buttons.push(lift);
			actions.appendChild(lift);
		}
		let editor;
		if (r.intentProposal) {
			editor = intentEditor(c);
			const grant = h("button", "btn", "Approve for session…");
			grant.type = "button";
			grant.setAttribute("aria-expanded", "false");
			grant.addEventListener("click", () => {
				editor.hidden = !editor.hidden;
				grant.setAttribute("aria-expanded", editor.hidden ? "false" : "true");
				if (!editor.hidden) c.intentLabel.focus();
			});
			c.buttons.push(grant);
			actions.appendChild(grant);
		}
		c.redirect = h("button", "btn", "Redirect…");
		c.redirect.type = "button";
		c.redirect.title = "Enter an instruction in the note field to redirect.";
		c.redirect.addEventListener("click", () => {
			send(c, "redirect", "once", false);
		});
		c.buttons.push(c.redirect);
		actions.appendChild(c.redirect);
		const deny = h("button", "btn", "Deny");
		deny.type = "button";
		deny.addEventListener("click", () => {
			send(c, "deny", "once", false);
		});
		c.buttons.push(deny);
		actions.appendChild(deny);
		c.err = h("div", "err");
		c.err.setAttribute("role", "alert");
		actions.appendChild(c.err);
		el.appendChild(actions);
		if (editor) el.appendChild(editor);

		updateTimes(c);
		return c;
	}

	function updateTimes(c) {
		c.timeEl.textContent = rel(c.req.createdAt);
		c.expEl.textContent = left(c.req.expiresAt);
	}

	function measure(c) {
		if (c.expanded) return;
		c.toggle.hidden = c.cmd.scrollHeight <= c.cmd.clientHeight + 1;
	}

	// Put children in order without moving nodes that are already right.
	function place(parent, kids) {
		for (let i = 0; i < kids.length; i++) {
			if (parent.children[i] !== kids[i]) parent.insertBefore(kids[i], parent.children[i] || null);
		}
	}

	function render() {
		const bySession = {};
		for (const id in cards) {
			const c = cards[id],
				sid = c.req.sessionId;
			bySession[sid] ??= [];
			bySession[sid].push(c);
		}
		const order = Object.keys(bySession);
		order.forEach((sid) => {
			bySession[sid].sort((a, b) => b.req.createdAt - a.req.createdAt);
		});
		order.sort((a, b) => bySession[b][0].req.createdAt - bySession[a][0].req.createdAt);

		for (const gid in groups) {
			if (!bySession[gid]) {
				groups[gid].remove();
				delete groups[gid];
			}
		}
		const groupEls = order.map((sid) => {
			let first = bySession[sid][0].req,
				g = groups[sid];
			if (!g) {
				g = h("section", "group");
				g.appendChild(h("h2", "group-title"));
				g.appendChild(h("div", "cards"));
				groups[sid] = g;
			}
			const t = g.firstChild;
			t.textContent = first.sessionLabel || "Session";
			const folder = baseName(first.cwd);
			t.appendChild(h("span", "", (folder === first.sessionLabel ? "" : `${folder} \u00B7 `) + sid.slice(0, 8)));
			place(
				g.lastChild,
				bySession[sid].map((c) => c.el),
			);
			return g;
		});
		place(listEl, groupEls);

		for (const k in cards) measure(cards[k]);
		const n = pendingCount();
		countEl.textContent = `${n} pending`;
		tabPendingEl.textContent = `Pending (${n})`;
		emptyEl.hidden = n > 0 || Object.keys(cards).length > 0;
		updateTitle();
		syncDisabled();
	}

	function addCard(r) {
		if (cards[r.id]) {
			cards[r.id].req.parked = r.parked;
			cards[r.id].parked.hidden = !r.parked;
			return false;
		}
		cards[r.id] = buildCard(r);
		return true;
	}

	function removeCard(id) {
		const c = cards[id];
		if (!c || c.leaving) return;
		c.leaving = true;
		c.el.classList.add("leaving");
		setTimeout(() => {
			c.el.remove();
			if (cards[id] === c) delete cards[id];
			render();
		}, 380);
		render();
	}

	return { syncDisabled, projectBlock, pathDetails, measure, render, addCard, removeCard, updateTimes };
};
