// @ts-nocheck
// biome-ignore-all lint: Browser code uses DOM values and plain script factory bindings.
// biome-ignore-all format: Keep the inline page source layout stable.
window.createApprovalHistory = function (view) {
  var { $, h, baseName, projectBlock, pathDetails } = view;
  // ----- history -----
  var HMAX = 500;
  var hist = [];           // newest first
  var histIds = {};        // id -> true
  var rows = {};           // id -> <li>
  var hFilter = 'all', hQuery = '', expandedId = null;
  var hlistEl = $('hlist'), hemptyEl = $('hempty'), showingEl = $('showing'), tabHistoryEl = $('tab-history'), searchEl = $('search');
  var panelPending = $('panel-pending'), panelHistory = $('panel-history');
  var SRC = { auto: 'Auto', human: 'You', rule: 'Rule', 'hard-deny': 'Hard deny', grant: 'Grant' };

  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function clock(d) { return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }

  function matches(e) {
    if (hFilter !== 'all' && e.status !== hFilter) return false;
    if (!hQuery) return true;
    var hay = e.command + '\n' + e.tldr + '\n' + e.sessionLabel + '\n' + e.cwd + '\n' + e.reasons.join('\n') + '\n' + (e.paths || []).map(function (p) { return p.path; }).join('\n');
    return hay.toLowerCase().indexOf(hQuery) !== -1;
  }

  function buildDetail(e) {
    var d = h('div', 'hdetail');
    d.appendChild(projectBlock(e.cwd));
    d.appendChild(pathDetails(e));
    var box = h('div', 'cmd');
    box.appendChild(h('pre', 'cmd-text scroll', e.command));
    d.appendChild(box);
    if (e.reasons.length) {
      var chips = h('div', 'chips');
      e.reasons.forEach(function (x) { chips.appendChild(h('span', 'chip', x)); });
      d.appendChild(chips);
    }
    var meta = h('div', 'meta');
    meta.appendChild(h('span', '', new Date(e.ts).toLocaleString()));
    var folder = baseName(e.cwd), label = e.sessionLabel || 'Session';
    meta.appendChild(h('span', '', 'Session: ' + label + (folder === label ? '' : ' (' + folder + ')')));
    if (e.model) meta.appendChild(h('span', '', 'Model: ' + e.model));
    if (e.via) meta.appendChild(h('span', '', 'Via: ' + e.via));
    if (e.recommendation) meta.appendChild(h('span', '', 'Recommended: ' + e.recommendation));
    if (e.scope) meta.appendChild(h('span', '', 'Scope: ' + e.scope));
    if (e.grantId) meta.appendChild(h('span', '', 'Grant: ' + e.grantId));
    if (Number.isFinite(e.shownAt)) meta.appendChild(h('span', '', 'Shown: ' + new Date(e.shownAt).toLocaleString()));
    if (Number.isFinite(e.answeredAt)) meta.appendChild(h('span', '', 'Answered: ' + new Date(e.answeredAt).toLocaleString()));
    d.appendChild(meta);
    if (e.note) d.appendChild(h('div', 'hnote', 'Note: ' + e.note));
    return d;
  }

  function setOpen(li, open) {
    li.classList.toggle('open', open);
    li.firstChild.setAttribute('aria-expanded', open ? 'true' : 'false');
    var det = li.querySelector('.hdetail');
    if (open && !det) li.appendChild(buildDetail(li._e));
    if (!open && det) det.remove();
  }

  function buildRow(e) {
    var li = h('li', 'hrow');
    li._e = e;
    var head = h('button', 'hhead');
    head.type = 'button';
    head.setAttribute('aria-expanded', 'false');
    var d = new Date(e.ts);
    var t = h('span', 'htime', clock(d));
    if (d.toDateString() !== new Date().toDateString()) {
      t.appendChild(h('small', '', d.toLocaleDateString([], { day: 'numeric', month: 'short' })));
    }
    head.appendChild(t);
    var statusStyle = { approved: 'approve', denied: 'deny', redirected: 'redirected', expired: 'expired' };
    var statusText = { approved: 'Approved', denied: 'Denied', redirected: 'Redirected', expired: 'Expired' };
    head.appendChild(h('span', 'pill ' + (statusStyle[e.status] || 'review'), statusText[e.status] || 'Unknown'));
    head.appendChild(h('span', 'hsrc', SRC[e.source] || e.source || 'Unknown'));
    head.appendChild(h('span', 'badge b-' + e.risk, e.risk.toUpperCase()));
    var main = h('span', 'hmain');
    main.appendChild(h('span', 'htldr', e.tldr));
    var sub = h('span', 'hsub');
    sub.appendChild(h('span', 'lbl', e.sessionLabel));
    sub.appendChild(h('code', '', e.command.split('\n')[0]));
    main.appendChild(sub);
    head.appendChild(main);
    head.addEventListener('click', function () {
      var open = !li.classList.contains('open');
      var prev = hlistEl.querySelector('.hrow.open');
      if (prev && prev !== li) setOpen(prev, false);
      setOpen(li, open);
      expandedId = open ? e.id : null;
    });
    li.appendChild(head);
    rows[e.id] = li;
    return li;
  }

  function updateHistoryMeta() {
    var total = hist.length, shown = hlistEl.children.length;
    tabHistoryEl.textContent = 'History (' + total + ')';
    showingEl.textContent = 'Showing ' + shown + ' of ' + total;
    hlistEl.hidden = shown === 0;
    hemptyEl.hidden = shown > 0;
    $('hempty-t').textContent = total === 0 ? 'No decisions yet' : 'No matching decisions';
    $('hempty-s').textContent = total === 0 ? 'Decisions will be listed here.' : 'Try another filter or search.';
  }

  function renderHistory() {
    var frag = document.createDocumentFragment();
    rows = {};
    hist.forEach(function (e) {
      if (!matches(e)) return;
      var li = buildRow(e);
      if (e.id === expandedId) setOpen(li, true);
      frag.appendChild(li);
    });
    hlistEl.textContent = '';
    hlistEl.appendChild(frag);
    updateHistoryMeta();
  }

  function setHistory(list) {
    hist = list.slice(0, HMAX);
    histIds = {};
    hist.forEach(function (e) { histIds[e.id] = true; });
    renderHistory();
  }

  // Insert one new entry at the top. Keep scroll position and open rows.
  function addHistoryEntry(e) {
    if (histIds[e.id]) {
      var index = hist.findIndex(function (entry) { return entry.id === e.id; });
      if (index >= 0) hist[index] = e;
      renderHistory();
      return;
    }
    histIds[e.id] = true;
    hist.unshift(e);
    if (hist.length > HMAX) {
      var old = hist.pop();
      delete histIds[old.id];
      if (rows[old.id]) { rows[old.id].remove(); delete rows[old.id]; }
    }
    if (matches(e)) {
      var before = document.documentElement.scrollHeight;
      hlistEl.insertBefore(buildRow(e), hlistEl.firstChild);
      if (!panelHistory.hidden && window.scrollY > 0) window.scrollBy(0, document.documentElement.scrollHeight - before);
    }
    updateHistoryMeta();
  }

  var filterBtns = document.querySelectorAll('.seg button');
  Array.prototype.forEach.call(filterBtns, function (b) {
    b.addEventListener('click', function () {
      hFilter = b.getAttribute('data-f');
      Array.prototype.forEach.call(filterBtns, function (o) { o.setAttribute('aria-pressed', o === b ? 'true' : 'false'); });
      renderHistory();
    });
  });
  searchEl.addEventListener('input', function () {
    hQuery = searchEl.value.trim().toLowerCase();
    renderHistory();
  });


  return { setHistory, addHistoryEntry, updateHistoryMeta, tabHistoryEl, panelPending, panelHistory };
};
