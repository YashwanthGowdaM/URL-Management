'use strict';
const $ = (s, r = document) => r.querySelector(s);
const state = { links: [], auth: { authenticated: false }, pendingId: null, editId: null, deleteLink: null };

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else e.setAttribute(k, v);
  }
  e.append(...kids);
  return e;
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (method !== 'GET' && state.auth.csrf) headers['X-CSRF-Token'] = state.auth.csrf;
  const res = await fetch('/api' + path, { method, headers, credentials: 'same-origin', body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && state.auth.authenticated) { state.auth = { authenticated: false }; renderAll(); }
    throw Object.assign(new Error(data.error || 'Request failed.'), { status: res.status });
  }
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg; t.classList.add('on');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('on'), 2600);
}

const safeHref = (u) => { try { const x = new URL(u); return /^https?:$/.test(x.protocol) ? x.href : '#'; } catch { return '#'; } };
const btn = (text, onclick, cls = 'small') => h('button', { type: 'button', class: cls, onclick }, text);

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('URL copied'); } catch { toast('Copy is not available in this browser'); }
}

function renderList() {
  const q = $('#q').value.trim().toLowerCase();
  const rows = state.links.filter((l) => !q || [l.label, l.url, l.description].some((s) => s.toLowerCase().includes(q)));
  const list = $('#list');
  list.replaceChildren();
  if (!rows.length) {
    list.append(h('p', { class: 'empty' }, state.links.length
      ? 'Nothing matches that search.'
      : state.auth.authenticated ? 'No links yet. Use Add link to create the first one.' : 'No links have been added yet.'));
  }
  for (const l of rows) {
    const actions = h('div', { class: 'actions' }, btn('Copy', () => copy(l.url)));
    if (state.auth.authenticated) actions.append(btn('Edit', () => openLinkForm(l)), btn('Delete', () => openDelete(l), 'small danger'));
    list.append(h('article', { class: 'row' },
      h('a', { class: 'label', href: safeHref(l.url), target: '_blank', rel: 'noopener noreferrer' }, l.label),
      h('p', { class: 'desc' }, l.description),
      h('div', { class: 'url', title: l.url }, l.url),
      actions));
  }
  const n = state.links.length;
  $('#count').textContent = q ? `${rows.length} of ${n} links` : `${n} ${n === 1 ? 'link' : 'links'}`;
}

function renderSession() {
  const box = $('#session');
  box.replaceChildren();
  if (state.auth.authenticated) {
    box.append(h('p', { class: 'who' }, `Signed in as ${state.auth.user}`),
      btn('Add link', () => openLinkForm(null), 'primary'),
      btn('Sign out', signOut, ''));
  } else {
    box.append(btn('Sign in to edit', openLogin, ''));
  }
}
const renderAll = () => { renderSession(); renderList(); };

async function loadLinks() {
  try { state.links = await api('/links'); } catch (e) { toast(e.message); }
  renderList();
}

/* ---- dialogs ---- */
const setErr = (form, msg = '') => { $('.err', form).textContent = msg; };
const busy = (form, on) => form.querySelectorAll('button').forEach((b) => { b.disabled = on; });
document.addEventListener('click', (e) => { const c = e.target.closest('[data-close]'); if (c) c.closest('dialog').close(); });

function openLogin() {
  const dlg = $('#dlg-login');
  for (const f of dlg.querySelectorAll('form')) { f.reset(); setErr(f); }
  $('#f-cred').hidden = false; $('#f-totp').hidden = true;
  dlg.showModal(); $('#f-cred [name=username]').focus();
}

$('#f-cred').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.currentTarget, d = Object.fromEntries(new FormData(f));
  setErr(f); busy(f, true);
  try {
    const r = await api('/auth/login', { method: 'POST', body: d });
    state.pendingId = r.pending;
    $('#enroll').hidden = !r.enroll;
    $('#totp-hint').hidden = r.enroll;
    if (r.enroll) { $('#qr').src = r.qr; $('#secret').textContent = r.secret; }
    f.reset(); f.hidden = true; $('#f-totp').hidden = false; $('#f-totp [name=code]').focus();
  } catch (err) { setErr(f, err.message); } finally { busy(f, false); }
});

$('#f-totp').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.currentTarget, code = new FormData(f).get('code');
  setErr(f); busy(f, true);
  try {
    const r = await api('/auth/verify', { method: 'POST', body: { pending: state.pendingId, code } });
    state.auth = { authenticated: true, user: r.user, csrf: r.csrf };
    $('#qr').removeAttribute('src'); $('#secret').textContent = '';
    $('#dlg-login').close(); renderAll(); toast('Signed in');
  } catch (err) {
    setErr(f, err.message);
    if (err.status === 401 && /timed out/.test(err.message) || err.status === 429) { f.hidden = true; $('#f-cred').hidden = false; setErr($('#f-cred'), err.message); }
  } finally { busy(f, false); }
});

async function signOut() {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* session already gone */ }
  state.auth = { authenticated: false }; renderAll(); toast('Signed out');
}

function openLinkForm(link) {
  const f = $('#f-link');
  f.reset(); setErr(f);
  state.editId = link ? link.id : null;
  $('#link-title').textContent = link ? 'Edit link' : 'Add link';
  if (link) for (const k of ['label', 'url', 'description']) f.elements[k].value = link[k];
  $('#dlg-link').showModal(); f.elements.label.focus();
}

$('#f-link').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.currentTarget, body = Object.fromEntries(new FormData(f));
  setErr(f); busy(f, true);
  try {
    const editing = state.editId !== null;
    await api(editing ? `/links/${state.editId}` : '/links', { method: editing ? 'PUT' : 'POST', body });
    $('#dlg-link').close(); await loadLinks(); toast(editing ? 'Link updated' : 'Link added');
  } catch (err) { setErr(f, err.message); } finally { busy(f, false); }
});

function openDelete(link) {
  state.deleteLink = link;
  $('#del-text').textContent = `“${link.label}” will be removed for everyone. This can't be undone.`;
  setErr($('#f-delete')); $('#dlg-delete').showModal();
}

$('#f-delete').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.currentTarget;
  setErr(f); busy(f, true);
  try {
    await api(`/links/${state.deleteLink.id}`, { method: 'DELETE' });
    $('#dlg-delete').close(); await loadLinks(); toast('Link deleted');
  } catch (err) { setErr(f, err.message); } finally { busy(f, false); }
});

/* ---- boot ---- */
$('#q').addEventListener('input', renderList);
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && !e.target.closest('input, textarea') && !document.querySelector('dialog[open]')) { e.preventDefault(); $('#q').focus(); }
});

(async () => {
  try { state.auth = await api('/auth/me'); } catch { /* public view still works */ }
  renderSession();
  await loadLinks();
})();
