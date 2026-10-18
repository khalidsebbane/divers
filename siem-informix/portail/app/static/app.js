/* Portail SIEM Informix - interface (sans dépendance) */
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const etat = { moi: null, debut: null, fin: null };
const VOLETS = { systeme: 'Système', base: 'Base', applicatif: 'Applicatif' };
const GRAVITES = { faible: 'Faible', moyenne: 'Moyenne', haute: 'Haute', critique: 'Critique' };
const ICONES_G = { faible: 'ℹ', moyenne: '▲', haute: '◆', critique: '⬣' };
const ATTR = { certaine: 'certaine', probable: 'probable (poste)', compte: 'non identifiée' };

// ---------------------------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------------------------
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function frDate(ts, avecSec) {
  if (!ts) return '';
  const [d, h] = ts.split('T');
  const [a, m, j] = d.split('-');
  return `${j}/${m}/${a}` + (h ? ' ' + (avecSec ? h.slice(0, 8) : h.slice(0, 5)) : '');
}
function duree(s) {
  if (s == null) return '<span class="discret">en cours</span>';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}h${String(m).padStart(2, '0')}` : `${m} min`;
}
const nb = n => (n ?? 0).toLocaleString('fr-FR');
const iso = d => d.toISOString().slice(0, 10);
const volet = v => `<span class="badge"><span class="puce v-${esc(v)}"></span>${esc(VOLETS[v] || v)}</span>`;
const gravite = g => `<span class="badge g-${esc(g)}"><span class="puce"></span>${ICONES_G[g] || ''} ${esc(GRAVITES[g] || g)}</span>`;
const attribution = a => a === 'certaine' ? '' : `<span class="badge attr-${esc(a)}" title="Attribution ${esc(ATTR[a])}">${esc(ATTR[a] || a)}</span>`;
const lienPersonne = p => p ? `<a href="#/utilisateur/${encodeURIComponent(p)}">${esc(p)}</a>` : '';
const resultat = r => r === 'echec' ? '<span class="r-echec">Échec</span>' : 'Succès';

async function api(chemin, options = {}) {
  const rep = await fetch(chemin, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-SIEM': '1' }, ...options });
  if (rep.status === 401 && !chemin.startsWith('/api/connexion')) { location.href = '/connexion'; throw new Error('Session expirée'); }
  if (!rep.ok) {
    let msg = rep.statusText;
    try { msg = (await rep.json()).detail || msg; } catch (e) { /* corps non JSON */ }
    throw new Error(msg);
  }
  return rep.json();
}
const qs = o => Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
const per = () => ({ debut: etat.debut, fin: etat.fin });

function tableau(colonnes, lignes, options = {}) {
  if (!lignes.length) return `<div class="vide">${options.vide || 'Aucune donnée sur la période.'}</div>`;
  const th = colonnes.map(c => `<th class="${c.num ? 'num' : ''}">${esc(c.t)}</th>`).join('');
  const tr = lignes.map((l, i) => `<tr ${options.clic ? `class="cliquable" data-i="${i}"` : ''}>` +
    colonnes.map(c => `<td class="${c.num ? 'num' : ''} ${c.cl || ''}">${c.f ? c.f(l) : esc(l[c.k])}</td>`).join('') + '</tr>').join('');
  return `<div class="table-wrap"><table><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table></div>`;
}

// ---------------------------------------------------------------------------------------------
// Infobulle
// ---------------------------------------------------------------------------------------------
const bulle = $('#infobulle');
function montrerBulle(e, html) {
  bulle.innerHTML = html;
  bulle.style.display = 'block';
  const x = Math.min(e.clientX + 14, window.innerWidth - bulle.offsetWidth - 8);
  const y = Math.min(e.clientY + 14, window.innerHeight - bulle.offsetHeight - 8);
  bulle.style.left = x + 'px'; bulle.style.top = y + 'px';
}
const cacherBulle = () => { bulle.style.display = 'none'; };

// ---------------------------------------------------------------------------------------------
// Graphique : barres empilées par jour et par volet
// ---------------------------------------------------------------------------------------------
function barresParJour(el, donnees) {
  const jours = [];
  for (let d = new Date(etat.debut + 'T00:00:00'); iso(d) <= etat.fin; d.setDate(d.getDate() + 1)) jours.push(iso(d));
  const par = {};
  donnees.forEach(r => { (par[r.jour] = par[r.jour] || {})[r.source] = r.n; });
  const series = ['systeme', 'base', 'applicatif'];
  const totaux = jours.map(j => series.reduce((s, k) => s + ((par[j] || {})[k] || 0), 0));
  const max = Math.max(1, ...totaux);
  const pas = Math.pow(10, Math.floor(Math.log10(max)));
  const haut = Math.ceil(max / pas) * pas;
  const L = 760, H = 220, g = 40, b = 22, w = (L - g) / jours.length, bw = Math.max(2, Math.min(26, w - 2));
  let svg = `<svg viewBox="0 0 ${L} ${H + b}" role="img" aria-label="Événements par jour et par volet">`;
  for (let i = 0; i <= 4; i++) {
    const v = haut * i / 4, y = H - (v / haut) * (H - 10);
    svg += `<line class="grille-l" x1="${g}" x2="${L}" y1="${y}" y2="${y}"/><g class="axe"><text x="${g - 6}" y="${y + 4}" text-anchor="end">${nb(Math.round(v))}</text></g>`;
  }
  jours.forEach((j, i) => {
    const x = g + i * w + (w - bw) / 2;
    let y = H;
    const vals = par[j] || {};
    series.forEach((s, k) => {
      const v = vals[s] || 0;
      if (!v) return;
      const h = (v / haut) * (H - 10);
      const haute = series.slice(k + 1).every(t => !vals[t]);
      const r = haute ? Math.min(4, bw / 2, h) : 0;
      // segment : la marque du haut est arrondie, un liseré de 2px sépare les segments
      svg += haute
        ? `<path d="M${x},${y} v${-(h - r)} q0,${-r} ${r},${-r} h${bw - 2 * r} q${r},0 ${r},${r} v${h - r} z" fill="var(--s-${s})"/>`
        : `<rect x="${x}" y="${y - h}" width="${bw}" height="${Math.max(0, h - 2)}" fill="var(--s-${s})"/>`;
      y -= h;
    });
    svg += `<rect x="${g + i * w}" y="0" width="${w}" height="${H}" fill="transparent" data-j="${j}"/>`;
    if (jours.length <= 10 || i % Math.ceil(jours.length / 8) === 0)
      svg += `<g class="axe"><text x="${x + bw / 2}" y="${H + 15}" text-anchor="middle">${j.slice(8, 10)}/${j.slice(5, 7)}</text></g>`;
  });
  svg += `<line x1="${g}" x2="${L}" y1="${H}" y2="${H}" stroke="var(--texte-3)"/></svg>`;
  el.innerHTML = `<div class="legende">${series.map(s => `<span><span class="puce v-${s}"></span>${VOLETS[s]}</span>`).join('')}</div>
    <div class="graph">${svg}</div>
    <details class="donnees"><summary>Voir les données</summary>${tableau(
      [{ t: 'Jour', f: r => frDate(r.j) }, ...series.map(s => ({ t: VOLETS[s], num: 1, f: r => nb((par[r.j] || {})[s] || 0) })), { t: 'Total', num: 1, f: r => nb(r.t) }],
      jours.map((j, i) => ({ j, t: totaux[i] })).filter(r => r.t))}</details>`;
  el.querySelectorAll('rect[data-j]').forEach(r => {
    r.addEventListener('mousemove', e => {
      const j = r.dataset.j, v = par[j] || {};
      montrerBulle(e, `<b>${frDate(j)}</b>` + series.map(s => `<div class="ligne"><span><span class="puce v-${s}"></span>${VOLETS[s]}</span><span>${nb(v[s] || 0)}</span></div>`).join(''));
    });
    r.addEventListener('mouseleave', cacherBulle);
  });
}

// Carte de chaleur jour de semaine x heure
function chaleur(el, donnees) {
  const jours = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'];
  const m = {};
  donnees.forEach(r => { m[`${(r.jour_semaine + 6) % 7}-${r.heure}`] = r.n; });
  const max = Math.max(1, ...Object.values(m));
  const niveau = v => v ? Math.min(5, 1 + Math.floor((v / max) * 4.999)) : 0;
  let h = '<div class="carte-chaleur"><span></span>' + Array.from({ length: 24 }, (_, i) => `<span class="h">${i % 3 === 0 ? i + 'h' : ''}</span>`).join('');
  jours.forEach((j, d) => {
    h += `<span>${j}</span>`;
    for (let k = 0; k < 24; k++) {
      const v = m[`${d}-${k}`] || 0;
      h += `<span class="c" style="background:var(--seq-${niveau(v)})" data-t="${j} ${k}h-${k + 1}h : ${v} événement(s)"></span>`;
    }
  });
  h += `</div><div class="echelle">Moins ${[0, 1, 2, 3, 4, 5].map(i => `<i style="background:var(--seq-${i})"></i>`).join('')} Plus</div>`;
  el.innerHTML = h;
  el.querySelectorAll('.c').forEach(c => {
    c.addEventListener('mousemove', e => montrerBulle(e, esc(c.dataset.t)));
    c.addEventListener('mouseleave', cacherBulle);
  });
}

// ---------------------------------------------------------------------------------------------
// Vues
// ---------------------------------------------------------------------------------------------
const vues = {};

const ETATS = { ok: 'À jour', partiel: 'Partiel', erreur: 'En erreur', retard: 'En retard', jamais: 'Jamais collecté', inactive: 'Désactivée', en_cours: 'En cours' };
const etatSource = e => `<span class="etat e-${esc(e)}"><span class="puce"></span>${esc(ETATS[e] || e)}</span>`;
const depuisQuand = ts => {
  if (!ts) return '-';
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  return s < 90 ? `il y a ${s} s` : s < 5400 ? `il y a ${Math.round(s / 60)} min` : frDate(ts);
};

vues.tableau = async el => {
  const [d, sante] = await Promise.all([api('/api/tableau-de-bord?' + qs(per())), api('/api/collecte/sante').catch(() => [])]);
  const k = d.indicateurs;
  const bandeauCollecte = sante.length ? `<div class="carte" style="margin-bottom:16px"><h2>Collecte des serveurs ${etat.moi.role === 'admin' ? '<a class="droite" href="#/collecte">Gérer</a>' : ''}</h2>${tableau(
    [{ t: 'Serveur', f: r => `<b>${esc(r.nom)}</b> <span class="tres-discret">${esc(r.hote)}</span>` }, { t: 'État', f: r => etatSource(r.etat) },
     { t: 'Dernière collecte', f: r => depuisQuand(r.derniere_execution) }, { t: 'Événements collectés', num: 1, f: r => nb(r.evenements_total) },
     { t: 'Message', f: r => `<span class="tres-discret">${esc(r.message || '')}</span>` }], sante)}</div>` : '';
  el.innerHTML = bandeauCollecte + `
  <div class="grille g-kpi">
    <div class="carte kpi"><div class="v">${nb(k.total)}</div><div class="l">Événements</div></div>
    <div class="carte kpi"><div class="v">${nb(k.personnes)}</div><div class="l">Personnes / comptes actifs</div></div>
    <div class="carte kpi"><div class="v">${nb(k.connexions)}</div><div class="l">Connexions</div></div>
    <div class="carte kpi"><div class="v">${nb(k.partage)}</div><div class="l">Utilisations comptes partagés</div></div>
    <div class="carte kpi"><div class="v">${nb(k.sensibles)}</div><div class="l">Opérations sensibles en base</div></div>
    <div class="carte kpi ${k.alertes_ouvertes ? 'alerte' : ''}"><div class="v">${nb(k.alertes_ouvertes)}</div><div class="l">Alertes à traiter</div></div>
  </div>
  <div class="grille g-2">
    <div class="carte" style="grid-column:1/-1"><h2>Activité par jour</h2><div id="g-jours"></div></div>
    <div class="carte"><h2>Alertes récentes <a class="droite" href="#/alertes">Toutes les alertes</a></h2>${tableau(
      [{ t: 'Date', f: r => frDate(r.ts) }, { t: 'Gravité', f: r => gravite(r.gravite) }, { t: 'Alerte', k: 'titre' }, { t: 'Personne', f: r => lienPersonne(r.personne) }],
      d.alertes, { vide: 'Aucune alerte.' })}</div>
    <div class="carte"><h2>Comptes partagés (${esc(d.comptes_partages.join(', '))}) <span class="n">dernières utilisations</span></h2>${tableau(
      [{ t: 'Date', f: r => frDate(r.ts) }, { t: 'Compte', k: 'compte' }, { t: 'Personne', f: r => lienPersonne(r.personne) + ' ' + attribution(r.attribution) },
       { t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Volet', f: r => volet(r.source) }],
      d.compte_partage, { vide: 'Aucune utilisation sur la période.' })}</div>
    <div class="carte"><h2>Personnes les plus actives <a class="droite" href="#/utilisateurs">Tous les utilisateurs</a></h2>${tableau(
      [{ t: 'Personne', f: r => lienPersonne(r.personne) }, { t: 'Événements', num: 1, f: r => nb(r.n) }, { t: 'Jours', num: 1, k: 'jours' }, { t: 'Dernière activité', f: r => frDate(r.derniere) }],
      d.top_personnes)}</div>
    <div class="carte"><h2>Adresses IP les plus actives</h2>${tableau(
      [{ t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Personnes', f: r => (r.personnes || '').split(',').map(lienPersonne).join(', ') }, { t: 'Événements', num: 1, f: r => nb(r.n) }, { t: 'Dernière', f: r => frDate(r.derniere) }],
      d.top_ip)}</div>
  </div>`;
  barresParJour($('#g-jours', el), d.par_jour);
};

vues.utilisateurs = async el => {
  el.innerHTML = `<div class="carte"><div class="filtres"><input class="champ" id="f-texte" placeholder="Rechercher une personne ou un compte..." style="flex:1"></div><div id="liste"></div></div>`;
  const charger = async () => {
    const rows = await api('/api/personnes?' + qs({ ...per(), texte: $('#f-texte').value }));
    $('#liste').innerHTML = tableau([
      { t: 'Personne', f: r => `<b>${lienPersonne(r.personne)}</b> ${r.certaine ? '' : attribution('compte')}` },
      { t: 'Événements', num: 1, f: r => nb(r.evenements) }, { t: 'Système', num: 1, f: r => nb(r.systeme) },
      { t: 'Base', num: 1, f: r => nb(r.base) }, { t: 'Applicatif', num: 1, f: r => nb(r.applicatif) },
      { t: 'Échecs', num: 1, f: r => r.echecs ? `<span class="r-echec">${nb(r.echecs)}</span>` : '0' },
      { t: 'Jours actifs', num: 1, k: 'jours' }, { t: 'Comptes utilisés', k: 'comptes' },
      { t: 'Adresses IP', f: r => `<span class="ip">${esc((r.ips || '').split(',').slice(0, 4).join(', '))}${(r.ips || '').split(',').length > 4 ? '…' : ''}</span>` },
      { t: 'Dernière activité', f: r => frDate(r.derniere) }], rows, { clic: 1 });
    $('#liste').querySelectorAll('tr.cliquable').forEach(tr => tr.addEventListener('click', e => {
      if (e.target.tagName !== 'A') location.hash = '#/utilisateur/' + encodeURIComponent(rows[tr.dataset.i].personne);
    }));
  };
  let t; $('#f-texte').addEventListener('input', () => { clearTimeout(t); t = setTimeout(charger, 250); });
  await charger();
};

vues.utilisateur = async (el, personne) => {
  const p = await api(`/api/personnes/${encodeURIComponent(personne)}?` + qs(per()));
  const k = p.indicateurs;
  $('#titre').textContent = 'Utilisateur : ' + personne;
  el.innerHTML = `
  <div class="entete-fiche">
    <div class="avatar">${esc(personne.slice(0, 2))}</div>
    <div><h2>${esc(personne)}</h2><div class="discret">Comptes utilisés : ${p.comptes.map(c => `${esc(c.compte)} (${nb(c.n)})`).join(', ') || '-'}
      · Première activité ${frDate(k.premiere)} · Dernière ${frDate(k.derniere)}</div></div>
    <div style="margin-left:auto;display:flex;gap:8px">
      <a class="bouton" href="/api/evenements.csv?${qs({ ...per(), personne })}">Exporter (CSV)</a>
      <button class="bouton principal" id="btn-demander">✦ Questions sur ${esc(personne)}</button></div>
  </div>
  ${k.probables ? `<div class="bandeau">${nb(k.probables)} événement(s) sont attribués à ${esc(personne)} <b>d'après le poste</b> (compte partagé utilisé depuis une IP affectée à cette personne). L'attribution est probable, pas certaine.</div>` : ''}
  <div class="grille g-kpi">
    <div class="carte kpi"><div class="v">${nb(k.total)}</div><div class="l">Événements</div></div>
    <div class="carte kpi"><div class="v">${nb(k.systeme)}</div><div class="l"><span class="puce v-systeme"></span> Système</div></div>
    <div class="carte kpi"><div class="v">${nb(k.base)}</div><div class="l"><span class="puce v-base"></span> Base</div></div>
    <div class="carte kpi"><div class="v">${nb(k.applicatif)}</div><div class="l"><span class="puce v-applicatif"></span> Applicatif</div></div>
    <div class="carte kpi"><div class="v">${nb(k.jours)}</div><div class="l">Jours actifs</div></div>
    <div class="carte kpi ${k.echecs ? 'alerte' : ''}"><div class="v">${nb(k.echecs)}</div><div class="l">Échecs</div></div>
  </div>
  <div class="carte">
    <div class="onglets" id="onglets">
      <button data-o="chrono" class="actif">Chronologie</button><button data-o="systeme">Système</button><button data-o="base">Base</button>
      <button data-o="applicatif">Applicatif</button><button data-o="sessions">Sessions (${p.sessions.length})</button>
      <button data-o="ip">Adresses IP (${p.ips.length})</button><button data-o="habitudes">Habitudes</button>
      <button data-o="alertes">Alertes (${p.alertes.length})</button></div>
    <div id="onglet"></div>
  </div>`;
  $('#btn-demander').addEventListener('click', () => ouvrirTiroir(personne));
  const onglet = $('#onglet');
  const ouvrir = async o => {
    el.querySelectorAll('#onglets button').forEach(b => b.classList.toggle('actif', b.dataset.o === o));
    if (o === 'sessions') {
      onglet.innerHTML = tableau([{ t: 'Connexion', f: r => frDate(r.ts, 1) }, { t: 'Déconnexion', f: r => r.fin ? frDate(r.fin, 1) : '-' },
        { t: 'Durée', num: 1, f: r => duree(r.duree_s) }, { t: 'Volet', f: r => volet(r.source) }, { t: 'Compte', k: 'compte' },
        { t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Poste', k: 'poste' }, { t: 'Opérations', num: 1, k: 'operations' }], p.sessions);
    } else if (o === 'ip') {
      onglet.innerHTML = tableau([{ t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Postes', k: 'postes' }, { t: 'Événements', num: 1, f: r => nb(r.n) },
        { t: 'Première', f: r => frDate(r.premiere) }, { t: 'Dernière', f: r => frDate(r.derniere) }], p.ips);
    } else if (o === 'habitudes') {
      onglet.innerHTML = `<div class="grille g-2"><div><h2 style="font-size:14px">Activité par jour et par heure</h2><div id="chaleur"></div></div>
        <div><h2 style="font-size:14px">Programmes les plus lancés</h2>${tableau([{ t: 'Programme', k: 'programme', cl: 'mono' }, { t: 'Lancements', num: 1, f: r => nb(r.n) }, { t: 'Dernier', f: r => frDate(r.dernier) }], p.programmes, { vide: 'Aucun programme applicatif.' })}</div></div>`;
      chaleur($('#chaleur'), p.heures);
    } else if (o === 'alertes') {
      onglet.innerHTML = tableau([{ t: 'Date', f: r => frDate(r.ts) }, { t: 'Gravité', f: r => gravite(r.gravite) }, { t: 'Alerte', k: 'titre' }, { t: 'Détail', k: 'message' }, { t: 'Statut', k: 'statut' }], p.alertes, { vide: 'Aucune alerte.' });
    } else {
      await listeEvenements(onglet, { personne, source: o === 'chrono' ? '' : o }, o === 'chrono');
    }
  };
  el.querySelectorAll('#onglets button').forEach(b => b.addEventListener('click', () => ouvrir(b.dataset.o)));
  await ouvrir('chrono');
};

async function listeEvenements(el, filtres, chrono, decalage = 0) {
  const lim = 100;
  const d = await api('/api/evenements?' + qs({ ...per(), ...filtres, limite: lim, decalage }));
  const pag = `<div class="pagination"><span class="discret">${nb(d.total)} événement(s)</span>
    <button class="bouton" data-p="-1" ${decalage ? '' : 'disabled'}>‹ Plus récents</button>
    <button class="bouton" data-p="1" ${decalage + lim < d.total ? '' : 'disabled'}>Plus anciens ›</button></div>`;
  if (chrono) {
    el.innerHTML = d.evenements.length ? `<ul class="chrono">${d.evenements.map(e => `<li><span class="quand">${frDate(e.ts, 1)}</span><span class="puce v-${esc(e.source)}"></span>
      <span class="quoi"><b>${esc(e.action)}</b>${e.objet ? ' · <span class="mono objet">' + esc(e.objet) + '</span>' : ''}
      <span class="tres-discret"> — ${esc(VOLETS[e.source])}, compte ${esc(e.compte || '-')}${e.ip ? ', IP <span class="ip">' + esc(e.ip) + '</span>' : ''}${e.poste ? ' (' + esc(e.poste) + ')' : ''}</span>
      ${e.resultat === 'echec' ? ' <span class="r-echec">échec</span>' : ''} ${attribution(e.attribution)}</span></li>`).join('')}</ul>${pag}`
      : '<div class="vide">Aucun événement sur la période.</div>';
  } else {
    el.innerHTML = tableau([{ t: 'Date', f: r => frDate(r.ts, 1) }, { t: 'Volet', f: r => volet(r.source) }, { t: 'Action', k: 'action' },
      { t: 'Personne', f: r => lienPersonne(r.personne) + ' ' + attribution(r.attribution) }, { t: 'Compte', k: 'compte' },
      { t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Poste', k: 'poste' }, { t: 'Objet', k: 'objet', cl: 'mono objet' }, { t: 'Résultat', f: r => resultat(r.resultat) }],
      d.evenements, { vide: 'Aucun événement pour ces critères.' }) + pag;
  }
  el.querySelectorAll('.pagination button').forEach(b => b.addEventListener('click', () =>
    listeEvenements(el, filtres, chrono, Math.max(0, decalage + Number(b.dataset.p) * lim))));
}

vues.recherche = async el => {
  el.innerHTML = `<div class="carte"><div class="filtres">
    <input class="champ" id="r-texte" placeholder="Texte (action, objet, commande...)" style="flex:1">
    <input class="champ" id="r-personne" placeholder="Personne"><input class="champ" id="r-compte" placeholder="Compte (ex. regix)">
    <input class="champ" id="r-ip" placeholder="Adresse IP">
    <select class="champ" id="r-source"><option value="">Tous les volets</option><option value="systeme">Système</option><option value="base">Base</option><option value="applicatif">Applicatif</option></select>
    <select class="champ" id="r-resultat"><option value="">Succès et échecs</option><option value="echec">Échecs seulement</option></select>
    <button class="bouton principal" id="r-go">Rechercher</button><a class="bouton" id="r-csv">Exporter (CSV)</a></div><div id="r-res"></div></div>`;
  const f = () => ({ texte: $('#r-texte').value, personne: $('#r-personne').value, compte: $('#r-compte').value, ip: $('#r-ip').value,
    source: $('#r-source').value, resultat: $('#r-resultat').value });
  const go = () => { $('#r-csv').href = '/api/evenements.csv?' + qs({ ...per(), ...f() }); listeEvenements($('#r-res'), f(), false); };
  $('#r-go').addEventListener('click', go);
  el.querySelectorAll('.filtres input').forEach(i => i.addEventListener('keydown', e => { if (e.key === 'Enter') go(); }));
  go();
};

vues.alertes = async el => {
  el.innerHTML = `<div class="carte"><div class="filtres">
    <select class="champ" id="a-statut"><option value="">Tous statuts</option><option value="ouverte" selected>Ouvertes</option><option value="en_cours">En cours</option><option value="close">Closes</option></select>
    <select class="champ" id="a-gravite"><option value="">Toutes gravités</option>${Object.entries(GRAVITES).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
    </div><div id="a-liste"></div></div>`;
  const admin = etat.moi.role === 'admin';
  const charger = async () => {
    const rows = await api('/api/alertes?' + qs({ statut: $('#a-statut').value, gravite: $('#a-gravite').value, ...per() }));
    $('#a-liste').innerHTML = tableau([{ t: 'N°', k: 'id', num: 1 }, { t: 'Date', f: r => frDate(r.ts) }, { t: 'Gravité', f: r => gravite(r.gravite) },
      { t: 'Alerte', f: r => `<b>${esc(r.titre)}</b><div class="tres-discret">${esc(r.message)}</div>` }, { t: 'Personne', f: r => lienPersonne(r.personne) },
      { t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Statut', f: r => admin ? `<select class="champ" data-id="${r.id}">${['ouverte', 'en_cours', 'close'].map(s => `<option ${s === r.statut ? 'selected' : ''}>${s}</option>`).join('')}</select>` : esc(r.statut) },
      { t: '', f: r => `<button class="bouton" data-q="${r.id}">✦ Analyser</button>` }], rows, { vide: 'Aucune alerte pour ces critères.' });
    $('#a-liste').querySelectorAll('select[data-id]').forEach(s => s.addEventListener('change', async () => {
      const commentaire = s.value === 'close' ? (prompt('Commentaire de clôture (justification) :') || '') : '';
      await api('/api/alertes/' + s.dataset.id, { method: 'POST', body: JSON.stringify({ statut: s.value, commentaire }) });
    }));
    $('#a-liste').querySelectorAll('button[data-q]').forEach(b => b.addEventListener('click', () => {
      ouvrirTiroir(null);
      envoyer($('#tiroir-chat'), { suggestion: 'alerte', alerte: Number(b.dataset.q), texte: `Que s'est-il passé autour de l'alerte n°${b.dataset.q} ?` });
    }));
  };
  el.querySelectorAll('.filtres select').forEach(s => s.addEventListener('change', charger));
  await charger();
};

vues.postes = async el => {
  const admin = etat.moi.role === 'admin';
  el.innerHTML = `<div class="carte"><h2>Affectation des postes</h2>
    <p class="discret">Associer une adresse IP à la personne qui utilise ce poste permet d'attribuer à cette personne (attribution « probable ») les actions faites avec un compte partagé comme ${esc(etat.moi.comptes_partages.join(', '))}. Pour une attribution certaine, il faut des comptes nominatifs.</p>
    ${admin ? `<div class="filtres"><input class="champ" id="p-ip" placeholder="Adresse IP"><input class="champ" id="p-personne" placeholder="Personne (vide = supprimer)">
      <input class="champ" id="p-libelle" placeholder="Libellé du poste"><button class="bouton principal" id="p-ok">Enregistrer</button><span id="p-msg" class="discret"></span></div>` : ''}
    <div id="p-liste"></div></div>`;
  const charger = async () => {
    $('#p-liste').innerHTML = tableau([{ t: 'IP', k: 'ip', cl: 'ip' }, { t: 'Personne', f: r => lienPersonne(r.personne) }, { t: 'Poste', k: 'libelle' }],
      await api('/api/postes'), { vide: 'Aucun poste affecté.' });
  };
  if (admin) $('#p-ok').addEventListener('click', async () => {
    const r = await api('/api/postes', { method: 'POST', body: JSON.stringify({ ip: $('#p-ip').value, personne: $('#p-personne').value, libelle: $('#p-libelle').value }) });
    $('#p-msg').textContent = `${nb(r.reattribues)} événement(s) recalculé(s).`;
    charger();
  });
  await charger();
};

vues.assistant = async el => {
  el.innerHTML = `<div class="carte" style="max-width:980px;margin:0 auto;height:calc(100vh - 130px)"><div id="page-chat" class="assistant"></div></div>`;
  monterChat($('#page-chat'), null);
};


// ---------------------------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------------------------
const SOURCES_COLLECTE = { wtmp: 'Connexions (wtmp)', btmp: 'Échecs (btmp)', secure: 'SSH, sudo, su (secure)', auditd: 'Commandes et fichiers (auditd)',
  sessions: 'Sessions base (sysmaster)', onaudit: 'Audit Informix (onaudit)', applicatif: 'Programmes (agr_lds)' };

function champ(id, libelle, valeur, opts = {}) {
  return `<label class="${opts.large ? 'large' : ''}">${esc(libelle)}<input class="champ" id="${id}" value="${esc(valeur ?? '')}" ${opts.type ? `type="${opts.type}"` : ''} ${opts.ph ? `placeholder="${esc(opts.ph)}"` : ''}></label>`;
}

vues.collecte = async el => {
  const [sources, cle] = await Promise.all([api('/api/admin/sources'), api('/api/admin/cle-ssh')]);
  el.innerHTML = `
  <div class="carte" style="margin-bottom:16px"><h2>Serveurs collectés <span class="n">${sources.length}</span>
    <button class="bouton principal droite" id="c-ajout">+ Ajouter un serveur</button></h2>
    ${tableau([{ t: 'Serveur', f: r => `<b>${esc(r.nom)}</b><div class="tres-discret">${esc(r.utilisateur)}@${esc(r.hote)}:${r.port} · ${r.mode === 'ssh' ? 'SSH' : 'local'}</div>` },
      { t: 'État', f: r => etatSource(!r.actif ? 'inactive' : r.derniere_execution ? (r.statut || 'ok') : 'jamais') },
      { t: 'Fréquence', f: r => `${Math.round(r.intervalle_s / 60) || 1} min` },
      { t: 'Sources', f: r => esc((r.config.collecteur || {}).sources || '') },
      { t: 'Dernière collecte', f: r => depuisQuand(r.derniere_execution) }, { t: 'Événements', num: 1, f: r => nb(r.evenements_total) },
      { t: 'Message', f: r => `<span class="tres-discret">${esc(r.message || '')}</span>` },
      { t: '', f: (r) => `<div class="actions"><button class="bouton" data-a="modifier" data-id="${r.id}">Modifier</button>
         <button class="bouton" data-a="tester" data-id="${r.id}">Tester</button><button class="bouton" data-a="lancer" data-id="${r.id}">Collecter</button></div>` }],
      sources, { vide: 'Aucun serveur déclaré. Ajoutez le serveur Informix à collecter.' })}
    <div id="c-msg"></div></div>
  <div id="c-form"></div>
  <div class="carte"><h2>Clé SSH du portail</h2>
    <p class="discret">Le portail se connecte aux serveurs avec cette clé, dans un compte dédié (<span class="mono">siemcollect</span>). Côté serveur, la clé est
    limitée à une seule commande : le collecteur. Elle ne donne pas de shell. Le script <span class="mono">preparer-serveur-bdd.sh</span> installe tout.</p>
    <div class="code">${esc(cle.publique || 'Clé non disponible : installer openssh-clients sur le serveur du portail.')}</div>
    <div id="c-exec"></div></div>`;
  const msg = (t, ok) => { $('#c-msg', el).innerHTML = `<div class="message ${ok ? 'ok' : 'ko'}">${esc(t)}</div>`; };
  $('#c-ajout', el).addEventListener('click', () => formulaireSource(el, null));
  el.querySelectorAll('button[data-a]').forEach(b => b.addEventListener('click', async () => {
    const id = Number(b.dataset.id), src = sources.find(s => s.id === id);
    if (b.dataset.a === 'modifier') return formulaireSource(el, src);
    b.disabled = true;
    try {
      if (b.dataset.a === 'tester') { const r = await api(`/api/admin/sources/${id}/tester`, { method: 'POST', body: '{}' }); msg(r.message, r.ok); }
      if (b.dataset.a === 'lancer') {
        const depuis = prompt('Reprendre l\'historique depuis une date (AAAA-MM-JJ), ou laisser vide pour une collecte normale :', '');
        if (depuis === null) { b.disabled = false; return; }
        const r = await api(`/api/admin/sources/${id}/executer`, { method: 'POST', body: JSON.stringify({ depuis }) });
        msg(r.message + ' Rafraîchissez la page dans quelques instants.', true);
      }
    } catch (e) { msg(e.message, false); }
    b.disabled = false;
  }));
  const ex = await api('/api/admin/sources/' + (sources[0] ? sources[0].id : 0) + '/executions').catch(() => []);
  if (ex.length) $('#c-exec', el).innerHTML = `<h2 style="margin-top:18px">Dernières collectes${sources[0] ? ' · ' + esc(sources[0].nom) : ''}</h2>` + tableau(
    [{ t: 'Début', f: r => frDate(r.debut, 1) }, { t: 'Durée', num: 1, f: r => r.duree_s + ' s' }, { t: 'État', f: r => etatSource(r.statut) },
     { t: 'Reçus', num: 1, k: 'recus' }, { t: 'Nouveaux', num: 1, k: 'nouveaux' }, { t: 'Alertes', num: 1, k: 'alertes' }, { t: 'Message', k: 'message' }], ex.slice(0, 15));
};

function formulaireSource(el, src) {
  const c = (src && src.config) || {};
  const g = (s, k, d = '') => ((c[s] || {})[k] ?? d);
  const actives = (g('collecteur', 'sources', 'wtmp,btmp,secure,auditd,sessions,applicatif')).split(',');
  const zone = $('#c-form', el);
  zone.innerHTML = `<div class="carte" style="margin-bottom:16px"><h2>${src ? 'Modifier ' + esc(src.nom) : 'Nouveau serveur à collecter'}</h2>
  <fieldset><legend>Connexion</legend><div class="formulaire">
    ${champ('f-nom', 'Nom affiché', src ? src.nom : '', { ph: 'srv-fr2-107' })}${champ('f-hote', 'Adresse du serveur', src ? src.hote : '', { ph: '10.x.x.x ou nom DNS' })}
    ${champ('f-port', 'Port SSH', src ? src.port : 22, { type: 'number' })}${champ('f-util', 'Compte de collecte', src ? src.utilisateur : 'siemcollect')}
    <label>Mode<select class="champ" id="f-mode"><option value="ssh">SSH (serveur distant)</option><option value="local" ${src && src.mode === 'local' ? 'selected' : ''}>Local (même machine)</option></select></label>
    ${champ('f-int', 'Fréquence (minutes)', src ? Math.max(1, Math.round(src.intervalle_s / 60)) : 1, { type: 'number' })}
    ${champ('f-py', 'Python sur le serveur', src ? src.python : '/usr/libexec/platform-python')}${champ('f-chemin', 'Chemin du collecteur', src ? src.chemin_collecteur : '/opt/siem-informix/collecteur.py')}
    <label>Actif<select class="champ" id="f-actif"><option value="1">Oui</option><option value="0" ${src && !src.actif ? 'selected' : ''}>Non (en pause)</option></select></label>
  </div></fieldset>
  <fieldset><legend>Sources</legend><div class="formulaire">${Object.entries(SOURCES_COLLECTE).map(([k, v]) =>
    `<label style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" data-src="${k}" ${actives.includes(k) ? 'checked' : ''}> ${esc(v)}</label>`).join('')}
    ${champ('f-hist', 'Historique repris au 1er passage (jours)', g('collecteur', 'historique_jours', '45'), { type: 'number' })}</div></fieldset>
  <fieldset><legend>Informix</legend><div class="formulaire">
    ${champ('f-ifxdir', 'INFORMIXDIR', g('informix', 'informixdir', '/opt/informix'))}${champ('f-ifxsrv', 'INFORMIXSERVER', g('informix', 'informixserver'))}
    ${champ('f-onconf', 'ONCONFIG', g('informix', 'onconfig'))}${champ('f-audit', 'Commande onshowaudit', g('informix', 'commande_onshowaudit'), { ph: 'onshowaudit -n ol_prod' })}
  </div></fieldset>
  <fieldset><legend>Table applicative</legend><div class="formulaire">
    ${champ('f-base', 'Base', g('applicatif', 'base'))}${champ('f-table', 'Table', g('applicatif', 'table', 'agr_lds'))}
    ${champ('f-cdate', 'Colonne date', g('applicatif', 'colonne_date', 'alds_open'))}${champ('f-cuser', 'Colonne utilisateur (vide = auto)', g('applicatif', 'colonne_utilisateur'))}
    ${champ('f-compte', 'Compte base de l\'application', g('applicatif', 'compte_base', 'regix'))}
    ${champ('f-filtre', 'Filtre', g('applicatif', 'filtre', "(alds_complement IS NULL OR alds_complement NOT MATCHES 'Xp_cron*')"), { large: 1 })}
  </div></fieldset>
  <div id="f-ak"></div>
  <div class="actions"><button class="bouton principal" id="f-ok">Enregistrer</button><button class="bouton" id="f-annuler">Annuler</button>
    ${src ? '<button class="bouton" id="f-suppr" style="margin-left:auto">Supprimer</button>' : ''}<span id="f-msg"></span></div></div>`;
  if (src) $('#f-ak', zone).innerHTML = `<p class="discret">Ligne à placer dans <span class="mono">~${esc(src.utilisateur)}/.ssh/authorized_keys</span> sur le serveur (remplacer IP_DU_PORTAIL) :</p><div class="code">${esc(src.authorized_keys)}</div>`;
  zone.scrollIntoView({ behavior: 'smooth' });
  const v = id => $('#' + id, zone).value.trim();
  $('#f-annuler', zone).addEventListener('click', () => { zone.innerHTML = ''; });
  if (src) $('#f-suppr', zone).addEventListener('click', async () => {
    if (!confirm(`Supprimer la source ${src.nom} ? Les événements déjà collectés sont conservés.`)) return;
    await api('/api/admin/sources/' + src.id, { method: 'DELETE' }); router();
  });
  $('#f-ok', zone).addEventListener('click', async () => {
    const corps = {
      nom: v('f-nom'), hote: v('f-hote'), port: Number(v('f-port')) || 22, utilisateur: v('f-util'), mode: v('f-mode'),
      intervalle_s: Math.max(1, Number(v('f-int')) || 1) * 60, python: v('f-py'), chemin_collecteur: v('f-chemin'), actif: Number(v('f-actif')),
      config: {
        collecteur: { sources: [...zone.querySelectorAll('input[data-src]:checked')].map(i => i.dataset.src).join(','), historique_jours: v('f-hist') || '45' },
        informix: { informixdir: v('f-ifxdir'), informixserver: v('f-ifxsrv'), onconfig: v('f-onconf'), commande_onshowaudit: v('f-audit') },
        applicatif: { base: v('f-base'), table: v('f-table'), colonne_date: v('f-cdate'), colonne_utilisateur: v('f-cuser'), compte_base: v('f-compte'), filtre: v('f-filtre') },
      },
    };
    try {
      await api('/api/admin/sources' + (src ? '/' + src.id : ''), { method: src ? 'PUT' : 'POST', body: JSON.stringify(corps) });
      router();
    } catch (e) { $('#f-msg', zone).innerHTML = `<span class="r-echec">${esc(e.message)}</span>`; }
  });
}

vues.comptes = async el => {
  const comptes = await api('/api/admin/comptes');
  el.innerHTML = `<div class="carte"><h2>Comptes locaux de secours</h2>
    <p class="discret">Les utilisateurs se connectent normalement avec leur compte <b>Active Directory</b> ; leur rôle vient de leur groupe AD.
    Les comptes locaux servent d'accès de secours si l'annuaire est indisponible. Gardez-en au moins un administrateur, avec un mot de passe stocké dans le coffre.</p>
    ${tableau([{ t: 'Identifiant', f: r => `<b>${esc(r.login)}</b>` }, { t: 'Rôle', k: 'role' },
      { t: '', f: r => `<button class="bouton" data-suppr="${esc(r.login)}">Supprimer</button>` }], comptes)}
    <h2 style="margin-top:18px">Créer ou réinitialiser un compte</h2>
    <div class="formulaire">${champ('l-login', 'Identifiant', '', { ph: 'admin.local' })}${champ('l-mdp', 'Mot de passe (12 caractères min.)', '', { type: 'password' })}
    <label>Rôle<select class="champ" id="l-role"><option value="admin">Administrateur</option><option value="lecteur">Lecteur</option></select></label></div>
    <div class="actions"><button class="bouton principal" id="l-ok">Enregistrer</button><span id="l-msg"></span></div></div>`;
  $('#l-ok', el).addEventListener('click', async () => {
    try {
      await api('/api/admin/comptes', { method: 'POST', body: JSON.stringify({ login: $('#l-login').value, mot_de_passe: $('#l-mdp').value, role: $('#l-role').value }) });
      router();
    } catch (e) { $('#l-msg').innerHTML = `<span class="r-echec">${esc(e.message)}</span>`; }
  });
  el.querySelectorAll('button[data-suppr]').forEach(b => b.addEventListener('click', async () => {
    if (!confirm('Supprimer le compte ' + b.dataset.suppr + ' ?')) return;
    try { await api('/api/admin/comptes/' + encodeURIComponent(b.dataset.suppr), { method: 'DELETE' }); router(); } catch (e) { alert(e.message); }
  }));
};

const ACTIONS_JOURNAL = { connexion: 'Connexion', deconnexion: 'Déconnexion', echec_connexion: 'Échec de connexion', connexion_bloquee: 'Connexion bloquée',
  fiche: 'Consultation de fiche', export_csv: 'Export CSV', assistant: 'Question à l\'assistant', poste: 'Affectation de poste',
  source_creee: 'Source créée', source_modifiee: 'Source modifiée', source_supprimee: 'Source supprimée', collecte_manuelle: 'Collecte manuelle',
  compte_local: 'Compte local enregistré', compte_local_supprime: 'Compte local supprimé' };

vues.journal = async el => {
  el.innerHTML = `<div class="carte"><h2>Journal d'audit du portail</h2>
    <p class="discret">Qui s'est connecté au portail, qui a consulté quelle fiche, exporté des données ou posé une question à l'assistant.</p>
    <div class="filtres"><input class="champ" id="j-texte" placeholder="Filtrer (utilisateur, action, détail)..." style="flex:1"></div><div id="j-liste"></div></div>`;
  const charger = async () => {
    const rows = await api('/api/admin/journal?' + qs({ texte: $('#j-texte').value }));
    $('#j-liste').innerHTML = tableau([{ t: 'Date', f: r => frDate(r.ts, 1) }, { t: 'Utilisateur', f: r => `<b>${esc(r.login)}</b>` },
      { t: 'Action', f: r => (r.action || '').startsWith('echec') || r.action === 'connexion_bloquee' ? `<span class="r-echec">${esc(ACTIONS_JOURNAL[r.action] || r.action)}</span>` : esc(ACTIONS_JOURNAL[r.action] || r.action) },
      { t: 'Détail', f: r => `<span class="tres-discret">${esc(r.details)}</span>` }], rows);
  };
  let t; $('#j-texte').addEventListener('input', () => { clearTimeout(t); t = setTimeout(charger, 250); });
  await charger();
};

vues.parametres = async el => {
  const p = await api('/api/admin/parametres');
  const bloc = (titre, lignes) => `<div class="carte param"><h2>${esc(titre)}</h2><dl>${lignes.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl></div>`;
  const oui = b => b ? '<span class="etat e-ok"><span class="puce"></span>Actif</span>' : '<span class="etat e-inactive"><span class="puce"></span>Inactif</span>';
  const liste = l => (l && l.length) ? l.map(esc).join('<br>') : '<span class="discret">-</span>';
  el.innerHTML = `<p class="discret">Ces paramètres sont définis dans le fichier de configuration du serveur (<span class="mono">.env</span>). Ils sont affichés ici en lecture seule ; les secrets ne sont jamais affichés.</p>
  <div class="grille-param">
    ${bloc('Active Directory', [['État', oui(p.ad.actif)], ['Contrôleurs', liste(p.ad.serveurs)], ['Base de recherche', esc(p.ad.base_dn || '-')],
      ['Groupe administrateurs', esc(p.ad.groupe_admin || '-')], ['Groupe lecteurs', esc(p.ad.groupe_lecteur || '-')], ['Certificat vérifié', p.ad.certificat_verifie ? 'Oui' : '<span class="r-echec">Non</span>']])}
    ${bloc('Sessions', [['Durée maximale', p.sessions.duree_h + ' h'], ['Déconnexion après inactivité', p.sessions.inactivite_min + ' min'], ['Verrouillage', esc(p.sessions.verrouillage)]])}
    ${bloc('Notifications e-mail', [['État', oui(p.notifications.actives)], ['Serveur SMTP', esc(p.notifications.serveur || '-')], ['Destinataires', liste(p.notifications.destinataires)], ['Gravités envoyées', liste(p.notifications.gravites)]])}
    ${bloc('Règles', [['Comptes partagés surveillés', liste(p.regles.comptes_partages)], ['Heures ouvrées', esc(p.regles.heures_ouvrees)], ['Seuil d\'échecs', p.regles.seuil_echecs + ' en 10 min'], ['Conservation', p.regles.conservation_jours + ' jours']])}
    ${bloc('Collecte', [['Planificateur automatique', oui(p.collecte.planificateur)], ['Réception poussée (collecteurs autonomes)', oui(p.collecte.ingestion_push)]])}
    ${bloc('Assistant', [['IA (questions libres)', oui(p.assistant.ia)], ['Modèle', esc(p.assistant.modele || '-')], ['Questions proposées', oui(true) + ' <span class="tres-discret">sans IA, aucune donnée envoyée</span>']])}
  </div>`;
};

// ---------------------------------------------------------------------------------------------
// Assistant (chat)
// ---------------------------------------------------------------------------------------------
function markdown(t) {
  const lignes = esc(t).split('\n');
  let html = '', liste = false, tab = [];
  const inline = s => s.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<span class="mono">$1</span>');
  const finTab = () => {
    if (!tab.length) return;
    const cel = l => l.replace(/^\||\|$/g, '').split('|').map(c => inline(c.trim()));
    const corps = tab.filter(l => !/^\|?\s*:?-{2,}/.test(l));
    html += `<div class="table-wrap"><table><thead><tr>${cel(corps[0]).map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>` +
      corps.slice(1).map(l => `<tr>${cel(l).map(c => `<td>${c}</td>`).join('')}</tr>`).join('') + '</tbody></table></div>';
    tab = [];
  };
  for (const l of lignes) {
    if (/^\s*\|.*\|\s*$/.test(l)) { tab.push(l.trim()); continue; }
    finTab();
    if (/^\s*[-*] /.test(l)) { if (!liste) { html += '<ul>'; liste = true; } html += `<li>${inline(l.replace(/^\s*[-*] /, ''))}</li>`; continue; }
    if (liste) { html += '</ul>'; liste = false; }
    if (/^#{1,4} /.test(l)) html += `<p><b>${inline(l.replace(/^#+ /, ''))}</b></p>`;
    else if (l.trim()) html += `<p>${inline(l)}</p>`;
  }
  finTab();
  if (liste) html += '</ul>';
  return html;
}

function monterChat(el, personne) {
  el.dataset.personne = personne || '';
  el._historique = [];
  el.innerHTML = `<div class="fil"></div>
    <div class="puces-q" id="proposees"></div>
    <div class="saisie"><textarea rows="2" placeholder="${etat.moi.ia ? 'Posez votre question (ex. : qui a supprimé une table la semaine dernière ?)' : 'Assistant IA non activé : choisissez une question proposée'}"></textarea>
    <button class="bouton principal">Envoyer</button></div>`;
  const fil = $('.fil', el);
  fil.innerHTML = `<div class="msg r"><p>Bonjour. ${personne ? `Je peux répondre à vos questions sur <b>${esc(personne)}</b> : connexions, adresses IP, programmes lancés, opérations en base.` : 'Je peux vous aider à retrouver qui a fait quoi, quand et depuis où, sur le système, la base et l\'application.'}</p>
    <p>Choisissez une question ci-dessous${etat.moi.ia ? ' ou posez la vôtre' : ''}.</p>
    ${etat.moi.ia ? '' : '<div class="mode">Mode sans IA : réponses calculées directement sur les données, rien n\'est envoyé à l\'extérieur.</div>'}</div>`;
  api('/api/assistant/suggestions?' + qs({ personne })).then(d => afficherPropositions(el, d.suggestions.slice(0, 8)));
  const zone = $('textarea', el);
  const partir = () => { const q = zone.value.trim(); if (q) { zone.value = ''; envoyer(el, { question: q, texte: q }); } };
  $('.saisie button', el).addEventListener('click', partir);
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); partir(); } });
}

function afficherPropositions(el, liste) {
  const z = $('#proposees', el);
  z.innerHTML = liste.map((s, i) => `<button data-i="${i}">${esc(s.texte)}</button>`).join('');
  z.querySelectorAll('button').forEach(b => b.addEventListener('click', () => {
    const s = liste[b.dataset.i];
    envoyer(el, s.id ? { suggestion: s.id, alerte: s.alerte, texte: s.texte } : { question: s.texte, texte: s.texte });
  }));
}

async function envoyer(el, { question, suggestion, alerte, texte }) {
  const fil = $('.fil', el);
  const personne = el.dataset.personne || null;
  fil.insertAdjacentHTML('beforeend', `<div class="msg q">${esc(texte)}</div><div class="msg r attente">Recherche en cours…</div>`);
  fil.scrollTop = fil.scrollHeight;
  const attente = fil.lastElementChild;
  try {
    const r = await api('/api/assistant', { method: 'POST', body: JSON.stringify({ question, suggestion, alerte, personne, historique: el._historique }) });
    attente.classList.remove('attente');
    attente.innerHTML = markdown(r.texte) + (r.tableaux || []).filter(Boolean).map(t =>
      tableau(t.colonnes.map((c, i) => ({ t: c, f: l => esc(l[i] ?? '') })), t.lignes.slice(0, 200), { vide: '' })).join('') +
      `<div class="mode">${r.mode === 'ia' ? 'Réponse de l\'assistant IA, à vérifier dans les événements' : r.mode === 'direct' ? 'Réponse calculée directement sur les données' : ''}</div>`;
    el._historique.push({ role: 'user', texte }, { role: 'assistant', texte: r.texte });
    afficherPropositions(el, (r.proposees || []).slice(0, 5));
  } catch (e) {
    attente.classList.remove('attente');
    attente.innerHTML = `<p class="r-echec">Erreur : ${esc(e.message)}</p>`;
  }
  fil.scrollTop = fil.scrollHeight;
}

function ouvrirTiroir(personne) {
  const t = $('#tiroir');
  t.classList.add('ouvert');
  const chat = $('#tiroir-chat');
  if (!chat.innerHTML || chat.dataset.personne !== (personne || '')) monterChat(chat, personne);
  $('#tiroir h2').textContent = personne ? 'Assistant · ' + personne : 'Assistant';
}

// ---------------------------------------------------------------------------------------------
// Période, routage, démarrage
// ---------------------------------------------------------------------------------------------
function calculerPeriode() {
  const v = $('#periode').value, a = new Date();
  let d = new Date(a), f = new Date(a);
  if (v === 'jour') { /* aujourd'hui */ }
  else if (v === '7') d.setDate(a.getDate() - 6);
  else if (v === '30') d.setDate(a.getDate() - 29);
  else if (v === 'mois') d = new Date(a.getFullYear(), a.getMonth(), 1);
  else if (v === 'mois-1') { d = new Date(a.getFullYear(), a.getMonth() - 1, 1); f = new Date(a.getFullYear(), a.getMonth(), 0); }
  const perso = v === 'perso';
  $('#debut').hidden = $('#fin').hidden = !perso;
  if (perso) { etat.debut = $('#debut').value || iso(d); etat.fin = $('#fin').value || iso(f); }
  else {
    const loc = x => new Date(x.getTime() - x.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
    etat.debut = loc(d); etat.fin = loc(f); $('#debut').value = etat.debut; $('#fin').value = etat.fin;
  }
}

const TITRES = { tableau: 'Tableau de bord', utilisateurs: 'Utilisateurs', recherche: 'Recherche d\'événements', alertes: 'Alertes', postes: 'Affectation des postes',
  assistant: 'Assistant', collecte: 'Collecte des serveurs', comptes: 'Comptes locaux', journal: 'Journal d\'audit', parametres: 'Paramètres' };

async function router() {
  const [, nom = 'tableau', arg] = location.hash.split('/');
  const vue = vues[nom] ? nom : 'tableau';
  if (['collecte', 'comptes', 'journal', 'parametres'].includes(vue) && etat.moi.role !== 'admin') { location.hash = '#/tableau'; return; }
  document.querySelectorAll('nav.menu a').forEach(a => a.classList.toggle('actif', a.dataset.vue === (vue === 'utilisateur' ? 'utilisateurs' : vue)));
  $('#titre').textContent = TITRES[vue] || '';
  $('#menu').classList.remove('ouvert');
  const el = $('#vue');
  el.innerHTML = '<div class="vide">Chargement…</div>';
  try { await vues[vue](el, arg ? decodeURIComponent(arg) : undefined); }
  catch (e) { el.innerHTML = `<div class="carte r-echec">Erreur : ${esc(e.message)}</div>`; }
}

async function demarrer() {
  try { const t = localStorage.getItem('siem-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* stockage indisponible */ }
  etat.moi = await api('/api/moi');
  const m = etat.moi.marque;
  document.title = m.nom;
  $('#marque-nom').textContent = m.nom;
  $('#marque-st').textContent = m.sous_titre;
  if (m.logo) { $('#logo').src = m.logo; $('#logo').alt = m.nom; $('#logo').hidden = false; $('#marque-nom').hidden = true; }
  $('#version').textContent = `Portail SIEM v${m.version}`;
  $('#qui-ini').textContent = (etat.moi.nom || etat.moi.login).split(/[ ._-]/).filter(Boolean).slice(0, 2).map(x => x[0]).join('');
  $('#qui-nom').innerHTML = `${esc(etat.moi.nom || etat.moi.login)}<small>${etat.moi.role === 'admin' ? 'Administrateur' : 'Lecteur'} · ${etat.moi.source === 'ad' ? 'Active Directory' : 'compte local'}</small>`;
  document.querySelectorAll('.admin-seul').forEach(x => { x.hidden = etat.moi.role !== 'admin'; });
  $('#btn-sortir').addEventListener('click', async () => { await api('/api/deconnexion', { method: 'POST', body: '{}' }).catch(() => {}); location.href = '/connexion'; });
  calculerPeriode();
  ['#periode', '#debut', '#fin'].forEach(s => $(s).addEventListener('change', () => { calculerPeriode(); router(); }));
  $('#btn-assistant').addEventListener('click', () => {
    const [, nom, arg] = location.hash.split('/');
    ouvrirTiroir(nom === 'utilisateur' && arg ? decodeURIComponent(arg) : null);
  });
  $('#btn-fermer').addEventListener('click', () => $('#tiroir').classList.remove('ouvert'));
  $('#btn-menu').addEventListener('click', () => $('#menu').classList.toggle('ouvert'));
  $('#btn-theme').addEventListener('click', () => {
    const sombre = (document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark';
    document.documentElement.dataset.theme = sombre ? 'light' : 'dark';
    try { localStorage.setItem('siem-theme', document.documentElement.dataset.theme); } catch (e) { /* stockage indisponible */ }
  });
  window.addEventListener('hashchange', router);
  router();
}
demarrer();
