'use strict';
(async () => {
  const $ = s => document.querySelector(s);
  try {
    const t = localStorage.getItem('siem-theme');
    if (t) document.documentElement.dataset.theme = t;
  } catch (e) { /* stockage indisponible */ }
  try {
    const m = await (await fetch('/api/marque')).json();
    document.title = 'Connexion - ' + m.nom;
    $('#titre').textContent = m.nom;
    $('#sous-titre').textContent = m.sous_titre;
    if (m.logo) { $('#logo').src = m.logo; $('#logo').alt = m.nom; $('#logo').hidden = false; }
    $('#mode').textContent = m.ad
      ? `Utilisez votre compte Windows${m.domaine ? ' (domaine ' + m.domaine + ')' : ''} : identifiant seul, DOMAINE\\identifiant ou adresse UPN.`
      : 'Connexion avec un compte local du portail.';
    $('#login').placeholder = m.ad ? 'prenom.nom' : 'admin.local';
  } catch (e) { /* marque par défaut */ }

  $('#form').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('#erreur').hidden = true;
    $('#valider').disabled = true;
    $('#valider').textContent = 'Vérification…';
    try {
      const r = await fetch('/api/connexion', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-SIEM': '1' },
        body: JSON.stringify({ login: $('#login').value, mot_de_passe: $('#mdp').value }),
      });
      if (r.ok) { location.href = '/'; return; }
      const d = await r.json().catch(() => ({}));
      $('#erreur').textContent = d.detail || 'Connexion refusée.';
      $('#erreur').hidden = false;
      $('#mdp').value = '';
      $('#mdp').focus();
    } catch (e) {
      $('#erreur').textContent = 'Portail injoignable.';
      $('#erreur').hidden = false;
    }
    $('#valider').disabled = false;
    $('#valider').textContent = 'Se connecter';
  });
})();
