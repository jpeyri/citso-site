/* CITSO — dynamique léger de l'accueil (13/11/2026)
   Onglets des quatre temps, compteurs, révélations au scroll.
   Tout est progressif : sans JS, tout le contenu reste visible. */
(function () {
  'use strict';
  var reduit = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* --- Mots tournants du hero : rotation pilotée en JS, une seule phrase visible à la fois --- */
  var phrases = Array.prototype.slice.call(document.querySelectorAll('.rotatif span'));
  if (phrases.length) {
    var indice = 0;
    phrases[0].classList.add('actif');
    if (phrases.length > 1 && !reduit) {
      setInterval(function () {
        phrases[indice].classList.remove('actif');
        indice = (indice + 1) % phrases.length;
        phrases[indice].classList.add('actif');
      }, 4000);
    }
  }

  /* --- Onglets accessibles : voir / corriger / tenir / récupérer --- */
  var onglets = Array.prototype.slice.call(document.querySelectorAll('.onglets [role="tab"]'));
  function activer(onglet) {
    onglets.forEach(function (o) {
      var etat = o === onglet;
      o.setAttribute('aria-selected', etat ? 'true' : 'false');
      o.tabIndex = etat ? 0 : -1;
      var panneau = document.getElementById(o.getAttribute('aria-controls'));
      if (panneau) panneau.hidden = !etat;
    });
    onglet.focus();
  }
  onglets.forEach(function (o, i) {
    o.addEventListener('click', function () { activer(o); });
    o.addEventListener('keydown', function (e) {
      var cible = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') cible = onglets[(i + 1) % onglets.length];
      if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') cible = onglets[(i - 1 + onglets.length) % onglets.length];
      if (e.key === 'Home') cible = onglets[0];
      if (e.key === 'End') cible = onglets[onglets.length - 1];
      if (cible) { e.preventDefault(); activer(cible); }
    });
  });

  /* Sans JS, les quatre panneaux restent affichés empilés ; avec JS, on ne montre que l'actif. */
  onglets.forEach(function (o) {
    var p = document.getElementById(o.getAttribute('aria-controls'));
    if (p) p.hidden = o.getAttribute('aria-selected') !== 'true';
  });

  /* --- Compteurs animés (valeur finale déjà dans le HTML) --- */
  function compter(el) {
    var fin = parseInt(el.getAttribute('data-compteur'), 10);
    if (isNaN(fin) || fin <= 0 || reduit) { el.textContent = String(fin || 0); return; }
    var debut = null, duree = 1200;
    function pas(t) {
      if (debut === null) debut = t;
      var p = Math.min((t - debut) / duree, 1);
      var aisee = 1 - Math.pow(1 - p, 3);
      el.textContent = String(Math.round(fin * aisee));
      if (p < 1) requestAnimationFrame(pas);
    }
    requestAnimationFrame(pas);
  }

  /* --- Révélations au scroll --- */
  function toutMontrer() {
    Array.prototype.forEach.call(document.querySelectorAll('.reveal'), function (el) {
      el.classList.add('visible');
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-compteur]'), compter);
  }

  if (reduit || !('IntersectionObserver' in window)) { toutMontrer(); return; }

  var io = new IntersectionObserver(function (entrees) {
    entrees.forEach(function (e) {
      if (!e.isIntersecting) return;
      e.target.classList.add('visible');
      Array.prototype.forEach.call(e.target.querySelectorAll('[data-compteur]'), compter);
      io.unobserve(e.target);
    });
  }, { threshold: 0.25 });
  Array.prototype.forEach.call(document.querySelectorAll('.reveal'), function (el) { io.observe(el); });
})();
