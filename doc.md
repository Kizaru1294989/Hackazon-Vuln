# Rapport Pentest 

> **Auteur :** Équipe d'or et de platine
>
> **Date :** <!-- Remplacer par la date -->
>
> **Cible / Scope :** https://hackazon.trackflaw.com/

---

## 1. Reconaissance
### 1.1 Scan Nmap — découverte services

**Commande exécutée**
```bash
nmap -sV -sC -T4 hackazon.trackflaw.com

Sortie Nmap (brute)

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-09 13:30 CEST
Nmap scan report for hackazon.trackflaw.com (31.220.95.27)
Host is up (0.053s latency).
rDNS record for 31.220.95.27: vmi1593261.contaboserver.net
Not shown: 995 closed tcp ports (reset)
PORT     STATE    SERVICE  VERSION
25/tcp   filtered smtp
80/tcp   open     http     nginx
|_http-title: Did not follow redirect to https://hackazon.trackflaw.com/
443/tcp  open     ssl/http nginx
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Hackazon
| ssl-cert: Subject: commonName=hackazon.trackflaw.com
| Subject Alternative Name: DNS:hackazon.trackflaw.com
| Not valid before: 2025-09-21T12:09:08
|_Not valid after:  2025-12-20T12:09:07
1234/tcp open     ssh      OpenSSH 10.0p2 Debian 5 (protocol 2.0)
9002/tcp open     http     Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Directory listing of http://hackazon.trackflaw.com:9002/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.08 seconds

```

**Synthèse — tableau récapitulatif**

| Port | État     | Service      | Version / Info importante                                  | Remarque rapide                        |
| ---- | -------- | ------------ | ---------------------------------------------------------- | -------------------------------------- |
| 25   | filtered | smtp         | —                                                          | Filtré (pas d'énumération)             |
| 80   | open     | http         | nginx                                                      | Redirection HTTP → HTTPS détectée      |
| 443  | open     | https / http | nginx ; certificat valide du 2025-09-21 au 2025-12-20      | PHPSESSID sans `HttpOnly` — à vérifier |
| 1234 | open     | ssh          | OpenSSH 10.0p2 Debian 5 (protocol 2.0)                     | Port SSH non standard (à auditer)      |
| 9002 | open     | http         | Apache/2.4.56 (Debian) — index listing (Directory listing) | Listing de répertoire exposé           |



---


### 1.2 Dirsearch 

cet outil nous permet de voir les fichiers,routes disponibles sur le site web

```bash
dirsearch -u https://hackazon.trackflaw.com/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                             
 (_||| _) (/_(_|| (_| )                                                                      
                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/reports/https_hackazon.trackflaw.com/__25-10-09_13-38-17.txt

Target: https://hackazon.trackflaw.com/

[13:38:17] Starting:                                                                         
[13:38:20] 301 -  332B  - /js  ->  http://hackazon.trackflaw.com/js/?js     
[13:38:45] 403 -  308B  - /.ht_wsr.txt                                      
[13:38:45] 403 -  311B  - /.htaccess.bak1                                   
[13:38:45] 403 -  311B  - /.htaccess.orig                                   
[13:38:45] 403 -  313B  - /.htaccess.sample                                 
[13:38:45] 403 -  311B  - /.htaccess.save                                   
[13:38:45] 403 -  312B  - /.htaccess_extra
[13:38:45] 403 -  309B  - /.htaccessBAK                                     
[13:38:45] 403 -  309B  - /.htaccess_sc
[13:38:45] 403 -  311B  - /.htaccess_orig                                   
[13:38:45] 403 -  309B  - /.htaccessOLD
[13:38:45] 403 -  310B  - /.htaccessOLD2
[13:38:45] 403 -  302B  - /.html                                            
[13:38:45] 403 -  301B  - /.htm                                             
[13:38:45] 403 -  307B  - /.htpasswds                                       
[13:38:45] 403 -  311B  - /.htpasswd_test                                   
[13:38:45] 403 -  308B  - /.httr-oauth                                      
[13:39:38] 302 -    0B  - /account/  ->  /user/login?return_url=%2Faccount%2F
[13:39:38] 302 -    0B  - /account  ->  /user/login?return_url=%2Faccount   
[13:39:39] 404 -   21KB - /account/login.aspx                               
[13:39:39] 404 -   21KB - /account/login.jsp
[13:39:39] 404 -   21KB - /account/login
[13:39:39] 404 -   21KB - /account/login.html
[13:39:39] 404 -   21KB - /account/login.php
[13:39:39] 404 -   21KB - /account/login.js
[13:39:39] 404 -   21KB - /account/login.htm
[13:39:39] 404 -   21KB - /account/login.py
[13:39:39] 404 -   21KB - /account/login.rb
[13:39:39] 404 -   21KB - /account/logon
[13:39:39] 404 -   21KB - /account/login.shtml
[13:39:39] 404 -   21KB - /account/signin
[13:39:50] 302 -    0B  - /admin  ->  /admin/user/login?return_url=%2Fadmin 
[13:39:54] 302 -    0B  - /admin/  ->  /admin/user/login?return_url=%2Fadmin%2F
[13:39:54] 302 -    0B  - /admin/.config  ->  /admin/user/login?return_url=%2Fadmin%2F.config
[13:39:54] 302 -    0B  - /admin/%3bindex/  ->  /admin/user/login?return_url=%2Fadmin%2F%253Bindex%2F
[13:39:54] 302 -    0B  - /admin/.htaccess  ->  /admin/user/login?return_url=%2Fadmin%2F.htaccess
[13:39:54] 302 -    0B  - /admin/_logs/access-log  ->  /admin/user/login?return_url=%2Fadmin%2F_logs%2Faccess-log
[13:39:54] 302 -    0B  - /admin/_logs/access.log  ->  /admin/user/login?return_url=%2Fadmin%2F_logs%2Faccess.log
[13:39:54] 302 -    0B  - /admin/_logs/access_log  ->  /admin/user/login?return_url=%2Fadmin%2F_logs%2Faccess_log
[13:39:54] 302 -    0B  - /admin/_logs/error-log  ->  /admin/user/login?return_url=%2Fadmin%2F_logs%2Ferror-log
[13:39:54] 302 -    0B  - /admin/_logs/err.log  ->  /admin/user/login?return_url=%2Fadmin%2F_logs%2Ferr.log

```
## 2. Exploitation

🔍 Exploitation d’un compte via l’analyse du Swagger
 
 ![alt text](image-1.png)

 Grace au fichiers Swagger on connait la route du backend api pour s'authentifier '/api/auth/'
 
```bash
curl -v -u zindar:rais \
  https://hackazon.trackflaw.com/api/auth
* Host hackazon.trackflaw.com:443 was resolved.
* IPv6: (none)
* IPv4: 31.220.95.27
*   Trying 31.220.95.27:443...
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / x25519 / RSASSA-PSS
* ALPN: server accepted h2
* Server certificate:
*  subject: CN=hackazon.trackflaw.com
*  start date: Sep 21 12:09:08 2025 GMT
*  expire date: Dec 20 12:09:07 2025 GMT
*  subjectAltName: host "hackazon.trackflaw.com" matched cert's "hackazon.trackflaw.com"
*  issuer: C=US; O=Let's Encrypt; CN=R13
*  SSL certificate verify ok.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 1: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 2: Public key type RSA (4096/152 Bits/secBits), signed using sha256WithRSAEncryption
* Connected to hackazon.trackflaw.com (31.220.95.27) port 443
* using HTTP/2
* Server auth using Basic with user 'zindar'
* [HTTP/2] [1] OPENED stream for https://hackazon.trackflaw.com/api/auth
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: hackazon.trackflaw.com]
* [HTTP/2] [1] [:path: /api/auth]
* [HTTP/2] [1] [authorization: Basic emluZGFyOnJhaXM=]
* [HTTP/2] [1] [user-agent: curl/8.15.0]
* [HTTP/2] [1] [accept: */*]
> GET /api/auth HTTP/2
> Host: hackazon.trackflaw.com
> Authorization: Basic emluZGFyOnJhaXM=
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
< HTTP/2 200 
< server: nginx
< date: Thu, 09 Oct 2025 12:26:27 GMT
< content-type: application/json; charset=utf-8
< content-length: 113
< vary: Accept-Encoding
< x-powered-by: PHP/5.6.40
< set-cookie: PHPSESSID=13773a52a7367f9a7df6f47a38a4fa90; path=/
< expires: Thu, 19 Nov 1981 08:52:00 GMT
< cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< pragma: no-cache
< 
* Connection #0 to host hackazon.trackflaw.com left intact
{"message":"Your token is established.","code":200,"trace":"","token":"baafd15881f341329f95cfb0bfddfb92e8e8c89b"} 

```

Nous avons maintenant notre token , on va maintenant exploiter une autre route pour 

###  Rapport technique
📘 Contexte

Lors d’un audit d’un environnement CTF simulant une application e-commerce (Hackazon), un fichier swagger.json exposé a été récupéré. Ce fichier contient la description complète des endpoints de l’API REST utilisée par l’application.

L’objectif était d’identifier des vulnérabilités liées aux mécanismes d’authentification et de gestion des utilisateurs.

🔎 Étapes de l’exploitation
1. Récupération du Swagger

Le fichier swagger.json, exposé publiquement, a permis de cartographier l’intégralité des endpoints disponibles dans l’API, y compris ceux normalement réservés à des opérations sensibles comme :

GET /api/auth : authentification par Basic Auth

GET /api/user/me : récupération du profil connecté

PUT /api/user/{id} : mise à jour d’un utilisateur spécifique

2. Connexion via un compte par défaut

À l’aide des informations disponibles, une tentative de connexion a été réalisée avec des identifiants génériques :

---



