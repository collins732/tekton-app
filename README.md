# TEKTON - Web Vulnerability Scanner

Platform automatisée de détection de vulnérabilités web pour applications et sites internet.

**Master 2 Cloud Computing - Projet Académique**

## Membres de l'équipe
- **Eugene**
- **Marlene**
- **collins**
- **Jessica**
- **Walid**


---

## Objectif du projet

TEKTON est un scanner de vulnérabilités web conçu pour identifier automatiquement les failles de sécurité dans les applications web. Le projet vise à fournir une solution modulaire permettant de :

1. **Découvrir les services exposés** - Identification des ports ouverts et services actifs
2. **Identifier les technologies utilisées** - Détection des frameworks, serveurs, langages
3. **Détecter les vulnérabilités XSS** - Tests de failles Cross-Site Scripting
4. **Identifier les injections SQL** - Détection des vulnérabilités SQL Injection

L'application offre une interface terminal rétro et une API REST pour l'intégration dans des workflows de sécurité existants.

---

## Technologies utilisées

| Composant | Technologie | Version |
|-----------|------------|---------|
| Framework Frontend/Backend | Next.js | 16.0.3 |
| Langage | TypeScript | 5.x |
| Base de données | SQLite (better-sqlite3) | 12.4.1 |
| Client HTTP | Axios | 1.13.2 |
| Parser HTML | Cheerio | 1.1.2 |
| Styling | TailwindCSS | 4.x |
| Identifiants uniques | Nanoid | 5.1.6 |

---

## Structure du projet

```
vulnscanner/
├── app/
│   ├── api/
│   │   └── scan/
│   │       ├── route.ts              # API: POST /api/scan, GET /api/scan
│   │       └── [id]/route.ts         # API: GET /api/scan/:id
│   │
│   ├── lib/
│   │   ├── types.ts                  # Interfaces TypeScript
│   │   ├── db.ts                     # Gestion base de données SQLite
│   │   ├── scanner.ts                # Orchestrateur principal des scans
│   │   └── scanners/
│   │       ├── port-scanner.ts       # Module: Scan de ports
│   │       ├── tech-detector.ts      # Module: Détection technologies
│   │       ├── xss-scanner.ts        # Module: Détection XSS
│   │       └── sqli-scanner.ts       # Module: Détection SQL Injection
│   │
│   ├── globals.css                   # Styles globaux (terminal rétro)
│   ├── layout.tsx                    # Layout de l'application
│   └── page.tsx                      # Interface utilisateur principale
│
├── public/                           # Ressources statiques
├── test-scan.js                      # Script CLI de test
├── package.json                      # Dépendances npm
├── tsconfig.json                     # Configuration TypeScript
├── next.config.ts                    # Configuration Next.js
└── scans.db                          # Base de données (créée automatiquement)
```

---

## Installation et lancement

### Prérequis

- **Node.js** version 18 ou supérieure
- **npm** ou **yarn**
- Système d'exploitation : Windows, Linux, ou macOS

### Installation

```bash
# 1. Naviguer vers le dossier du projet
cd vulnscanner

# 2. Installer les dépendances
npm install

# 3. Lancer le serveur de développement
npm run dev
```

L'application sera accessible sur **http://localhost:3000**

### Commandes disponibles

```bash
# Développement
npm run dev          # Lance le serveur de développement (port 3000)

# Production
npm run build        # Compile l'application pour production
npm start            # Lance l'application en mode production

# Tests
node test-scan.js "URL"   # Teste le scanner en ligne de commande
```

---

## Utilisation

### Interface Web

1. Ouvrir le navigateur sur **http://localhost:3000**
2. Saisir l'URL cible dans le champ prévu
3. Cliquer sur le bouton **[SCAN]**
4. Suivre la progression en temps réel dans le terminal
5. Consulter les résultats à la fin du scan

### Interface CLI (Ligne de commande)

```bash
node test-scan.js "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

### URLs de test

**Site vulnérable** (pour tests et démonstrations) :
```
http://testphp.vulnweb.com/listproducts.php?cat=1
```

**Site sécurisé** (baseline) :
```
http://example.com
```

---

## Modules de scanning

### 1. Port Scanner
**Responsable** : Bensk
**Fichier** : `app/lib/scanners/port-scanner.ts`

Scanne les ports TCP courants (21, 22, 80, 443, 3306, etc.) pour identifier les services exposés. Utilise `nmap` en fallback si disponible.

### 2. Technology Detector
**Responsable** : Eugene
**Fichier** : `app/lib/scanners/tech-detector.ts`

Identifie les technologies utilisées par analyse des en-têtes HTTP et parsing HTML : serveurs web, frameworks JavaScript, langages backend, CMS.

### 3. XSS Scanner
**Responsable** : Collins
**Fichier** : `app/lib/scanners/xss-scanner.ts`

Détecte les vulnérabilités Cross-Site Scripting (XSS) en injectant des payloads dans les paramètres URL et formulaires.

### 4. SQL Injection Scanner
**Responsable** : Marlene/Marie
**Fichier** : `app/lib/scanners/sqli-scanner.ts`

Identifie les vulnérabilités SQL Injection par injection de payloads et détection de messages d'erreur SQL (MySQL, PostgreSQL, MSSQL).

---

## API REST

### Démarrer un scan

```http
POST /api/scan
Content-Type: application/json

{
  "url": "http://example.com"
}
```

**Réponse** :
```json
{
  "scanId": "abc123xyz",
  "status": "pending"
}
```

### Obtenir le statut d'un scan

```http
GET /api/scan/{scanId}
```

**Réponse** :
```json
{
  "scanId": "abc123xyz",
  "target": "http://example.com",
  "status": "completed",
  "progress": 100,
  "results": {
    "ports": [
      { "port": 80, "service": "HTTP", "state": "open" }
    ],
    "technologies": [
      { "name": "nginx", "category": "server", "version": "1.19.0" }
    ],
    "vulnerabilities": [
      {
        "type": "sqli",
        "severity": "critical",
        "title": "SQL Injection in URL Parameter",
        "description": "...",
        "location": "..."
      }
    ]
  }
}
```

---

## Déploiement sur Azure

Le projet est configuré pour être déployé sur Azure via Terraform (IaaS).

### Étapes de déploiement

1. **Build de production**
   ```bash
   npm run build
   ```

2. **Configuration Terraform**
   - Infrastructure définie dans `/terraform`
   - VM Ubuntu 22.04 LTS
   - Network Security Group (ports 22, 80, 3000)

3. **Déploiement**
   ```bash
   cd ../terraform
   terraform init
   terraform apply
   ```

4. **Configuration serveur**
   - Installer Node.js et npm
   - Cloner le dépôt
   - Installer les dépendances
   - Configurer nginx en reverse proxy
   - Configurer PM2 pour la gestion des processus

---

## Sécurité et conformité

**Avertissement important** : Cet outil est conçu à des fins éducatives uniquement.

### Règles d'utilisation

- ✅ Utiliser uniquement sur des sites dont vous êtes propriétaire
- ✅ Obtenir une autorisation écrite avant tout scan
- ✅ Utiliser des environnements de test (testphp.vulnweb.com)
- ❌ Ne jamais scanner des sites sans autorisation
- ❌ Ne pas utiliser en production sans validation
- ❌ Respecter les lois locales sur la cybersécurité

### Conformité légale

Ce projet s'inscrit dans le cadre d'un cursus Master 2 Cloud Computing et doit être utilisé conformément aux principes de l'ethical hacking et aux réglementations en vigueur.

---

## Tests et validation

### Test complet via CLI

```bash
node test-scan.js "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

**Résultat attendu** :
- Port 80 (HTTP) ouvert
- Technologies : nginx/1.19.0, PHP 5.6.40
- Vulnérabilités : 2 trouvées
  - XSS Reflected (HIGH)
  - SQL Injection (CRITICAL)

### Test via interface web

1. Accéder à http://localhost:3000
2. Entrer l'URL de test
3. Cliquer sur [SCAN]
4. Vérifier l'affichage en temps réel
5. Valider la présence des 2 vulnérabilités

---

## Développement

### Workflow Git

```bash
# Créer une branche de fonctionnalité
git checkout -b feature/nom-fonctionnalite

# Commiter les modifications
git add .
git commit -m "Description de la modification"

# Pousser vers le dépôt
git push origin feature/nom-fonctionnalite
```

### Améliorations futures

- **Port Scanner** : Ajout du scanning UDP, détection des versions de services
- **Tech Detector** : Identification CDN, détection d'outils analytics
- **XSS Scanner** : DOM-based XSS, stored XSS, payloads polyglots
- **SQLi Scanner** : Blind SQLi, time-based SQLi, union-based injection

---

## Licence

Projet académique - Master 2 Cloud Computing

---

## Contact

Pour toute question ou problème, contacter l'équipe de développement :
- **Chef de projet** : Bensk
