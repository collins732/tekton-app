import axios from 'axios';
import * as cheerio from 'cheerio';
import { TechnologyInfo } from '../types';

// ============================================================================
// TECHNOLOGY DETECTOR - Fingerprinting & Stack Analysis
// ============================================================================

/**
 * À QUOI SERT CE SCANNER :
 *
 * Le Technology Detector identifie les technologies utilisées par une application web.
 * C'est une étape cruciale dans un audit de sécurité car connaître la stack technologique
 * permet de cibler les vulnérabilités spécifiques.
 *
 * POURQUOI C'EST IMPORTANT :
 * - Identifier les versions vulnérables (ex: PHP 5.6 a des failles connues)
 * - Connaître les CMS pour chercher leurs vulnérabilités (ex: WordPress plugins)
 * - Comprendre l'architecture (React, Next.js, etc.)
 * - Découvrir les serveurs exposés (Apache, Nginx, IIS)
 *
 * EXEMPLE D'UTILISATION :
 * Si on détecte "WordPress 4.7.0", on peut chercher :
 * - CVE-2017-5487 (REST API Content Injection)
 * - CVE-2017-5488 (Cross-Site Scripting)
 * - Etc.
 *
 * MÉTHODES DE DÉTECTION :
 * 1. Headers HTTP (Server, X-Powered-By, etc.)
 * 2. Meta tags (<meta name="generator">)
 * 3. Patterns dans le HTML (wp-content, _next, etc.)
 * 4. Scripts et librairies chargés (jquery, react, etc.)
 * 5. Cookies spécifiques (PHPSESSID, ASP.NET_SessionId)
 * 6. Fichiers caractéristiques (/wp-admin, /admin.php)
 *
 * [WARNING] NOTE :
 * Ce scanner ne détecte PAS de vulnérabilités directement.
 * Il fournit des informations pour orienter les tests suivants.
 */

// Technologies détectables par headers
const HEADER_SIGNATURES = {
  // Serveurs Web
  'nginx': { pattern: /nginx/i, category: 'server' as const },
  'apache': { pattern: /apache/i, category: 'server' as const },
  'iis': { pattern: /Microsoft-IIS/i, category: 'server' as const },
  'litespeed': { pattern: /litespeed/i, category: 'server' as const },
  'cloudflare': { pattern: /cloudflare/i, category: 'server' as const },

  // Langages
  'php': { pattern: /PHP\/([0-9.]+)/i, category: 'language' as const },
  'asp.net': { pattern: /ASP\.NET/i, category: 'framework' as const },

  // Frameworks
  'express': { pattern: /express/i, category: 'framework' as const },
  'django': { pattern: /django/i, category: 'framework' as const },
};

// Patterns HTML pour détection
const HTML_PATTERNS = [
  // CMS
  { name: 'WordPress', pattern: /wp-content|wp-includes/i, category: 'cms' as const },
  { name: 'Drupal', pattern: /sites\/default|drupal/i, category: 'cms' as const },
  { name: 'Joomla', pattern: /\/joomla|com_content/i, category: 'cms' as const },
  { name: 'Magento', pattern: /Mage\.Cookies|\/skin\/frontend/i, category: 'cms' as const },
  { name: 'Shopify', pattern: /cdn\.shopify\.com|myshopify\.com/i, category: 'cms' as const },
  { name: 'Wix', pattern: /wix\.com|parastorage\.com/i, category: 'cms' as const },

  // Frameworks JavaScript
  { name: 'Next.js', pattern: /__NEXT_DATA__|_next\/static/i, category: 'framework' as const },
  { name: 'Nuxt.js', pattern: /__NUXT__|_nuxt\//i, category: 'framework' as const },
  { name: 'React', pattern: /react|data-reactroot|data-reactid/i, category: 'framework' as const },
  { name: 'Vue.js', pattern: /vue\.js|data-v-|v-cloak/i, category: 'framework' as const },
  { name: 'Angular', pattern: /ng-app|ng-controller|angular\.js/i, category: 'framework' as const },
  { name: 'Svelte', pattern: /svelte|_svelte/i, category: 'framework' as const },

  // Librairies CSS
  { name: 'Bootstrap', pattern: /bootstrap|bs-|col-md/i, category: 'framework' as const },
  { name: 'Tailwind CSS', pattern: /tailwind|tw-/i, category: 'framework' as const },
  { name: 'Material-UI', pattern: /material-ui|mui/i, category: 'framework' as const },

  // Analytics & Tracking
  { name: 'Google Analytics', pattern: /google-analytics\.com|gtag|ga\(/i, category: 'other' as const },
  { name: 'Google Tag Manager', pattern: /googletagmanager\.com|GTM-/i, category: 'other' as const },
  { name: 'Facebook Pixel', pattern: /connect\.facebook\.net\/.*\/fbevents/i, category: 'other' as const },

  // CDNs
  { name: 'Cloudflare', pattern: /cdn\.cloudflare\.com|__cf_bm/i, category: 'other' as const },
  { name: 'Fastly', pattern: /fastly\.net|fastly-cdn/i, category: 'other' as const },
];

/**
 * Point d'entrée principal du Technology Detector
 */
export async function detectTechnologies(target: string): Promise<TechnologyInfo[]> {
  const technologies: TechnologyInfo[] = [];
  const detectedNames = new Set<string>(); // Pour éviter les doublons

  console.log('\n[INFO] Starting Technology Detection...');

  try {
    // Faire la requête avec tous les headers
    const response = await axios.get(target, {
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 5,
      headers: {
        'User-Agent': 'VulnScanner/2.0 (Security Audit; +https://github.com/vulnscanner)',
      },
    });

    if (response.status !== 200) {
      console.log(`   ℹ️  Target returned ${response.status}, limited tech detection`);
    }

    const headers = response.headers;
    const html = response.data?.toString() || '';
    const $ = cheerio.load(html);

    // ===== 1. DÉTECTION PAR HEADERS HTTP =====
    console.log('   [API] Analyzing HTTP headers...');

    // Server header
    if (headers.server) {
      const serverHeader = headers.server;
      console.log(`   ✓ Server: ${serverHeader}`);

      for (const [tech, sig] of Object.entries(HEADER_SIGNATURES)) {
        if (sig.pattern.test(serverHeader)) {
          const versionMatch = serverHeader.match(/\/([0-9.]+)/);
          addTechnology(technologies, detectedNames, {
            name: tech.charAt(0).toUpperCase() + tech.slice(1),
            version: versionMatch?.[1],
            category: sig.category,
          });
        }
      }
    }

    // X-Powered-By header
    if (headers['x-powered-by']) {
      const poweredBy = headers['x-powered-by'];
      console.log(`   ✓ X-Powered-By: ${poweredBy}`);

      if (/PHP/i.test(poweredBy)) {
        const version = poweredBy.match(/PHP\/([0-9.]+)/i)?.[1];
        addTechnology(technologies, detectedNames, {
          name: 'PHP',
          version,
          category: 'language',
        });
      }

      if (/ASP\.NET/i.test(poweredBy)) {
        const version = poweredBy.match(/ASP\.NET ([0-9.]+)/i)?.[1];
        addTechnology(technologies, detectedNames, {
          name: 'ASP.NET',
          version,
          category: 'framework',
        });
      }

      if (/Express/i.test(poweredBy)) {
        addTechnology(technologies, detectedNames, {
          name: 'Express.js',
          category: 'framework',
        });
      }
    }

    // Autres headers intéressants
    if (headers['x-aspnet-version']) {
      addTechnology(technologies, detectedNames, {
        name: 'ASP.NET',
        version: headers['x-aspnet-version'],
        category: 'framework',
      });
    }

    if (headers['x-drupal-cache'] || headers['x-drupal-dynamic-cache']) {
      addTechnology(technologies, detectedNames, {
        name: 'Drupal',
        category: 'cms',
      });
    }

    // ===== 2. DÉTECTION PAR PATTERNS HTML =====
    console.log('   [SEARCH] Analyzing HTML patterns...');

    for (const pattern of HTML_PATTERNS) {
      if (pattern.pattern.test(html)) {
        addTechnology(technologies, detectedNames, {
          name: pattern.name,
          category: pattern.category,
        });
        console.log(`   ✓ Detected: ${pattern.name}`);
      }
    }

    // ===== 3. DÉTECTION PAR META TAGS =====
    console.log('   [TAG]  Analyzing meta tags...');

    const generator = $('meta[name="generator"]').attr('content');
    if (generator) {
      console.log(`   ✓ Generator: ${generator}`);

      // Extraire le nom et la version
      const match = generator.match(/^([^\d]+)\s*([\d.]+)?/);
      if (match) {
        addTechnology(technologies, detectedNames, {
          name: match[1].trim(),
          version: match[2],
          category: 'cms',
        });
      }
    }

    // ===== 4. DÉTECTION PAR SCRIPTS =====
    console.log('   [JS] Analyzing loaded scripts...');

    const scripts = $('script[src]').toArray();

    for (const script of scripts) {
      const src = $(script).attr('src') || '';

      // jQuery
      if (/jquery[.-]([0-9.]+)/i.test(src)) {
        const version = src.match(/jquery[.-]([0-9.]+)/i)?.[1];
        addTechnology(technologies, detectedNames, {
          name: 'jQuery',
          version,
          category: 'framework',
        });
        console.log(`   ✓ jQuery ${version || '(unknown version)'}`);
      }

      // React
      if (/react[.-]dom|react\.production/i.test(src)) {
        const version = src.match(/react[.-]([0-9.]+)/i)?.[1];
        addTechnology(technologies, detectedNames, {
          name: 'React',
          version,
          category: 'framework',
        });
        console.log(`   ✓ React ${version || '(unknown version)'}`);
      }

      // Vue.js
      if (/vue[.-]([0-9.]+)/i.test(src)) {
        const version = src.match(/vue[.-]([0-9.]+)/i)?.[1];
        addTechnology(technologies, detectedNames, {
          name: 'Vue.js',
          version,
          category: 'framework',
        });
        console.log(`   ✓ Vue.js ${version || '(unknown version)'}`);
      }
    }

    // ===== 5. DÉTECTION PAR LINKS CSS =====
    const links = $('link[href]').toArray();

    for (const link of links) {
      const href = $(link).attr('href') || '';

      // Bootstrap
      if (/bootstrap[.-]([0-9.]+)/i.test(href)) {
        const version = href.match(/bootstrap[.-]([0-9.]+)/i)?.[1];
        addTechnology(technologies, detectedNames, {
          name: 'Bootstrap',
          version,
          category: 'framework',
        });
        console.log(`   ✓ Bootstrap ${version || '(unknown version)'}`);
      }
    }

    // ===== 6. DÉTECTION PAR COOKIES =====
    const cookies = response.headers['set-cookie'] || [];

    if (cookies.some(c => c.includes('PHPSESSID'))) {
      addTechnology(technologies, detectedNames, {
        name: 'PHP',
        category: 'language',
      });
      console.log('   ✓ PHP (detected via PHPSESSID cookie)');
    }

    if (cookies.some(c => c.includes('ASP.NET_SessionId'))) {
      addTechnology(technologies, detectedNames, {
        name: 'ASP.NET',
        category: 'framework',
      });
      console.log('   ✓ ASP.NET (detected via session cookie)');
    }

    // ===== 7. DÉTECTION PAR VERSION COMMENTS =====
    // WordPress souvent laisse des commentaires de version
    const wpVersionMatch = html.match(/WordPress ([0-9.]+)/i);
    if (wpVersionMatch) {
      addTechnology(technologies, detectedNames, {
        name: 'WordPress',
        version: wpVersionMatch[1],
        category: 'cms',
      });
      console.log(`   ✓ WordPress ${wpVersionMatch[1]} (from HTML comment)`);
    }

  } catch (error) {
    console.error('   [ERROR] Error detecting technologies:', error);
  }

  console.log(`\n   [OK] Technology detection completed: ${technologies.length} technologies found`);

  // Afficher le résumé
  if (technologies.length > 0) {
    console.log('\n   [STATS] Detected Stack:');
    const byCategory = groupByCategory(technologies);

    for (const [category, techs] of Object.entries(byCategory)) {
      console.log(`\n      ${getCategoryIcon(category)} ${category.toUpperCase()}:`);
      for (const tech of techs) {
        const version = tech.version ? ` (v${tech.version})` : '';
        console.log(`         - ${tech.name}${version}`);
      }
    }
  }

  return technologies;
}

/**
 * Ajoute une technologie en évitant les doublons
 */
function addTechnology(
  technologies: TechnologyInfo[],
  detectedNames: Set<string>,
  tech: TechnologyInfo
): void {
  const key = `${tech.name.toLowerCase()}-${tech.category}`;

  if (!detectedNames.has(key)) {
    detectedNames.add(key);
    technologies.push(tech);
  } else {
    // Si déjà détecté, mettre à jour la version si elle est plus précise
    const existing = technologies.find(
      t => t.name.toLowerCase() === tech.name.toLowerCase() && t.category === tech.category
    );

    if (existing && tech.version && !existing.version) {
      existing.version = tech.version;
    }
  }
}

/**
 * Groupe les technologies par catégorie
 */
function groupByCategory(technologies: TechnologyInfo[]): Record<string, TechnologyInfo[]> {
  const grouped: Record<string, TechnologyInfo[]> = {
    server: [],
    language: [],
    framework: [],
    cms: [],
    other: [],
  };

  for (const tech of technologies) {
    grouped[tech.category].push(tech);
  }

  // Retirer les catégories vides
  return Object.fromEntries(
    Object.entries(grouped).filter(([_, techs]) => techs.length > 0)
  );
}

/**
 * Icônes pour les catégories
 */
function getCategoryIcon(category: string): string {
  const icons: Record<string, string> = {
    server: '[SERVER]',
    language: '[TECH]',
    framework: '⚛️',
    cms: '[CMS]',
    other: '[TOOL]',
  };

  return icons[category] || '[PACKAGE]';
}

/**
 * Analyse les vulnérabilités connues pour les technologies détectées
 * (Fonction utilitaire pour extension future)
 */
export function analyzeKnownVulnerabilities(tech: TechnologyInfo): string[] {
  const vulnerabilities: string[] = [];

  // Bases de données de versions vulnérables
  const knownVulnerable: Record<string, Record<string, string[]>> = {
    'WordPress': {
      '4.7.0': ['CVE-2017-5487', 'CVE-2017-5488'],
      '4.7.1': ['CVE-2017-5610', 'CVE-2017-5611'],
      '5.0.0': ['CVE-2019-8942', 'CVE-2019-8943'],
    },
    'PHP': {
      '5.6': ['Multiple EOL vulnerabilities'],
      '7.0': ['Multiple EOL vulnerabilities'],
      '7.1': ['CVE-2019-11043 (RCE)'],
    },
    'jQuery': {
      '1.x': ['CVE-2020-11022 (XSS)', 'CVE-2020-11023 (XSS)'],
      '2.x': ['CVE-2020-11022 (XSS)', 'CVE-2020-11023 (XSS)'],
    },
  };

  if (tech.version && knownVulnerable[tech.name]) {
    const versionVulns = knownVulnerable[tech.name][tech.version];
    if (versionVulns) {
      vulnerabilities.push(...versionVulns);
    }

    // Vérifier les versions majeures (ex: 5.x)
    const majorVersion = tech.version.split('.')[0];
    const majorVulns = knownVulnerable[tech.name][`${majorVersion}.x`];
    if (majorVulns) {
      vulnerabilities.push(...majorVulns);
    }
  }

  return vulnerabilities;
}
