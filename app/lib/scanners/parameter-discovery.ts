import axios from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';

/**
 * PARAMETER DISCOVERY - Découverte automatique des paramètres à tester
 *
 * Ce module découvre TOUS les paramètres testables d'un site :
 * - Paramètres GET dans les URLs
 * - Paramètres POST dans les formulaires
 * - Headers personnalisés
 */

export interface DiscoveredParameter {
  url: string;
  method: 'GET' | 'POST';
  paramName: string;
  paramType: 'url' | 'form' | 'header';
  defaultValue?: string;
  formAction?: string;
}

/**
 * Point d'entrée principal - Découvre tous les paramètres testables
 */
export async function discoverParameters(endpoints: string[]): Promise<DiscoveredParameter[]> {
  const parameters: DiscoveredParameter[] = [];
  const tested = new Set<string>();

  console.log(`\n[INFO] Discovering parameters from ${endpoints.length} endpoints...`);

  for (const endpoint of endpoints) {
    try {
      // Éviter de tester le même endpoint plusieurs fois
      const baseUrl = endpoint.split('?')[0];
      if (tested.has(baseUrl)) continue;
      tested.add(baseUrl);

      // 1. Extraire les paramètres GET de l'URL
      const urlParams = extractUrlParameters(endpoint);
      parameters.push(...urlParams);

      // 2. Crawler la page pour trouver les formulaires
      const formParams = await extractFormParameters(endpoint);
      parameters.push(...formParams);

      // 3. Chercher des paramètres dans les liens de la page
      const linkParams = await extractLinkParameters(endpoint);
      parameters.push(...linkParams);

      // Petit délai pour ne pas surcharger
      await sleep(100);

    } catch (error) {
      // Continue silently
    }
  }

  // Dédupliquer
  const unique = deduplicateParameters(parameters);

  console.log(`   ✓ Found ${unique.length} testable parameters`);

  return unique;
}

/**
 * [1] Extrait les paramètres GET de l'URL
 */
function extractUrlParameters(url: string): DiscoveredParameter[] {
  const parameters: DiscoveredParameter[] = [];

  try {
    const parsedUrl = new URL(url);
    const searchParams = parsedUrl.searchParams;

    searchParams.forEach((value, key) => {
      parameters.push({
        url: url,
        method: 'GET',
        paramName: key,
        paramType: 'url',
        defaultValue: value,
      });
    });
  } catch (error) {
    // URL invalide
  }

  return parameters;
}

/**
 * [2] Extrait les paramètres des formulaires
 */
async function extractFormParameters(url: string): Promise<DiscoveredParameter[]> {
  const parameters: DiscoveredParameter[] = [];

  try {
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'VulnScanner/2.0 ParamDiscovery' },
    });

    if (response.status !== 200) {
      return parameters;
    }

    const $ = cheerio.load(response.data);

    // Analyser tous les formulaires
    $('form').each((_, formElement) => {
      const form = $(formElement);
      const action = form.attr('action') || '';
      const method = (form.attr('method') || 'GET').toUpperCase() as 'GET' | 'POST';

      // Construire l'URL d'action du formulaire
      let formUrl: string;
      try {
        formUrl = new URL(action, url).href;
      } catch (error) {
        formUrl = url;
      }

      // Extraire tous les inputs, textareas, selects
      const inputs = form.find('input, textarea, select');

      inputs.each((_, inputElement) => {
        const input = $(inputElement);
        const name = input.attr('name');
        const type = input.attr('type') || 'text';
        const value = input.attr('value') || '';

        // Ignorer les boutons et hidden fields (sauf csrf tokens)
        if (!name || type === 'submit' || type === 'button') {
          return;
        }

        parameters.push({
          url: formUrl,
          method: method,
          paramName: name,
          paramType: 'form',
          defaultValue: value,
          formAction: formUrl,
        });
      });
    });

  } catch (error) {
    // Erreur de crawling
  }

  return parameters;
}

/**
 * [3] Extrait les paramètres des liens sur la page
 */
async function extractLinkParameters(url: string): Promise<DiscoveredParameter[]> {
  const parameters: DiscoveredParameter[] = [];

  try {
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'VulnScanner/2.0 ParamDiscovery' },
    });

    if (response.status !== 200) {
      return parameters;
    }

    const $ = cheerio.load(response.data);
    const baseUrl = new URL(url);

    // Analyser tous les liens <a href="...?param=value">
    $('a[href]').each((_, element) => {
      const href = $(element).attr('href');
      if (!href || !href.includes('?')) return;

      try {
        const linkUrl = new URL(href, url);

        // Seulement les liens du même domaine
        if (linkUrl.hostname !== baseUrl.hostname) {
          return;
        }

        // Extraire les paramètres
        linkUrl.searchParams.forEach((value, key) => {
          parameters.push({
            url: linkUrl.href,
            method: 'GET',
            paramName: key,
            paramType: 'url',
            defaultValue: value,
          });
        });
      } catch (error) {
        // URL invalide
      }
    });

  } catch (error) {
    // Erreur de crawling
  }

  return parameters;
}

/**
 * Déduplique les paramètres pour éviter de tester plusieurs fois le même
 */
function deduplicateParameters(parameters: DiscoveredParameter[]): DiscoveredParameter[] {
  const seen = new Set<string>();
  const unique: DiscoveredParameter[] = [];

  for (const param of parameters) {
    // Créer une clé unique : url + method + paramName
    const key = `${param.url}|${param.method}|${param.paramName}`;

    if (!seen.has(key)) {
      seen.add(key);
      unique.push(param);
    }
  }

  return unique;
}

/**
 * Filtre les paramètres pour ne garder que les plus intéressants
 */
export function filterInterestingParameters(parameters: DiscoveredParameter[]): DiscoveredParameter[] {
  // Paramètres suspects à prioriser
  const suspiciousNames = [
    'id', 'user', 'username', 'email', 'search', 'query', 'q',
    'name', 'file', 'page', 'url', 'cat', 'category', 'item',
    'product', 'action', 'cmd', 'exec', 'code', 'data',
  ];

  // Séparer les paramètres suspects et normaux
  const suspicious: DiscoveredParameter[] = [];
  const normal: DiscoveredParameter[] = [];

  for (const param of parameters) {
    const paramLower = param.paramName.toLowerCase();
    const isSuspicious = suspiciousNames.some(name => paramLower.includes(name));

    if (isSuspicious) {
      suspicious.push(param);
    } else {
      normal.push(param);
    }
  }

  // Retourner les suspects en premier, puis les normaux
  return [...suspicious, ...normal];
}

/**
 * Génère toutes les URLs de test pour un paramètre
 */
export function generateTestUrls(
  param: DiscoveredParameter,
  payload: string
): { url: string; method: 'GET' | 'POST'; data?: Record<string, string> } {
  if (param.method === 'GET' || param.paramType === 'url') {
    // Pour GET, modifier l'URL
    try {
      const testUrl = new URL(param.url);
      testUrl.searchParams.set(param.paramName, payload);

      return {
        url: testUrl.href,
        method: 'GET',
      };
    } catch (error) {
      return { url: param.url, method: 'GET' };
    }
  } else {
    // Pour POST, préparer les données du formulaire
    const formData: Record<string, string> = {};
    formData[param.paramName] = payload;

    return {
      url: param.formAction || param.url,
      method: 'POST',
      data: formData,
    };
  }
}

/**
 * Utilitaire : Sleep
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Affiche un résumé des paramètres découverts
 */
export function summarizeParameters(parameters: DiscoveredParameter[]): void {
  const byType = {
    url: parameters.filter(p => p.paramType === 'url').length,
    form: parameters.filter(p => p.paramType === 'form').length,
    header: parameters.filter(p => p.paramType === 'header').length,
  };

  const byMethod = {
    GET: parameters.filter(p => p.method === 'GET').length,
    POST: parameters.filter(p => p.method === 'POST').length,
  };

  console.log('\n   [STATS] Parameter Summary:');
  console.log(`      Total: ${parameters.length}`);
  console.log(`      By type: URL=${byType.url}, Form=${byType.form}, Header=${byType.header}`);
  console.log(`      By method: GET=${byMethod.GET}, POST=${byMethod.POST}`);
}
