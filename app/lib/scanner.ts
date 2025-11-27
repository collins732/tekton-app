import { ScanResult } from './types';
import { createScan, updateScan, getScan } from './db';
import { scanPorts } from './scanners/port-scanner';
import { detectTechnologies } from './scanners/tech-detector';
import { scanXSS } from './scanners/xss-scanner';
import { scanSQLi } from './scanners/sqli-scanner';
import { scanAuthAndAccess } from './scanners/auth-and-access-scanner';
import { scanHiddenFiles } from './scanners/sensitive-file-scanner';
import { scanSecurityHeaders } from './scanners/security-headers-scanner';
import { discoverEndpoints, DiscoveredEndpoint } from './scanners/endpoint-discovery';
import { resetSession } from './scanners/http-client';
import { browserScanXSS, browserScanSQLi, browserCrawl, closeBrowser } from './scanners/browser-scanner';
import {
  deepCrawl,
  ultraScanXSS,
  ultraScanSQLi,
  scanSSRF,
  scanSensitiveFiles,
  scanAuthBypass,
  closeUltraBrowser
} from './scanners/ultra-scanner';

/**
 * TEKTON VULNERABILITY SCANNER v5.0 - ULTRA EDITION
 *
 * Scanner de niveau expert avec bypass WAF avancé
 *
 * CAPACITÉS:
 * 1. DEEP CRAWL - Découvre TOUTES les pages + API + JS endpoints
 * 2. 500+ PAYLOADS - XSS/SQLi avancés avec bypass WAF
 * 3. MULTI-VULN - SSRF, XXE, LFI, Auth bypass
 * 4. STEALTH MODE - Bypass Cloudflare, Akamai, Imperva
 */

export async function executeScan(scanId: string, target: string, userId: string = 'default_user', cost: number = 0): Promise<void> {
  try {
    // Reset HTTP session
    resetSession();

    // Initialiser le scan
    createScan(scanId, target, userId, cost);
    updateScan(scanId, {
      status: 'running',
      currentStep: 'Initializing scanner...',
      progress: 0,
    });

    const results: ScanResult['results'] = {
      ports: [],
      technologies: [],
      vulnerabilities: [],
      discoveredEndpoints: [], // Nouveau: stocker les pages découvertes
    };

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 1: DEEP CRAWL ULTRA (0-20%) - Browser-based avec stealth
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'ULTRA CRAWL: Deep scanning with browser (WAF bypass)...',
      progress: 5,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  TEKTON ULTRA SCANNER v5.0 - EXPERT LEVEL');
    console.log('═'.repeat(60));
    console.log(`  Target: ${target}`);
    console.log('  Mode: Stealth (Cloudflare/Akamai/Imperva bypass)');
    console.log('═'.repeat(60));

    // ULTRA CRAWL avec browser stealth + découverte API
    let crawlResults: any;
    let pagesToTest: any[] = [];

    try {
      crawlResults = await deepCrawl(target, 100);
      console.log(`\n  [DEEP CRAWL] Discovered:`);
      console.log(`    - ${crawlResults.urls.length} pages`);
      console.log(`    - ${crawlResults.apiEndpoints.length} API endpoints`);
      console.log(`    - ${crawlResults.forms.length} forms`);
      console.log(`    - ${crawlResults.jsFiles.length} JS files`);

      // Stocker tous les endpoints découverts
      results.discoveredEndpoints = [
        ...crawlResults.urls,
        ...crawlResults.apiEndpoints,
      ];

      // Créer la liste des pages à tester
      for (const url of crawlResults.urls) {
        pagesToTest.push({
          url,
          method: 'GET',
          source: 'browser_crawl',
          isAPI: false,
        });
      }

    } catch (crawlError) {
      console.log('  [WARN] Ultra crawl failed, using fallback...');
      // Fallback au crawl HTTP classique
      const discoveredEndpoints = await discoverEndpoints(target);
      pagesToTest = discoveredEndpoints.filter(e => {
        const isAsset = /\.(jpg|jpeg|png|gif|css|js|ico|svg|woff|woff2|ttf|pdf|zip|rar)$/i.test(e.url);
        return !isAsset;
      });
      results.discoveredEndpoints = pagesToTest.map(e => e.url);
      crawlResults = { forms: [], apiEndpoints: [] };
    }

    // Ajouter l'URL cible si pas déjà présente
    const targetInList = pagesToTest.some((e: any) => e.url === target);
    if (!targetInList) {
      pagesToTest.unshift({
        url: target,
        method: 'GET',
        source: 'target',
        isAPI: false,
      });
    }

    console.log('\n' + '─'.repeat(60));
    console.log(`  DISCOVERED ${pagesToTest.length} PAGES TO TEST:`);
    console.log('─'.repeat(60));
    pagesToTest.slice(0, 20).forEach((e: any, i: number) => {
      console.log(`  ${i + 1}. ${e.url}`);
    });
    if (pagesToTest.length > 20) {
      console.log(`  ... and ${pagesToTest.length - 20} more pages`);
    }

    updateScan(scanId, {
      currentStep: `Found ${pagesToTest.length} pages + ${crawlResults.apiEndpoints?.length || 0} APIs`,
      progress: 15,
      results,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 2: PORT SCANNING (10-15%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Scanning ports...',
      progress: 10,
    });

    results.ports = await scanPorts(target);
    updateScan(scanId, {
      results,
      progress: 15,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 3: TECHNOLOGY DETECTION (15-25%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Detecting technologies...',
      progress: 20,
    });

    results.technologies = await detectTechnologies(target);
    updateScan(scanId, {
      results,
      progress: 25,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 4: SECURITY HEADERS (25-35%) - Test sur TOUTES les pages
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: `Checking security headers on ${Math.min(pagesToTest.length, 10)} pages...`,
      progress: 30,
    });

    // Tester les headers sur plusieurs pages (pas seulement la cible)
    const headerPages = pagesToTest.slice(0, 10);
    for (const page of headerPages) {
      const headerVulns = await scanSecurityHeaders(page.url);
      // Éviter les doublons (même vulnérabilité sur différentes pages)
      for (const vuln of headerVulns) {
        const exists = results.vulnerabilities?.some(v =>
          v.title === vuln.title && v.type === vuln.type
        );
        if (!exists) {
          results.vulnerabilities = [...(results.vulnerabilities || []), vuln];
        }
      }
    }

    updateScan(scanId, {
      results,
      progress: 35,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 5: SENSITIVE FILES (35-45%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Scanning for sensitive files...',
      progress: 40,
    });

    results.hiddenFiles = await scanHiddenFiles(target, {
      verbose: false,
      concurrency: 30,
      includeBackupVariations: false
    });
    updateScan(scanId, {
      results,
      progress: 45,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 6: ULTRA XSS SCANNING (45-60%) - 100+ payloads avec bypass WAF
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'ULTRA XSS: Testing 100+ payloads with WAF bypass...',
      progress: 50,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  ULTRA XSS - 100+ Payloads with Cloudflare/WAF Bypass');
    console.log('═'.repeat(60));

    // Utiliser l'ULTRA scanner avec tous les formulaires découverts
    let xssVulns: any[] = [];
    try {
      xssVulns = await ultraScanXSS(target, crawlResults?.forms || []);
    } catch (ultraError) {
      console.log('   [WARN] Ultra XSS failed, trying standard browser scan...');
      try {
        xssVulns = await browserScanXSS(target);
      } catch (browserError) {
        console.log('   [WARN] Browser scan failed, using HTTP scanner...');
        xssVulns = await scanXSS(target);
      }
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...xssVulns];

    updateScan(scanId, {
      currentStep: `ULTRA XSS: ${xssVulns.length} vulnerabilities found`,
      results,
      progress: 55,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 7: ULTRA SQLI (55-70%) - 100+ payloads avec bypass WAF
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'ULTRA SQLI: Testing 100+ payloads including time-based blind...',
      progress: 60,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  ULTRA SQLI - 100+ Payloads (Error/Time/Boolean-based)');
    console.log('═'.repeat(60));

    let sqliVulns: any[] = [];
    try {
      sqliVulns = await ultraScanSQLi(target, crawlResults?.forms || []);
    } catch (ultraError) {
      console.log('   [WARN] Ultra SQLi failed, trying standard browser scan...');
      try {
        sqliVulns = await browserScanSQLi(target);
      } catch (browserError) {
        console.log('   [WARN] Browser scan failed, using HTTP scanner...');
        sqliVulns = await scanSQLi(target);
      }
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...sqliVulns];

    updateScan(scanId, {
      currentStep: `ULTRA SQLI: ${sqliVulns.length} vulnerabilities found`,
      results,
      progress: 70,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 8: SSRF SCANNING (70-75%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Testing for Server-Side Request Forgery (SSRF)...',
      progress: 72,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  SSRF SCANNING - Testing internal network access');
    console.log('═'.repeat(60));

    let ssrfVulns: any[] = [];
    try {
      ssrfVulns = await scanSSRF(target);
    } catch (ssrfError) {
      console.log('   [WARN] SSRF scan failed');
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...ssrfVulns];

    updateScan(scanId, {
      results,
      progress: 75,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 9: AUTH BYPASS & ACCESS CONTROL (75-85%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Testing for authentication bypass and access control...',
      progress: 78,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  AUTH BYPASS - Testing admin panels and login forms');
    console.log('═'.repeat(60));

    // Ultra auth bypass
    let authBypassVulns: any[] = [];
    try {
      authBypassVulns = await scanAuthBypass(target);
    } catch (authError) {
      console.log('   [WARN] Auth bypass scan failed');
    }

    // Standard auth scanner
    const authAccessVulns = await scanAuthAndAccess(target);

    results.vulnerabilities = [
      ...(results.vulnerabilities || []),
      ...authBypassVulns,
      ...authAccessVulns
    ];

    updateScan(scanId, {
      results,
      progress: 85,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 10: SENSITIVE FILES ULTRA (85-95%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Scanning for sensitive files, backups, and admin panels...',
      progress: 88,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  SENSITIVE FILES - Config, backups, git, admin panels');
    console.log('═'.repeat(60));

    let sensitiveVulns: any[] = [];
    try {
      sensitiveVulns = await scanSensitiveFiles(target);
    } catch (sensitiveError) {
      console.log('   [WARN] Sensitive files scan failed');
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...sensitiveVulns];

    updateScan(scanId, {
      results,
      progress: 95,
    });

    // ═══════════════════════════════════════════════════════════════════
    // FINALISATION
    // ═══════════════════════════════════════════════════════════════════

    // Fermer tous les navigateurs
    try {
      await closeBrowser();
      await closeUltraBrowser();
    } catch (e) {}

    // Compter les vulnérabilités par sévérité
    const criticalCount = results.vulnerabilities?.filter(v => v.severity === 'critical').length || 0;
    const highCount = results.vulnerabilities?.filter(v => v.severity === 'high').length || 0;
    const mediumCount = results.vulnerabilities?.filter(v => v.severity === 'medium').length || 0;
    const lowCount = results.vulnerabilities?.filter(v => v.severity === 'low').length || 0;

    console.log('\n' + '═'.repeat(60));
    console.log('  TEKTON ULTRA SCAN COMPLETED');
    console.log('═'.repeat(60));
    console.log(`  Target: ${target}`);
    console.log('─'.repeat(60));
    console.log(`  Pages discovered: ${pagesToTest.length}`);
    console.log(`  API endpoints: ${crawlResults?.apiEndpoints?.length || 0}`);
    console.log(`  Forms tested: ${crawlResults?.forms?.length || 0}`);
    console.log('─'.repeat(60));
    console.log(`  VULNERABILITIES FOUND: ${results.vulnerabilities?.length || 0}`);
    console.log(`    🔴 Critical: ${criticalCount}`);
    console.log(`    🟠 High: ${highCount}`);
    console.log(`    🟡 Medium: ${mediumCount}`);
    console.log(`    🟢 Low: ${lowCount}`);
    console.log(`  Hidden files found: ${results.hiddenFiles?.length || 0}`);
    console.log('═'.repeat(60) + '\n');

    updateScan(scanId, {
      status: 'completed',
      currentStep: 'ULTRA Scan completed',
      progress: 100,
      results,
      completedAt: new Date(),
    });

  } catch (error) {
    console.error('Scan error:', error);

    // Fermer tous les navigateurs en cas d'erreur
    try {
      await closeBrowser();
      await closeUltraBrowser();
    } catch (e) {}

    updateScan(scanId, {
      status: 'failed',
      error: error instanceof Error ? error.message : 'Unknown error',
      completedAt: new Date(),
    });
  }
}

/**
 * Récupère le statut d'un scan
 */
export function getScanStatus(scanId: string): ScanResult | null {
  return getScan(scanId);
}
