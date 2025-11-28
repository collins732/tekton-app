import { ScanResult } from './types';
import { createScan, updateScan, getScan } from './db';
import { scanPorts } from './scanners/port-scanner';
import { detectTechnologies } from './scanners/tech-detector';
import { scanXSS } from './scanners/xss-scanner';
import { scanSQLi, scanTimeBasedSQLi } from './scanners/sqli-scanner';
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

// Helper function to add timeout to any promise
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms))
  ]);
}

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
      discoveredEndpoints: [],
    };

    console.log('\n' + '═'.repeat(60));
    console.log('  TEKTON ULTRA SCANNER v6.0 - OPTIMIZED');
    console.log('═'.repeat(60));
    console.log(`  Target: ${target}`);
    console.log('  Priority: SQLi/XSS detection FIRST');
    console.log('═'.repeat(60));

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 1: QUICK CRAWL (0-10%) - Rapide pour trouver les formulaires
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Quick crawl: Finding forms and endpoints...',
      progress: 5,
    });

    let crawlResults: any = { urls: [], forms: [], apiEndpoints: [], jsFiles: [] };
    let pagesToTest: any[] = [];

    try {
      // Timeout de 30 secondes pour le crawl
      crawlResults = await withTimeout(deepCrawl(target, 50), 30000, { urls: [target], forms: [], apiEndpoints: [], jsFiles: [] });
      console.log(`  [CRAWL] Found ${crawlResults.urls.length} pages, ${crawlResults.forms.length} forms`);
    } catch (crawlError) {
      console.log('  [WARN] Crawl failed, using target URL only');
      crawlResults = { urls: [target], forms: [], apiEndpoints: [], jsFiles: [] };
    }

    // Ajouter les pages à tester
    for (const url of crawlResults.urls) {
      pagesToTest.push({ url, method: 'GET', source: 'crawl' });
    }
    if (!pagesToTest.some(p => p.url === target)) {
      pagesToTest.unshift({ url: target, method: 'GET', source: 'target' });
    }

    results.discoveredEndpoints = pagesToTest.map(p => p.url);

    updateScan(scanId, {
      currentStep: `Found ${pagesToTest.length} pages to test`,
      progress: 10,
      results,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 2: ULTRA SQLI - PRIORITÉ #1 (10-35%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'PRIORITY: Testing SQL Injection (Time-based + Error-based)...',
      progress: 15,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  🔴 PRIORITY #1: SQL INJECTION TESTING');
    console.log('═'.repeat(60));

    let sqliVulns: any[] = [];
    try {
      // PRIORITÉ: Time-based blind SQLi via HTTP (plus fiable que Puppeteer)
      console.log('  [SQLI] Testing Time-Based Blind SQLi via HTTP...');
      const timeBasedVulns = await withTimeout(scanTimeBasedSQLi(target), 180000, []);
      sqliVulns = [...timeBasedVulns];

      if (sqliVulns.length === 0) {
        // Si pas trouvé, essayer ultra scanner (Puppeteer)
        console.log('  [SQLI] No time-based found, trying ultra scanner...');
        const ultraVulns = await withTimeout(ultraScanSQLi(target, crawlResults.forms), 180000, []);
        sqliVulns = [...sqliVulns, ...ultraVulns];
      }

      console.log(`  [SQLI] Found ${sqliVulns.length} vulnerabilities`);
    } catch (ultraError) {
      console.log('  [WARN] SQLi scan failed, trying fallback...');
      try {
        sqliVulns = await withTimeout(scanSQLi(target), 60000, []);
      } catch (fallbackError) {
        console.log('  [WARN] All SQLi scans failed');
      }
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...sqliVulns];

    updateScan(scanId, {
      currentStep: `SQLi: ${sqliVulns.length} vulnerabilities found`,
      results,
      progress: 35,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 3: ULTRA XSS - PRIORITÉ #2 (35-55%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Testing XSS vulnerabilities...',
      progress: 40,
    });

    console.log('\n' + '═'.repeat(60));
    console.log('  🟠 PRIORITY #2: XSS TESTING');
    console.log('═'.repeat(60));

    let xssVulns: any[] = [];
    try {
      xssVulns = await withTimeout(ultraScanXSS(target, crawlResults.forms), 90000, []);
      console.log(`  [XSS] Found ${xssVulns.length} vulnerabilities`);
    } catch (ultraError) {
      console.log('  [WARN] Ultra XSS failed, trying browser scan...');
      try {
        xssVulns = await withTimeout(browserScanXSS(target), 60000, []);
      } catch (browserError) {
        console.log('  [WARN] Browser XSS failed, trying HTTP scan...');
        xssVulns = await withTimeout(scanXSS(target), 30000, []);
      }
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...xssVulns];

    updateScan(scanId, {
      currentStep: `XSS: ${xssVulns.length} vulnerabilities found`,
      results,
      progress: 55,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 4: AUTH BYPASS (55-65%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Testing authentication bypass...',
      progress: 58,
    });

    console.log('\n' + '─'.repeat(60));
    console.log('  AUTH BYPASS TESTING');
    console.log('─'.repeat(60));

    let authVulns: any[] = [];
    try {
      const authBypassVulns = await withTimeout(scanAuthBypass(target), 30000, []);
      const authAccessVulns = await withTimeout(scanAuthAndAccess(target), 30000, []);
      authVulns = [...authBypassVulns, ...authAccessVulns];
    } catch (authError) {
      console.log('  [WARN] Auth scan failed');
    }

    results.vulnerabilities = [...(results.vulnerabilities || []), ...authVulns];

    updateScan(scanId, {
      results,
      progress: 65,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 5: SECURITY HEADERS (65-75%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Checking security headers...',
      progress: 68,
    });

    const headerPages = pagesToTest.slice(0, 5);
    for (const page of headerPages) {
      try {
        const headerVulns = await withTimeout(scanSecurityHeaders(page.url), 10000, []);
        for (const vuln of headerVulns) {
          const exists = results.vulnerabilities?.some(v => v.title === vuln.title);
          if (!exists) {
            results.vulnerabilities = [...(results.vulnerabilities || []), vuln];
          }
        }
      } catch (e) {}
    }

    updateScan(scanId, {
      results,
      progress: 75,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 6: SENSITIVE FILES (75-85%) - Avec timeout strict
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Scanning for sensitive files (quick scan)...',
      progress: 78,
    });

    try {
      // Timeout de 45 secondes max pour les fichiers sensibles
      results.hiddenFiles = await withTimeout(
        scanHiddenFiles(target, { verbose: false, concurrency: 50, includeBackupVariations: false }),
        45000,
        []
      );
    } catch (e) {
      console.log('  [WARN] Sensitive files scan timeout');
      results.hiddenFiles = [];
    }

    updateScan(scanId, {
      results,
      progress: 85,
    });

    // ═══════════════════════════════════════════════════════════════════
    // ÉTAPE 7: SSRF + TECH DETECTION (85-95%)
    // ═══════════════════════════════════════════════════════════════════
    updateScan(scanId, {
      currentStep: 'Final checks: SSRF, ports, technologies...',
      progress: 88,
    });

    // SSRF (avec timeout)
    try {
      const ssrfVulns = await withTimeout(scanSSRF(target), 30000, []);
      results.vulnerabilities = [...(results.vulnerabilities || []), ...ssrfVulns];
    } catch (e) {}

    // Port scan (avec timeout)
    try {
      results.ports = await withTimeout(scanPorts(target), 20000, []);
    } catch (e) {}

    // Tech detection (avec timeout)
    try {
      results.technologies = await withTimeout(detectTechnologies(target), 15000, []);
    } catch (e) {}

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
