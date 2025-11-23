import { ScanResult } from './types';
import { createScan, updateScan, getScan } from './db';
import { scanPorts } from './scanners/port-scanner';
import { detectTechnologies } from './scanners/tech-detector';
import { scanXSS } from './scanners/xss-scanner';
import { scanSQLi } from './scanners/sqli-scanner';
import { scanAuthAndAccess } from './scanners/auth-and-access-scanner';
import { scanSecurityHeaders } from './scanners/security-headers-scanner';

/**
 * Orchestre l'exécution complète d'un scan
 */
export async function executeScan(scanId: string, target: string): Promise<void> {
  try {
    // Initialiser le scan
    createScan(scanId, target);
    updateScan(scanId, {
      status: 'running',
      currentStep: 'Initialisation...',
      progress: 0,
    });

    const results: ScanResult['results'] = {
      ports: [],
      technologies: [],
      vulnerabilities: [],
    };

    // Étape 1: Port Scanning (25%)
    updateScan(scanId, {
      currentStep: 'Scanning ports...',
      progress: 10,
    });

    results.ports = await scanPorts(target);
    updateScan(scanId, {
      results,
      progress: 25,
    });

    // Étape 2: Technology Detection (40%)
    updateScan(scanId, {
      currentStep: 'Detecting technologies...',
      progress: 30,
    });

    results.technologies = await detectTechnologies(target);
    updateScan(scanId, {
      results,
      progress: 40,
    });

    // Étape 3: Security Headers Check (50%)
    updateScan(scanId, {
      currentStep: 'Checking security headers...',
      progress: 45,
    });

    const headerVulns = await scanSecurityHeaders(target);
    results.vulnerabilities = [...(results.vulnerabilities || []), ...headerVulns];
    updateScan(scanId, {
      results,
      progress: 50,
    });

    // Étape 4: XSS Scanning (65%)
    updateScan(scanId, {
      currentStep: 'Testing for XSS vulnerabilities...',
      progress: 55,
    });

    const xssVulns = await scanXSS(target);
    results.vulnerabilities = [...(results.vulnerabilities || []), ...xssVulns];
    updateScan(scanId, {
      results,
      progress: 65,
    });

    // Étape 5: SQL Injection Scanning (75%)
    updateScan(scanId, {
      currentStep: 'Testing for SQL injection...',
      progress: 70,
    });

    const sqliVulns = await scanSQLi(target);
    results.vulnerabilities = [...(results.vulnerabilities || []), ...sqliVulns];
    updateScan(scanId, {
      results,
      progress: 75,
    });

    // Étape 6: Authentication & Access Control Scanning (100%)
    updateScan(scanId, {
      currentStep: 'Testing for authentication and access control issues...',
      progress: 80,
    });

    const authAccessVulns = await scanAuthAndAccess(target);
    results.vulnerabilities = [...(results.vulnerabilities || []), ...authAccessVulns];

    // Finaliser le scan
    updateScan(scanId, {
      status: 'completed',
      currentStep: 'Scan completed',
      progress: 100,
      results,
      completedAt: new Date(),
    });

  } catch (error) {
    console.error('Scan error:', error);
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
