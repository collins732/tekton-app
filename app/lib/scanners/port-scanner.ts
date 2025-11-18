import { PortScanResult } from '../types';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Ports communs à scanner
const COMMON_PORTS = [
  { port: 21, service: 'FTP' },
  { port: 22, service: 'SSH' },
  { port: 23, service: 'Telnet' },
  { port: 25, service: 'SMTP' },
  { port: 80, service: 'HTTP' },
  { port: 443, service: 'HTTPS' },
  { port: 3306, service: 'MySQL' },
  { port: 3389, service: 'RDP' },
  { port: 5432, service: 'PostgreSQL' },
  { port: 8080, service: 'HTTP-Alt' },
  { port: 8443, service: 'HTTPS-Alt' },
];

/**
 * Scanne les ports ouverts d'une cible
 * Utilise nmap si disponible, sinon fallback sur TCP connect
 */
export async function scanPorts(target: string): Promise<PortScanResult[]> {
  const hostname = new URL(target).hostname;

  try {
    // Essayer d'utiliser nmap
    const nmapResults = await scanWithNmap(hostname);
    if (nmapResults.length > 0) {
      return nmapResults;
    }
  } catch (error) {
    console.warn('nmap not available, using fallback scanner');
  }

  // Fallback: scan TCP simple
  return await scanWithTCP(hostname);
}

/**
 * Scan avec nmap (si installé)
 */
async function scanWithNmap(hostname: string): Promise<PortScanResult[]> {
  const ports = COMMON_PORTS.map(p => p.port).join(',');
  const { stdout } = await execAsync(`nmap -p ${ports} ${hostname} --open -oG -`);

  const results: PortScanResult[] = [];
  const lines = stdout.split('\n');

  for (const line of lines) {
    if (line.includes('Ports:')) {
      const portMatches = line.match(/(\d+)\/open\/([a-z]+)/g);
      if (portMatches) {
        for (const match of portMatches) {
          const [port, , protocol] = match.split('/');
          const portNum = parseInt(port);
          const serviceInfo = COMMON_PORTS.find(p => p.port === portNum);

          results.push({
            port: portNum,
            state: 'open',
            service: serviceInfo?.service || protocol,
          });
        }
      }
    }
  }

  return results;
}

/**
 * Scan TCP simple (fallback)
 */
async function scanWithTCP(hostname: string): Promise<PortScanResult[]> {
  const results: PortScanResult[] = [];

  // Scan en parallèle mais limité à 5 simultanés pour éviter surcharge
  const chunks = chunkArray(COMMON_PORTS, 5);

  for (const chunk of chunks) {
    const promises = chunk.map(async ({ port, service }) => {
      const isOpen = await checkPort(hostname, port);
      return {
        port,
        state: isOpen ? ('open' as const) : ('closed' as const),
        service: isOpen ? service : undefined,
      };
    });

    const chunkResults = await Promise.all(promises);
    results.push(...chunkResults.filter(r => r.state === 'open'));
  }

  return results;
}

/**
 * Vérifie si un port est ouvert
 */
function checkPort(hostname: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();

    const timeout = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, 2000);

    socket.connect(port, hostname, () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve(true);
    });

    socket.on('error', () => {
      clearTimeout(timeout);
      resolve(false);
    });
  });
}

/**
 * Découpe un tableau en chunks
 */
function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}
