import axios from 'axios';
import * as cheerio from 'cheerio';
import { TechnologyInfo } from '../types';

/**
 * Détecte les technologies utilisées par le site cible
 * Analyse: headers HTTP, meta tags, scripts, patterns dans le HTML
 */
export async function detectTechnologies(target: string): Promise<TechnologyInfo[]> {
  const technologies: TechnologyInfo[] = [];

  try {
    const response = await axios.get(target, {
      timeout: 10000,
      headers: {
        'User-Agent': 'VulnScanner/1.0 (Security Scanner)',
      },
      validateStatus: () => true, // Accept all status codes
    });

    const headers = response.headers;
    const html = response.data;
    const $ = cheerio.load(html);

    // Détecter le serveur web
    if (headers.server) {
      technologies.push({
        name: headers.server,
        category: 'server',
      });
    }

    // Détecter PHP
    if (headers['x-powered-by']?.includes('PHP')) {
      const version = headers['x-powered-by'].match(/PHP\/([0-9.]+)/)?.[1];
      technologies.push({
        name: 'PHP',
        version,
        category: 'language',
      });
    }

    // Détecter framework via headers
    if (headers['x-aspnet-version']) {
      technologies.push({
        name: 'ASP.NET',
        version: headers['x-aspnet-version'],
        category: 'framework',
      });
    }

    // Détecter Next.js
    if (html.includes('__NEXT_DATA__') || html.includes('_next/static')) {
      technologies.push({
        name: 'Next.js',
        category: 'framework',
      });
    }

    // Détecter React
    if (html.includes('react') || $('script[src*="react"]').length > 0) {
      technologies.push({
        name: 'React',
        category: 'framework',
      });
    }

    // Détecter WordPress
    if (html.includes('wp-content') || html.includes('wp-includes')) {
      const version = html.match(/wp-content\/themes\/([^\/]+)/)?.[1];
      technologies.push({
        name: 'WordPress',
        version,
        category: 'cms',
      });
    }

    // Détecter jQuery
    const jqueryScript = $('script[src*="jquery"]').attr('src');
    if (jqueryScript) {
      const version = jqueryScript.match(/jquery[.-]([0-9.]+)/)?.[1];
      technologies.push({
        name: 'jQuery',
        version,
        category: 'framework',
      });
    }

    // Détecter Bootstrap
    if ($('link[href*="bootstrap"]').length > 0 || html.includes('bootstrap')) {
      technologies.push({
        name: 'Bootstrap',
        category: 'framework',
      });
    }

    // Détecter via meta generator
    const generator = $('meta[name="generator"]').attr('content');
    if (generator) {
      technologies.push({
        name: generator,
        category: 'cms',
      });
    }

  } catch (error) {
    console.error('Error detecting technologies:', error);
  }

  return technologies;
}
