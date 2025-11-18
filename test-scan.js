// Script de test pour lancer un scan complet
// Usage: node test-scan.js <URL>

const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
const TARGET = process.argv[2] || 'http://testphp.vulnweb.com';

async function testScan() {
  console.log('🚀 Starting scan for:', TARGET);
  console.log('---');

  try {
    // 1. Lancer le scan
    const startResponse = await axios.post(`${BASE_URL}/api/scan`, {
      url: TARGET
    });

    const { scanId } = startResponse.data;
    console.log('✅ Scan started with ID:', scanId);
    console.log('---');

    // 2. Polling pour suivre la progression
    let completed = false;
    let lastProgress = 0;

    while (!completed) {
      await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2s

      const statusResponse = await axios.get(`${BASE_URL}/api/scan/${scanId}`);
      const scan = statusResponse.data;

      // Afficher la progression si changée
      if (scan.progress !== lastProgress) {
        console.log(`📊 Progress: ${scan.progress}% - ${scan.currentStep}`);
        lastProgress = scan.progress;
      }

      // Vérifier si terminé
      if (scan.status === 'completed' || scan.status === 'failed') {
        completed = true;

        console.log('---');
        console.log('🎉 Scan completed!');
        console.log('');
        console.log('RESULTS:');
        console.log('========');
        console.log('');

        // Ports ouverts
        if (scan.results.ports && scan.results.ports.length > 0) {
          console.log('🔓 Open Ports:');
          scan.results.ports.forEach(port => {
            console.log(`  - Port ${port.port} (${port.service})`);
          });
          console.log('');
        }

        // Technologies
        if (scan.results.technologies && scan.results.technologies.length > 0) {
          console.log('💻 Technologies:');
          scan.results.technologies.forEach(tech => {
            const version = tech.version ? ` ${tech.version}` : '';
            console.log(`  - ${tech.name}${version} [${tech.category}]`);
          });
          console.log('');
        }

        // Vulnérabilités
        if (scan.results.vulnerabilities && scan.results.vulnerabilities.length > 0) {
          console.log('⚠️  Vulnerabilities:');
          scan.results.vulnerabilities.forEach((vuln, index) => {
            console.log(`  ${index + 1}. ${vuln.title} [${vuln.severity.toUpperCase()}]`);
            console.log(`     ${vuln.description}`);
            if (vuln.location) {
              console.log(`     Location: ${vuln.location}`);
            }
            console.log('');
          });
        } else {
          console.log('✅ No vulnerabilities found!');
        }

        if (scan.status === 'failed') {
          console.error('❌ Scan failed:', scan.error);
        }
      }
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.response) {
      console.error('Response:', error.response.data);
    }
  }
}

testScan();
