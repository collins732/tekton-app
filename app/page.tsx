'use client';

import Link from 'next/link';
import dynamic from 'next/dynamic';

const SplineViewer = dynamic(() => import('@/components/SplineViewer'), {
  ssr: false,
  loading: () => (
      <div className="w-full h-full flex items-center justify-center">
        <div className="text-purple-400 animate-pulse">Loading 3D...</div>
      </div>
  ),
});

export default function LandingPage() {
  return (
      <div className="min-h-screen bg-black">
        {/* Hero Section - Three.js Journey inspired */}
        <section className="min-h-screen flex items-center justify-center px-6 md:px-12 py-20 relative overflow-hidden">
          {/* Gradient Background */}
          <div className="absolute inset-0 bg-gradient-to-br from-purple-900/20 via-black to-black"></div>

          <div className="max-w-[1400px] w-full relative z-10">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
              {/* Left - Content */}
              <div className="space-y-10">
                <div className="space-y-6">
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-purple-500/50 bg-purple-500/10 backdrop-blur-sm">
                    <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
                    <span className="text-sm font-medium text-purple-300">OWASP Top 10 Compliant</span>
                  </div>

                  <h1 className="text-7xl md:text-8xl lg:text-9xl font-black leading-none tracking-tight">
                    <span className="bg-gradient-to-r from-white via-purple-200 to-purple-400 bg-clip-text text-transparent">
                      TEKTON
                    </span>
                  </h1>

                  <p className="text-3xl md:text-4xl font-bold text-white/90 leading-tight">
                    Automated Web Security Testing
                  </p>

                  <p className="text-lg text-white/60 leading-relaxed max-w-xl">
                    Detect vulnerabilities, scan for XSS & SQLi exploits, and secure your web applications
                    with cutting-edge automated scanning in real-time.
                  </p>
                </div>

                {/* CTA */}
                <div className="flex flex-col sm:flex-row gap-4">
                  <Link
                      href="/scan"
                      className="group relative px-8 py-5 bg-gradient-to-r from-purple-600 to-purple-500 rounded-xl font-bold text-lg overflow-hidden transition-all hover:scale-105 hover:shadow-2xl hover:shadow-purple-500/50"
                  >
                    <span className="relative z-10">Start Free Scan</span>
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-purple-400 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  </Link>

                  <Link
                      href="/pricing"
                      className="px-8 py-5 rounded-xl font-bold text-lg border-2 border-white/20 hover:border-purple-400 transition-all hover:bg-white/5"
                  >
                    View Pricing
                  </Link>
                </div>

                {/* Trust Metrics */}
                <div className="flex items-center gap-8 pt-4">
                  <div>
                    <div className="text-3xl font-black text-green-400">10K+</div>
                    <div className="text-sm text-white/50">Scans Performed</div>
                  </div>
                  <div className="w-px h-12 bg-white/10"></div>
                  <div>
                    <div className="text-3xl font-black text-green-400">50K+</div>
                    <div className="text-sm text-white/50">Vulnerabilities Found</div>
                  </div>
                  <div className="w-px h-12 bg-white/10"></div>
                  <div>
                    <div className="text-3xl font-black text-green-400">99.9%</div>
                    <div className="text-sm text-white/50">Uptime</div>
                  </div>
                </div>
              </div>

              {/* Right - 3D */}
              <div className="h-[600px] lg:h-[700px] relative">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 to-transparent rounded-3xl blur-3xl"></div>
                <div className="relative h-full rounded-2xl overflow-hidden">
                  <SplineViewer />
                </div>
              </div>
            </div>
          </div>

          {/* Scroll Indicator */}
          <div className="absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
            <div className="w-6 h-10 rounded-full border-2 border-white/30 flex items-start justify-center p-2">
              <div className="w-1 h-3 bg-white/50 rounded-full"></div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="py-32 px-6 md:px-12 relative">
          <div className="max-w-[1400px] mx-auto">
            {/* Header */}
            <div className="text-center mb-24 space-y-4">
              <h2 className="text-5xl md:text-6xl font-black">
                <span className="bg-gradient-to-r from-white to-purple-400 bg-clip-text text-transparent">
                  Comprehensive Security Coverage
                </span>
              </h2>
              <p className="text-xl text-white/60 max-w-2xl mx-auto">
                Complete OWASP Top 10 protection with automated detection and real-time reporting
              </p>
            </div>

            {/* Main Features */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-24">
              {[
                {
                  icon: '>>',
                  title: 'Injection Detection',
                  description: 'SQL, NoSQL, OS command, and LDAP injection vulnerabilities detected automatically'
                },
                {
                  icon: '#',
                  title: 'Access Control',
                  description: 'Authentication flaws, broken access control, and session management issues'
                },
                {
                  icon: '!',
                  title: 'XSS & Client-Side',
                  description: 'Cross-site scripting, DOM-based attacks, and client-side vulnerabilities'
                }
              ].map((feature, i) => (
                  <div key={i} className="group p-8 rounded-2xl bg-gradient-to-br from-white/5 to-transparent border border-white/10 hover:border-purple-500/50 transition-all hover:scale-105">
                    <div className="text-6xl mb-6 font-black text-purple-400 group-hover:scale-110 transition-transform">
                      {feature.icon}
                    </div>
                    <h3 className="text-2xl font-bold mb-3 text-white">{feature.title}</h3>
                    <p className="text-white/60 leading-relaxed">{feature.description}</p>
                  </div>
              ))}
            </div>

            {/* OWASP Coverage - Version enrichie */}
            <div className="mt-32 text-center">
              <div className="inline-flex items-center gap-3 px-6 py-3 rounded-full bg-purple-500/10 border border-purple-500/30 mb-12">
                <span className="text-green-400 text-2xl">✓</span>
                <span className="font-bold text-lg">Full OWASP Top 10 2021 Coverage</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 max-w-6xl mx-auto">
                {[
                  { code: 'A01', name: 'Broken Access Control', severity: 'critical' },
                  { code: 'A02', name: 'Cryptographic Failures', severity: 'high' },
                  { code: 'A03', name: 'Injection', severity: 'critical' },
                  { code: 'A04', name: 'Insecure Design', severity: 'high' },
                  { code: 'A05', name: 'Security Misconfiguration', severity: 'high' },
                  { code: 'A06', name: 'Vulnerable Components', severity: 'high' },
                  { code: 'A07', name: 'Auth & Session Failures', severity: 'critical' },
                  { code: 'A08', name: 'Software Integrity Failures', severity: 'medium' },
                  { code: 'A09', name: 'Logging & Monitoring Failures', severity: 'medium' },
                  { code: 'A10', name: 'Server-Side Request Forgery', severity: 'high' }
                ].map((item, i) => (
                    <div key={i} className="group p-6 rounded-2xl bg-gradient-to-br from-white/5 to-transparent border border-white/10 hover:border-green-500/50 transition-all hover:scale-105">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-xs font-bold text-purple-400">{item.code}</span>
                        <div className={`w-2 h-2 rounded-full ${
                            item.severity === 'critical' ? 'bg-red-500' :
                                item.severity === 'high' ? 'bg-orange-500' :
                                    'bg-yellow-500'
                        }`}></div>
                      </div>
                      <div className="text-green-400 text-3xl mb-3 group-hover:scale-125 transition-transform">✓</div>
                      <div className="text-sm font-semibold text-white/90 leading-tight">{item.name}</div>
                    </div>
                ))}
              </div>

              <p className="mt-12 text-sm text-white/40">
                + Port scanning • Technology fingerprinting • SSL/TLS analysis • HTTP security headers • Cookie security
              </p>
            </div>
          </div>
        </section>

        {/* Social Proof / Stats Section */}
        <section className="py-32 px-6 md:px-12 relative">
          <div className="max-w-[1400px] mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-5xl md:text-6xl font-black mb-4">
                <span className="bg-gradient-to-r from-white to-purple-400 bg-clip-text text-transparent">
                  Trusted by Security Teams
                </span>
              </h2>
              <p className="text-xl text-white/60">
                Join thousands of developers securing their applications
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="p-10 rounded-3xl bg-gradient-to-br from-purple-500/10 to-transparent border border-purple-500/30 text-center">
                <div className="text-7xl font-black bg-gradient-to-r from-green-400 to-emerald-500 bg-clip-text text-transparent mb-4">
                  10,000+
                </div>
                <div className="text-lg font-semibold text-white/80 mb-2">Security Scans Performed</div>
                <div className="text-sm text-white/50">Across 50+ countries worldwide</div>
              </div>

              <div className="p-10 rounded-3xl bg-gradient-to-br from-purple-500/10 to-transparent border border-purple-500/30 text-center">
                <div className="text-7xl font-black bg-gradient-to-r from-red-400 to-orange-500 bg-clip-text text-transparent mb-4">
                  50,000+
                </div>
                <div className="text-lg font-semibold text-white/80 mb-2">Vulnerabilities Detected</div>
                <div className="text-sm text-white/50">Preventing potential breaches</div>
              </div>

              <div className="p-10 rounded-3xl bg-gradient-to-br from-purple-500/10 to-transparent border border-purple-500/30 text-center">
                <div className="text-7xl font-black bg-gradient-to-r from-blue-400 to-cyan-500 bg-clip-text text-transparent mb-4">
                  99.9%
                </div>
                <div className="text-lg font-semibold text-white/80 mb-2">Platform Uptime</div>
                <div className="text-sm text-white/50">Always available when you need it</div>
              </div>
            </div>
          </div>
        </section>

        {/* How it Works Section */}
        <section className="py-32 px-6 md:px-12 relative bg-gradient-to-b from-transparent via-purple-900/10 to-transparent">
          <div className="max-w-[1400px] mx-auto">
            <div className="text-center mb-20">
              <h2 className="text-5xl md:text-6xl font-black mb-4">
                <span className="bg-gradient-to-r from-white to-purple-400 bg-clip-text text-transparent">
                  How It Works
                </span>
              </h2>
              <p className="text-xl text-white/60">
                Security testing in three simple steps
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
              {[
                {
                  step: '01',
                  title: 'Enter Target URL',
                  description: 'Simply paste your web application URL. Our intelligent system automatically detects the technology stack.',
                  icon: '→'
                },
                {
                  step: '02',
                  title: 'Select Scan Modules',
                  description: 'Choose from comprehensive OWASP Top 10 tests or run a full security audit. Customize based on your needs.',
                  icon: '⚡'
                },
                {
                  step: '03',
                  title: 'Get Instant Results',
                  description: 'Receive real-time vulnerability reports with detailed remediation guides and code examples.',
                  icon: '✓'
                }
              ].map((item, i) => (
                  <div key={i} className="relative group">
                    <div className="p-8 rounded-3xl bg-gradient-to-br from-white/5 to-transparent border border-white/10 hover:border-purple-500/50 transition-all">
                      <div className="text-8xl font-black text-purple-500/20 mb-4">{item.step}</div>
                      <div className="text-5xl mb-6">{item.icon}</div>
                      <h3 className="text-2xl font-bold text-white mb-4">{item.title}</h3>
                      <p className="text-white/60 leading-relaxed">{item.description}</p>
                    </div>
                    {i < 2 && (
                        <div className="hidden md:block absolute top-1/2 -right-6 text-4xl text-purple-500/30">
                          →
                        </div>
                    )}
                  </div>
              ))}
            </div>
          </div>
        </section>

        {/* Integration Section */}
        <section className="py-32 px-6 md:px-12">
          <div className="max-w-[1400px] mx-auto">
            <div className="p-12 md:p-20 rounded-3xl bg-gradient-to-br from-purple-900/40 via-purple-800/20 to-transparent border-2 border-purple-500/30 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/10 to-transparent"></div>

              <div className="relative z-10 max-w-3xl">
                <div className="inline-block px-4 py-2 rounded-full bg-green-500/20 text-green-400 text-sm font-bold mb-6">
                  FOR DEVELOPERS
                </div>

                <h2 className="text-5xl md:text-6xl font-black mb-6 text-white">
                  Integrate with Your CI/CD Pipeline
                </h2>

                <p className="text-xl text-white/70 mb-8 leading-relaxed">
                  Built for modern DevSecOps workflows. Add automated security testing to your deployment pipeline with our REST API.
                </p>

                <div className="flex flex-wrap gap-4 mb-8">
                  {['GitHub Actions', 'GitLab CI', 'Jenkins', 'CircleCI', 'Azure DevOps'].map((tech, i) => (
                      <div key={i} className="px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-sm font-semibold">
                        {tech}
                      </div>
                  ))}
                </div>

                <Link
                    href="/docs"
                    className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-white text-black font-bold hover:scale-105 transition-all"
                >
                  View Documentation
                  <span>→</span>
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-32 px-6 md:px-12 relative bg-gradient-to-b from-transparent via-purple-900/5 to-transparent">
          <div className="max-w-[1400px] mx-auto">
            <div className="text-center mb-20 space-y-4">
              <h2 className="text-5xl md:text-6xl font-black">
                <span className="bg-gradient-to-r from-white to-purple-400 bg-clip-text text-transparent">
                  Why Choose TEKTON?
                </span>
              </h2>
              <p className="text-xl text-white/60">
                Next-generation approach to web security
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* TEKTON */}
              <div className="p-10 rounded-3xl bg-gradient-to-br from-purple-900/40 via-purple-800/20 to-transparent border-2 border-purple-500/50 relative overflow-hidden">
                <div className="absolute top-4 right-4 px-4 py-2 rounded-full bg-green-500 text-black text-xs font-black">
                  NEXT-GEN
                </div>

                <h3 className="text-4xl font-black mb-8 text-white">TEKTON</h3>

                <div className="space-y-4">
                  {[
                    { title: 'Full OWASP Top 10 Coverage', desc: 'Complete protection against all modern web vulnerabilities' },
                    { title: 'Real-Time Results', desc: 'Live scanning progress with instant vulnerability detection' },
                    { title: 'Pay-As-You-Scan Token System', desc: 'No monthly commitments, scan only when you need' },
                    { title: 'Automated Technology Detection', desc: 'Identifies frameworks, servers, and versions automatically' },
                    { title: 'Modern Terminal UI', desc: 'Intuitive interface designed for security professionals' },
                    { title: 'Detailed Remediation Guides', desc: 'Step-by-step fixes with code examples' },
                    { title: 'API-First Architecture', desc: 'CI/CD integration in minutes' },
                    { title: 'Zero False Positives Focus', desc: 'Advanced verification to minimize noise' }
                  ].map((item, i) => (
                      <div key={i} className="flex gap-3">
                        <span className="text-green-400 text-xl mt-1 flex-shrink-0">✓</span>
                        <div>
                          <div className="font-bold text-white">{item.title}</div>
                          <div className="text-sm text-white/60">{item.desc}</div>
                        </div>
                      </div>
                  ))}
                </div>
              </div>

              {/* Traditional */}
              <div className="p-10 rounded-3xl bg-gradient-to-br from-white/5 to-transparent border-2 border-white/10 relative">
                <div className="absolute top-4 right-4 px-4 py-2 rounded-full bg-orange-500/20 text-orange-400 text-xs font-black border border-orange-500/50">
                  ESTABLISHED
                </div>

                <h3 className="text-4xl font-black mb-8 text-white/70">Traditional Scanners</h3>

                <div className="space-y-4">
                  {[
                    { type: 'positive', title: 'Industry Track Record', desc: 'Years of proven reliability in enterprise' },
                    { type: 'positive', title: 'Extensive Documentation', desc: 'Large knowledge base and community' },
                    { type: 'positive', title: 'Compliance Certifications', desc: 'Meet regulatory requirements' },
                    { type: 'negative', title: 'Delayed Reporting', desc: 'Results available hours or days later' },
                    { type: 'negative', title: 'Higher Costs', desc: 'Expensive annual contracts' },
                    { type: 'negative', title: 'Complex Setup', desc: 'Requires extensive configuration' },
                    { type: 'negative', title: 'Legacy Interface', desc: 'Older UI/UX not optimized' },
                    { type: 'negative', title: 'False Positives', desc: 'Time spent on non-critical issues' }
                  ].map((item, i) => (
                      <div key={i} className={`flex gap-3 ${item.type === 'negative' ? 'opacity-60' : ''}`}>
                      <span className={`text-xl mt-1 flex-shrink-0 ${item.type === 'positive' ? 'text-green-400' : 'text-red-400'}`}>
                        {item.type === 'positive' ? '✓' : '✗'}
                      </span>
                        <div>
                          <div className={`font-bold ${item.type === 'positive' ? 'text-white/80' : 'text-white/50'}`}>
                            {item.title}
                          </div>
                          <div className="text-sm text-white/50">{item.desc}</div>
                        </div>
                      </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-32 px-6 md:px-12">
          <div className="max-w-4xl mx-auto text-center space-y-8">
            <h2 className="text-5xl md:text-7xl font-black">
              <span className="bg-gradient-to-r from-white via-purple-200 to-purple-400 bg-clip-text text-transparent">
                Start Securing Your Apps Today
              </span>
            </h2>

            <p className="text-xl text-white/60 max-w-2xl mx-auto">
              No credit card required. Get comprehensive security insights in minutes.
            </p>

            <Link
                href="/scan"
                className="inline-block px-12 py-6 bg-gradient-to-r from-purple-600 to-purple-500 rounded-xl font-bold text-xl hover:scale-105 transition-all hover:shadow-2xl hover:shadow-purple-500/50"
            >
              Launch Scanner
            </Link>

            <div className="pt-12 flex items-center justify-center gap-6 text-sm text-white/40">
              <span>Trusted by security teams</span>
              <span>•</span>
              <span>OWASP compliant</span>
              <span>•</span>
              <span>Enterprise-ready</span>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="py-12 px-6 md:px-12 border-t border-white/10">
          <div className="max-w-[1400px] mx-auto text-center space-y-4">
            <div className="text-sm text-white/40 space-y-2">
              <p>⚠️ For authorized security testing and educational purposes only</p>
              <p>Always obtain explicit permission before scanning any website</p>
            </div>
            <div className="text-xs text-white/30 pt-4">
              Master 2 Cloud Computing Project © 2025 TEKTON
            </div>
          </div>
        </footer>
      </div>
  );
}