'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';
import TokenDisplay from '@/components/TokenDisplay';
import ScanHistoryItem from '@/components/ScanHistoryItem';

export default function DashboardPage() {
  const [selectedPeriod, setSelectedPeriod] = useState('30 DAYS');
  const [loading, setLoading] = useState(true);

  // User data state
  const [userData, setUserData] = useState<any>({
    tokens: 50,
    plan: 'FREE',
    stats: {
      total_scans: 0,
      completed_scans: 0,
      tokens_spent: 0
    }
  });

  const [recentScans, setRecentScans] = useState<any[]>([]);

  // Load user data on mount
  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);

      // Load user data
      const userRes = await fetch('/api/user');
      if (userRes.ok) {
        const data = await userRes.json();
        setUserData({
          tokens: data.tokens || 50,
          plan: data.plan || 'FREE',
          stats: data.stats || {
            total_scans: 0,
            completed_scans: 0,
            tokens_spent: 0
          }
        });
      }

      // Load recent scans
      const scansRes = await fetch('/api/scan');
      if (scansRes.ok) {
        const scans = await scansRes.json();
        // Get the 5 most recent scans
        setRecentScans(scans.slice(0, 5));
      }

    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl md:text-5xl font-bold mb-2 glow-purple">[DASHBOARD]</h1>
          <p className="text-sm opacity-50">Monitor your security scanning activity</p>
        </div>


        {/* Account Overview Section */}
        <section className="mb-12">
          <h2 className="text-2xl font-bold mb-6 glow-purple">{'>'} ACCOUNT OVERVIEW</h2>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Current Plan */}
            <div className="terminal-border bg-black/80 backdrop-blur p-6">
              <h3 className="text-sm opacity-50 mb-2">CURRENT PLAN</h3>
              <div className="flex items-center gap-3 mb-4">
                <span className="text-4xl font-bold glow-purple">{userData.plan}</span>
                <span className="text-2xl">[◆]</span>
              </div>
              <Link
                href="/pricing"
                className="block w-full py-2 text-center bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
              >
                [UPGRADE]
              </Link>
            </div>

            {/* Tokens */}
            <div className="lg:col-span-2">
              <TokenDisplay
                current={userData.tokens}
                showProgress={false}
              />
              <div className="mt-4 flex gap-4">
                <Link
                  href="/tokens"
                  className="flex-1 py-2 text-center bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
                >
                  [BUY TOKENS]
                </Link>
                <Link
                  href="/scan"
                  className="flex-1 py-2 text-center bg-black hover:bg-gray-900 border-2 border-purple-400 font-bold transition-all"
                >
                  [START SCAN]
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* Statistics Section */}
        <section className="mb-12">
          <h2 className="text-2xl font-bold mb-6 glow-purple">{'>'} STATISTICS</h2>

          {/* Period Selector */}
          <div className="flex justify-center gap-4 mb-6">
            {['7 DAYS', '30 DAYS', 'ALL TIME'].map((period) => (
              <button
                key={period}
                onClick={() => setSelectedPeriod(period)}
                className={`px-4 py-2 font-bold transition-all ${
                  period === selectedPeriod
                    ? 'bg-purple-600 border-2 border-purple-400 glow-accent'
                    : 'bg-black border-2 border-purple-400 hover:bg-gray-900'
                }`}
              >
                [{period}]
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Total Scans */}
            <div className="terminal-border bg-black/80 backdrop-blur p-6 text-center">
              <div className="text-5xl font-bold glow-green mb-2">{userData.stats.total_scans}</div>
              <div className="text-sm opacity-50">TOTAL SCANS</div>
              <div className="text-xs text-green-400 mt-1">{userData.stats.completed_scans} completed</div>
            </div>

            {/* Tokens */}
            <div className="terminal-border bg-black/80 backdrop-blur p-6 text-center">
              <div className="text-5xl font-bold text-purple-400 mb-2">{userData.tokens}</div>
              <div className="text-sm opacity-50">AVAILABLE TOKENS</div>
              <div className="text-xs text-red-400 mt-1">{userData.stats.tokens_spent || 0} spent</div>
            </div>
          </div>

          {/* Chart Placeholder */}
          <div className="mt-6 terminal-border bg-black/80 backdrop-blur p-8">
            <div className="placeholder-3d-icon bg-purple-900/20 h-64 w-full flex items-center justify-center border border-purple-600">
              <div className="text-center">
                <span className="text-4xl mb-2 block">[CHART]</span>
                <span className="text-sm opacity-50">[Future 3D Analytics Chart]</span>
              </div>
            </div>
          </div>
        </section>

        {/* Scan History Section */}
        <section>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold glow-purple">{'>'} SCAN HISTORY</h2>
            <Link
              href="/scan"
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
            >
              [NEW SCAN]
            </Link>
          </div>

          <div className="space-y-4">
            {recentScans.length > 0 ? (
              recentScans.map((scan, index) => (
                <ScanHistoryItem key={scan.scanId || scan.scan_id || index} {...scan} />
              ))
            ) : (
              <div className="terminal-border bg-black/80 backdrop-blur p-8 text-center">
                <p className="text-sm opacity-50 mb-4">No scans yet. Start your first security scan!</p>
                <Link
                  href="/scan"
                  className="inline-block px-6 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
                >
                  [START YOUR FIRST SCAN]
                </Link>
              </div>
            )}
          </div>

          {/* View All Button */}
          <div className="mt-6 text-center">
            <button
              onClick={() => console.log('TODO: Load more scans')}
              className="px-8 py-3 bg-black hover:bg-gray-900 border-2 border-purple-400 font-bold transition-all"
            >
              [LOAD MORE]
            </button>
          </div>
        </section>

        {/* Activity Summary */}
        <section className="mt-12 terminal-border bg-purple-900/20 backdrop-blur p-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-bold glow-purple mb-2">ACCOUNT SUMMARY</h3>
              <p className="text-sm opacity-70">
                Plan: <span className="text-green-400 font-bold">{userData.plan}</span> • {userData.stats.total_scans} scans completed
              </p>
            </div>
            <div className="flex gap-4">
              <div className="text-center">
                <div className="text-3xl font-bold text-green-400">{userData.tokens}</div>
                <div className="text-xs opacity-50">tokens available</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-red-400">{userData.stats.tokens_spent || 0}</div>
                <div className="text-xs opacity-50">tokens spent</div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
