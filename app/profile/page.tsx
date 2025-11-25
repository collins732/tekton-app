'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function ProfilePage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [userData, setUserData] = useState<any>(null);

  // Check authentication and load user data
  useEffect(() => {
    const loadUserData = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const sessionData = await response.json();

        if (!sessionData.authenticated || !sessionData.user) {
          router.push('/login');
          return;
        }

        // Load full user data
        const userResponse = await fetch('/api/user');
        if (userResponse.ok) {
          const data = await userResponse.json();
          setUserData(data);
        }
      } catch (error) {
        console.error('Failed to load user data:', error);
        router.push('/login');
      } finally {
        setLoading(false);
      }
    };

    loadUserData();
  }, [router]);

  if (loading || !userData) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
          <div className="text-lg glow-purple">LOADING...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        {/* Profile Header */}
        <div className="terminal-border-strong bg-gradient-to-r from-purple-900/30 to-black/50 backdrop-blur p-8 mb-8">
          <div className="flex flex-col lg:flex-row gap-8 items-start lg:items-center">
            {/* Avatar & Info */}
            <div className="flex items-center gap-6">
              <div className="text-8xl">[U]</div>
              <div>
                <h1 className="text-4xl font-bold glow-title mb-2">{userData.username}</h1>
                <div className="flex items-center gap-4 mb-2">
                  <span className="text-sm opacity-50">{userData.country || 'Unknown'}</span>
                  <span className="text-sm opacity-50">•</span>
                  <span className="text-sm opacity-50">Joined {userData.created_at ? new Date(userData.created_at).toLocaleDateString('en-US', { month: 'short', year: 'numeric' }) : 'Recently'}</span>
                  <span className="text-sm opacity-50">•</span>
                  <span className="text-sm bg-purple-600 px-2 py-1 font-bold">{userData.plan || 'FREE'}</span>
                </div>
                <p className="text-sm opacity-70 max-w-md">{userData.bio || 'No bio yet'}</p>
              </div>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mt-8">
            <div className="terminal-border bg-black/50 p-4 text-center">
              <div className="text-3xl font-bold text-orange-400">{userData.stats?.total_scans || 0}</div>
              <div className="text-xs opacity-50">TOTAL SCANS</div>
            </div>
            <div className="terminal-border bg-black/50 p-4 text-center">
              <div className="text-3xl font-bold text-red-400">{userData.stats?.vulns_found || 0}</div>
              <div className="text-xs opacity-50">VULNS FOUND</div>
            </div>
            <div className="terminal-border bg-black/50 p-4 text-center">
              <div className="text-3xl font-bold text-green-400">{userData.stats?.avg_scan_time || '0s'}</div>
              <div className="text-xs opacity-50">AVG SCAN TIME</div>
            </div>
          </div>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Detailed Stats */}
          <div className="terminal-border bg-black/80 backdrop-blur p-6">
            <h2 className="text-2xl font-bold mb-6 glow-header">SCANNING STATISTICS</h2>
            <div className="space-y-4">
              <div className="flex justify-between items-center pb-3 border-b border-purple-900">
                <span className="opacity-70">Scans this month</span>
                <span className="font-bold text-purple-400">{userData.stats?.scans_this_month || 0}</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-purple-900">
                <span className="opacity-70">Current streak</span>
                <span className="font-bold text-orange-400">{userData.stats?.streak || 0} days</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-purple-900">
                <span className="opacity-70">Avg scan time</span>
                <span className="font-bold">{userData.stats?.avg_scan_time || '0s'}</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-purple-900">
                <span className="opacity-70">Favorite target</span>
                <span className="font-bold text-green-400">{userData.stats?.favorite_target || 'None yet'}</span>
              </div>
            </div>
          </div>

          {/* Vulnerability Breakdown */}
          <div className="terminal-border bg-black/80 backdrop-blur p-6">
            <h2 className="text-2xl font-bold mb-6 glow-header">VULNERABILITY BREAKDOWN</h2>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-red-400">CRITICAL</span>
                  <span>{userData.stats?.critical_vulns || 0}</span>
                </div>
                <div className="h-2 bg-gray-800 overflow-hidden">
                  <div className="h-full bg-red-600" style={{ width: `${Math.min((userData.stats?.critical_vulns || 0) * 5, 100)}%` }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-orange-400">HIGH</span>
                  <span>{userData.stats?.high_vulns || 0}</span>
                </div>
                <div className="h-2 bg-gray-800 overflow-hidden">
                  <div className="h-full bg-orange-600" style={{ width: `${Math.min((userData.stats?.high_vulns || 0) * 3, 100)}%` }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-yellow-400">MEDIUM</span>
                  <span>{userData.stats?.medium_vulns || 0}</span>
                </div>
                <div className="h-2 bg-gray-800 overflow-hidden">
                  <div className="h-full bg-yellow-600" style={{ width: `${Math.min((userData.stats?.medium_vulns || 0) * 2, 100)}%` }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-blue-400">LOW</span>
                  <span className="font-bold">{userData.stats?.low_vulns || 0}</span>
                </div>
                <div className="h-2 bg-gray-800 overflow-hidden">
                  <div className="h-full bg-blue-600" style={{ width: `${Math.min((userData.stats?.low_vulns || 0) * 1.5, 100)}%` }}></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Activity Section */}
        <div className="mt-8 terminal-border bg-black/80 backdrop-blur p-6">
          <h2 className="text-2xl font-bold mb-6 glow-header">RECENT ACTIVITY</h2>
          <div className="space-y-4">
            {userData.recentActivity && userData.recentActivity.length > 0 ? (
              userData.recentActivity.map((activity: any, index: number) => (
                <div key={index} className="flex items-center gap-4 p-4 bg-purple-900/10 border-l-4 border-purple-600">
                  <span className="text-2xl font-bold text-purple-400">[+]</span>
                  <div className="flex-1">
                    <div className="font-bold">{activity.title}</div>
                    <div className="text-xs opacity-50">{activity.time}</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 opacity-50">
                <div className="text-4xl mb-2">[...]</div>
                <p>No recent activity yet</p>
                <p className="text-xs mt-2">Start scanning to build your activity history</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
