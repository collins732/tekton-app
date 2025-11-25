'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import Image from "next/image";
import { useState, useEffect } from 'react';

export default function Navigation() {
  const pathname = usePathname();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [showTokenTooltip, setShowTokenTooltip] = useState(false);
  const [showLogoutMenu, setShowLogoutMenu] = useState(false);

  // Check authentication status
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const data = await response.json();

        if (data.authenticated && data.user) {
          setIsAuthenticated(true);
          setUser(data.user);
        } else {
          setIsAuthenticated(false);
          setUser(null);
        }
      } catch (error) {
        console.error('Failed to check auth:', error);
        setIsAuthenticated(false);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, [pathname]);

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      window.location.href = '/login';
    } catch (err) {
      console.error('Failed to logout:', err);
    }
  };

  const isActive = (path: string) => {
    return pathname === path ? 'text-purple-400 glow-purple' : 'text-gray-400 hover:text-purple-300';
  };

  return (
    <nav className="sticky top-0 z-50 terminal-border bg-black/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-8 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <Link href="/" className="flex items-center">
            <Image
              src='/logo.png'
              alt='TEKTON Logo'
              width={80}
              height={80}
              className='object-contain'
            />
          </Link>

          {/* Navigation Links - Show skeleton during loading */}
          {loading ? (
            <div className="hidden md:flex items-center gap-6">
              <div className="w-16 h-6 bg-gray-800 animate-pulse"></div>
              <div className="w-24 h-6 bg-gray-800 animate-pulse"></div>
              <div className="w-16 h-6 bg-gray-800 animate-pulse"></div>
            </div>
          ) : isAuthenticated ? (
            <div className="hidden md:flex items-center gap-6">
              <Link href="/scan" className={`font-bold transition-colors ${isActive('/scan')}`}>
                SCAN
              </Link>
              <Link href="/dashboard" className={`font-bold transition-colors ${isActive('/dashboard')}`}>
                DASHBOARD
              </Link>
              <Link href="/pricing" className={`font-bold transition-colors ${isActive('/pricing')}`}>
                PRICING
              </Link>

              {/* Dropdown Menu for More Options */}
              <div className="relative group">
                <button className="font-bold text-gray-400 hover:text-purple-300 transition-colors">
                  MORE ▾
                </button>
                <div className="absolute top-full right-0 mt-2 w-48 terminal-border bg-black/95 backdrop-blur-md opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div className="flex flex-col p-2">
                    <Link href="/profile" className="px-4 py-2 hover:bg-purple-900/20 transition-all text-sm">
                      [U] Profile
                    </Link>
                    <Link href="/settings" className="px-4 py-2 hover:bg-purple-900/20 transition-all text-sm">
                      [*] Settings
                    </Link>
                    <Link href="/api-keys" className="px-4 py-2 hover:bg-purple-900/20 transition-all text-sm">
                      [K] API Keys
                    </Link>
                    <Link href="/integrations" className="px-4 py-2 hover:bg-purple-900/20 transition-all text-sm">
                      [+] Integrations
                    </Link>
                    <div className="border-t border-purple-600 my-1"></div>
                    <button
                      onClick={handleLogout}
                      className="px-4 py-2 hover:bg-red-900/20 text-red-400 hover:text-red-300 transition-all text-sm text-left w-full"
                    >
                      [X] Logout
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* Show login/register for non-authenticated users */
            <div className="hidden md:flex items-center gap-4">
              <Link
                href="/login"
                className="px-4 py-2 font-bold text-gray-400 hover:text-purple-300 transition-colors"
              >
                [LOGIN]
              </Link>
              <Link
                href="/register"
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
              >
                [SIGN UP]
              </Link>
            </div>
          )}

          {/* Token Display - Only show if authenticated */}
          {isAuthenticated && user && (
            <div className="flex items-center gap-7">
              <div
                className="relative"
                onMouseEnter={() => setShowTokenTooltip(true)}
                onMouseLeave={() => setShowTokenTooltip(false)}
              >
                <div className="terminal-border bg-black/50 px-4 py-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs opacity-50">TOKENS:</span>
                    <span className={`text-lg font-bold ${
                      user.tokens > 200 ? 'glow-green' :
                      user.tokens > 50 ? 'text-yellow-400' :
                      'text-red-400'
                    }`}>
                      {user.tokens}
                    </span>
                    <span className="text-purple-400">[⚡]</span>
                  </div>
                </div>

                {/* Tooltip */}
                {showTokenTooltip && (
                  <div className="absolute top-full mt-2 right-0 w-64 terminal-border bg-black p-4 z-50">
                    <div className="text-xs space-y-2">
                      <div className="text-purple-400 font-bold mb-2">SCAN COSTS:</div>
                      <div>• Port Scan: 10 tokens</div>
                      <div>• Tech Detection: 15 tokens</div>
                      <div>• XSS Scanner: 30 tokens</div>
                      <div>• SQLi Scanner: 45 tokens</div>
                      <div className="border-t border-purple-600 mt-2 pt-2">
                        <div className="text-purple-400">Your plan: {user.plan || 'FREE'}</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              <Link
                href="/tokens"
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
              >
                [BUY MORE]
              </Link>
            </div>
          )}
        </div>

        {/* Hamburger Button - Mobile Only - Show only if there are links to show */}
        {!loading && (
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden absolute top-4 right-4 z-50 p-2 terminal-border bg-black"
          >
            <div className="flex flex-col gap-1">
              <span className="block w-6 h-0.5 bg-purple-400"></span>
              <span className="block w-6 h-0.5 bg-purple-400"></span>
              <span className="block w-6 h-0.5 bg-purple-400"></span>
            </div>
          </button>
        )}

        {/* Mobile Menu - Slide Down */}
        {mobileMenuOpen && (
          <div className="md:hidden absolute top-full left-0 w-full bg-black/95 backdrop-blur-md terminal-border animate-slideDown max-h-[80vh] overflow-y-auto">
            <div className="flex flex-col gap-3 p-4">
              {isAuthenticated ? (
                <>
                  <Link href="/scan" onClick={() => setMobileMenuOpen(false)} className={`text-sm font-bold ${isActive('/scan')}`}>
                    [SCAN]
                  </Link>
                  <Link href="/dashboard" onClick={() => setMobileMenuOpen(false)} className={`text-sm font-bold ${isActive('/dashboard')}`}>
                    [DASHBOARD]
                  </Link>
                  <Link href="/pricing" onClick={() => setMobileMenuOpen(false)} className={`text-sm font-bold ${isActive('/pricing')}`}>
                    [PRICING]
                  </Link>

                  <div className="border-t border-purple-600 my-2"></div>

                  <Link href="/profile" onClick={() => setMobileMenuOpen(false)} className={`text-sm ${isActive('/profile')}`}>
                    👤 Profile
                  </Link>
                  <Link href="/settings" onClick={() => setMobileMenuOpen(false)} className={`text-sm ${isActive('/settings')}`}>
                    ⚙️ Settings
                  </Link>
                  <Link href="/api-keys" onClick={() => setMobileMenuOpen(false)} className={`text-sm ${isActive('/api-keys')}`}>
                    🔑 API Keys
                  </Link>
                  <Link href="/integrations" onClick={() => setMobileMenuOpen(false)} className={`text-sm ${isActive('/integrations')}`}>
                    🔗 Integrations
                  </Link>

                  <div className="border-t border-purple-600 my-2"></div>

                  <button
                    onClick={handleLogout}
                    className="text-sm text-red-400 hover:text-red-300 transition-colors text-left w-full"
                  >
                    🚪 Logout
                  </button>
                </>
              ) : (
                <>
                  <Link href="/login" onClick={() => setMobileMenuOpen(false)} className="text-sm font-bold text-gray-400">
                    [LOGIN]
                  </Link>
                  <Link href="/register" onClick={() => setMobileMenuOpen(false)} className="text-sm font-bold text-purple-400">
                    [SIGN UP]
                  </Link>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </nav>
  );
}
