import { NextRequest, NextResponse } from 'next/server';
import { getUser, updateUser, getAllScans } from '@/app/lib/db';
import { getUserFromSession } from '@/app/lib/auth';

/**
 * GET /api/user
 * Get current user profile with stats
 */
export async function GET() {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const user = getUser(userId) as any;

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    // Get scans for statistics
    const scans = getAllScans(userId);
    const completedScans = scans.filter((s: any) => s.status === 'completed');

    // Calculate vulnerability statistics
    let totalVulns = 0;
    let criticalVulns = 0;
    let highVulns = 0;
    let mediumVulns = 0;
    let lowVulns = 0;
    let totalScanTime = 0;
    const targetCounts: { [key: string]: number } = {};

    completedScans.forEach((scan: any) => {
      if (scan.results) {
        const results = typeof scan.results === 'string' ? JSON.parse(scan.results) : scan.results;

        // Count vulnerabilities by severity
        if (results.xss_results?.vulnerabilities) {
          results.xss_results.vulnerabilities.forEach((v: any) => {
            totalVulns++;
            if (v.severity === 'CRITICAL') criticalVulns++;
            else if (v.severity === 'HIGH') highVulns++;
            else if (v.severity === 'MEDIUM') mediumVulns++;
            else if (v.severity === 'LOW') lowVulns++;
          });
        }

        if (results.sqli_results?.vulnerabilities) {
          results.sqli_results.vulnerabilities.forEach((v: any) => {
            totalVulns++;
            if (v.severity === 'CRITICAL') criticalVulns++;
            else if (v.severity === 'HIGH') highVulns++;
            else if (v.severity === 'MEDIUM') mediumVulns++;
            else if (v.severity === 'LOW') lowVulns++;
          });
        }
      }

      // Track scan time
      if (scan.completed_at && scan.started_at) {
        totalScanTime += (scan.completed_at - scan.started_at);
      }

      // Count targets
      if (scan.target) {
        targetCounts[scan.target] = (targetCounts[scan.target] || 0) + 1;
      }
    });

    // Calculate average scan time
    const avgScanTimeMs = completedScans.length > 0 ? totalScanTime / completedScans.length : 0;
    const avgScanTime = avgScanTimeMs > 0 ? `${Math.round(avgScanTimeMs / 1000)}s` : '0s';

    // Find favorite target
    let favoriteTarget = 'None yet';
    let maxCount = 0;
    Object.entries(targetCounts).forEach(([target, count]) => {
      if (count > maxCount) {
        maxCount = count;
        favoriteTarget = target;
      }
    });

    // Calculate scans this month
    const now = Date.now();
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const scansThisMonth = scans.filter((s: any) => s.started_at >= monthStart.getTime()).length;

    // Calculate total tokens spent from all scans
    const tokensSpent = scans.reduce((total: number, scan: any) => {
      return total + (scan.cost || 0);
    }, 0);

    return NextResponse.json({
      user_id: user.user_id,
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      bio: user.bio,
      country: user.country,
      github: user.github,
      twitter: user.twitter,
      tokens: user.tokens,
      plan: user.plan,
      streak: user.streak,
      created_at: user.created_at,
      stats: {
        total_scans: scans.length,
        completed_scans: completedScans.length,
        tokens_spent: tokensSpent,
        vulns_found: totalVulns,
        avg_scan_time: avgScanTime,
        scans_this_month: scansThisMonth,
        favorite_target: favoriteTarget,
        critical_vulns: criticalVulns,
        high_vulns: highVulns,
        medium_vulns: mediumVulns,
        low_vulns: lowVulns
      }
    });

  } catch (error) {
    console.error('Error fetching user:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/user
 * Update user profile
 */
export async function PATCH(request: NextRequest) {
  try {
    const userId = await getUserFromSession();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const body = await request.json();

    const allowedFields = ['username', 'bio', 'country', 'github', 'twitter', 'avatar'];
    const updates: any = {};

    allowedFields.forEach(field => {
      if (body[field] !== undefined) {
        updates[field] = body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      return NextResponse.json(
        { error: 'No valid fields to update' },
        { status: 400 }
      );
    }

    updateUser(userId, updates);

    const updatedUser = getUser(userId);

    return NextResponse.json({
      success: true,
      user: updatedUser
    });

  } catch (error) {
    console.error('Error updating user:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
