import { NextRequest, NextResponse } from 'next/server';
import { getAllScans } from '@/app/lib/db';

const DEFAULT_USER_ID = 'default_user';

/**
 * GET /api/search
 * Search scans by URL, status, or date
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get('q')?.toLowerCase() || '';
    const status = searchParams.get('status');
    const dateFrom = searchParams.get('from');
    const dateTo = searchParams.get('to');

    let scans = getAllScans(DEFAULT_USER_ID);

    // Filter by search query (URL or scan ID)
    if (query) {
      scans = scans.filter(scan =>
        scan.target.toLowerCase().includes(query) ||
        scan.scanId.toLowerCase().includes(query)
      );
    }

    // Filter by status
    if (status) {
      scans = scans.filter(scan => scan.status === status);
    }

    // Filter by date range
    if (dateFrom) {
      const fromDate = new Date(dateFrom).getTime();
      scans = scans.filter(scan => scan.startedAt.getTime() >= fromDate);
    }

    if (dateTo) {
      const toDate = new Date(dateTo).getTime();
      scans = scans.filter(scan => scan.startedAt.getTime() <= toDate);
    }

    return NextResponse.json({
      results: scans,
      count: scans.length,
      query: {
        q: query || null,
        status: status || null,
        from: dateFrom || null,
        to: dateTo || null
      }
    });

  } catch (error) {
    console.error('Error searching scans:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
