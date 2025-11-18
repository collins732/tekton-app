import { NextRequest, NextResponse } from 'next/server';
import { getScanStatus } from '@/app/lib/scanner';

/**
 * GET /api/scan/[id]
 * Récupère le statut et les résultats d'un scan
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const scanId = id;

    const scan = getScanStatus(scanId);

    if (!scan) {
      return NextResponse.json(
        { error: 'Scan not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(scan);

  } catch (error) {
    console.error('Error fetching scan:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
