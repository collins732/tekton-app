import { NextRequest, NextResponse } from 'next/server';
import { getScheduledScans, createScheduledScan, deleteScheduledScan, updateScheduledScanStatus } from '@/app/lib/db';

const DEFAULT_USER_ID = 'default_user';

/**
 * GET /api/scheduled-scans
 * Get all scheduled scans
 */
export async function GET() {
  try {
    const scans = getScheduledScans(DEFAULT_USER_ID);

    return NextResponse.json({
      scheduled_scans: scans
    });

  } catch (error) {
    console.error('Error fetching scheduled scans:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/scheduled-scans
 * Create a new scheduled scan
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name, target, scan_types, frequency } = body;

    if (!name || !target || !scan_types || !frequency) {
      return NextResponse.json(
        { error: 'name, target, scan_types, and frequency are required' },
        { status: 400 }
      );
    }

    if (!['daily', 'weekly', 'monthly'].includes(frequency)) {
      return NextResponse.json(
        { error: 'frequency must be daily, weekly, or monthly' },
        { status: 400 }
      );
    }

    const scheduleId = createScheduledScan(DEFAULT_USER_ID, {
      name,
      target,
      scanTypes: scan_types,
      frequency
    });

    return NextResponse.json({
      success: true,
      schedule_id: scheduleId,
      message: 'Scheduled scan created successfully'
    });

  } catch (error) {
    console.error('Error creating scheduled scan:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/scheduled-scans
 * Delete a scheduled scan
 */
export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json();
    const { schedule_id } = body;

    if (!schedule_id) {
      return NextResponse.json(
        { error: 'schedule_id is required' },
        { status: 400 }
      );
    }

    deleteScheduledScan(schedule_id, DEFAULT_USER_ID);

    return NextResponse.json({
      success: true,
      message: 'Scheduled scan deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting scheduled scan:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/scheduled-scans
 * Update scheduled scan status
 */
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { schedule_id, status } = body;

    if (!schedule_id || !status) {
      return NextResponse.json(
        { error: 'schedule_id and status are required' },
        { status: 400 }
      );
    }

    if (!['active', 'paused', 'cancelled'].includes(status)) {
      return NextResponse.json(
        { error: 'status must be active, paused, or cancelled' },
        { status: 400 }
      );
    }

    updateScheduledScanStatus(schedule_id, status);

    return NextResponse.json({
      success: true,
      message: `Scheduled scan ${status}`
    });

  } catch (error) {
    console.error('Error updating scheduled scan:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
