#!/usr/bin/env python3
"""Script to sync threat feeds."""

import sys
import os
import asyncio
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.ingestion.feed_aggregator import FeedAggregator
from app.services.risk_aggregator import RiskAggregator


async def sync_cves(days: int = 7):
    """Sync CVEs from NVD."""
    print(f"Syncing CVEs from last {days} days...")
    session = SessionLocal()
    
    try:
        aggregator = FeedAggregator(session)
        results = await aggregator.sync_recent_cves(days=days)
        
        print(f"Total fetched: {results['total_fetched']}")
        print(f"New CVEs: {results['new_cves']}")
        print(f"Updated CVEs: {results['updated_cves']}")
        
        if results['errors']:
            print(f"Errors: {len(results['errors'])}")
            
    finally:
        session.close()


async def sync_exploits():
    """Sync exploit information."""
    print("Syncing exploit data...")
    session = SessionLocal()
    
    try:
        aggregator = FeedAggregator(session)
        results = await aggregator.sync_exploits_for_cves()
        
        print(f"CVEs processed: {results['cves_processed']}")
        print(f"Exploits found: {results['exploits_found']}")
        print(f"New exploits: {results['new_exploits']}")
        
    finally:
        session.close()


def calculate_risks():
    """Calculate risk scores for all CVEs."""
    print("Calculating risk scores...")
    session = SessionLocal()
    
    try:
        aggregator = RiskAggregator(session)
        results = aggregator.calculate_all_risks()
        
        print(f"Processed: {results['total_processed']}")
        print(f"Scores created: {results['scores_created']}")
        
    finally:
        session.close()


async def full_sync(days: int = 30):
    """Perform full synchronization."""
    print(f"Starting full sync for last {days} days...")
    session = SessionLocal()
    
    try:
        aggregator = FeedAggregator(session)
        results = await aggregator.full_sync(days=days)
        
        print("\nCVE Sync Results:")
        print(f"  New: {results['cve_sync'].get('new_cves', 0)}")
        print(f"  Updated: {results['cve_sync'].get('updated_cves', 0)}")
        
        print("\nExploit Sync Results:")
        print(f"  New exploits: {results['exploit_sync'].get('new_exploits', 0)}")
        
    finally:
        session.close()
    
    # Calculate risk scores
    calculate_risks()
    
    print("\nFull sync complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync threat intelligence feeds")
    parser.add_argument("--cves", action="store_true", help="Sync CVEs only")
    parser.add_argument("--exploits", action="store_true", help="Sync exploits only")
    parser.add_argument("--risks", action="store_true", help="Calculate risks only")
    parser.add_argument("--full", action="store_true", help="Full sync (default)")
    parser.add_argument("--days", type=int, default=7, help="Days to look back (default: 7)")
    
    args = parser.parse_args()
    
    if args.cves:
        asyncio.run(sync_cves(args.days))
    elif args.exploits:
        asyncio.run(sync_exploits())
    elif args.risks:
        calculate_risks()
    else:
        asyncio.run(full_sync(args.days))
