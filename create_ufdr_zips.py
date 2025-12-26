#!/usr/bin/env python3
"""
Script to create ZIP files for all UFDR case directories and replace existing ZIP files.
"""

import zipfile
import os
from pathlib import Path
from datetime import datetime

# Base directory
BASE_DIR = Path(__file__).parent / "data" / "UFDR's(new)"

def create_zip_from_directory(source_dir, zip_path):
    """Create a ZIP file from a directory, preserving structure."""
    try:
        # Remove existing ZIP if it exists
        if zip_path.exists():
            zip_path.unlink()
            print(f"  Removed existing {zip_path.name}")
        
        # Create new ZIP file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through all files in the directory
            for root, dirs, files in os.walk(source_dir):
                # Skip __pycache__ and .pyc files
                dirs[:] = [d for d in dirs if d != '__pycache__']
                files = [f for f in files if not f.endswith('.pyc')]
                
                for file in files:
                    file_path = Path(root) / file
                    # Get relative path from source directory (so files are at root of ZIP)
                    arcname = file_path.relative_to(source_dir)
                    zipf.write(file_path, arcname)
        
        # Get file size
        size_mb = zip_path.stat().st_size / (1024 * 1024)
        print(f"  [OK] Created {zip_path.name} ({size_mb:.2f} MB)")
        return True
    except Exception as e:
        print(f"  [ERROR] Failed to create {zip_path.name}: {e}")
        return False

def main():
    """Main function to create ZIP files for all cases."""
    print("Creating ZIP files for UFDR cases...\n")
    
    if not BASE_DIR.exists():
        print(f"Error: Base directory {BASE_DIR} does not exist!")
        return
    
    # Find all case directories (exclude ZIP files and __pycache__)
    case_dirs = [d for d in BASE_DIR.iterdir() 
                 if d.is_dir() and not d.name.startswith('.')]
    
    total_created = 0
    total_failed = 0
    
    for case_dir in sorted(case_dirs):
        case_name = case_dir.name
        zip_name = f"{case_name}.zip"
        zip_path = BASE_DIR / zip_name
        
        print(f"Processing: {case_name}")
        
        if create_zip_from_directory(case_dir, zip_path):
            total_created += 1
        else:
            total_failed += 1
        print()
    
    print(f"[OK] ZIP creation complete!")
    print(f"  Created: {total_created} ZIP files")
    if total_failed > 0:
        print(f"  Failed: {total_failed} ZIP files")

if __name__ == "__main__":
    main()

