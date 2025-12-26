# Push to GitHub - Quick Guide

This guide will help you push all your code changes to the GitHub repository.

## Prerequisites

1. Make sure you have Git installed
2. Make sure you're authenticated with GitHub (either via SSH or HTTPS)

## Step-by-Step Instructions

### Step 1: Navigate to Project Directory

```bash
cd EVI-SCAN
```

### Step 2: Check Git Status

```bash
git status
```

This will show you all the files that have been modified, added, or deleted.

### Step 3: Add All Changes

```bash
# Add all changes (modified, new, and deleted files)
git add .

# OR add specific files/directories
git add README.md
git add CHANGELOG.md
git add requirements.txt
git add FORENSIC/
git add "Image Model/"
git add database/
```

### Step 4: Commit Changes

```bash
git commit -m "Update: Enhanced features and bug fixes

- Added Image Model with face/object detection and frequency analysis
- Fixed Case Management update functionality
- Enhanced Smart Analysis with contact name resolution
- Updated README.md with new features
- Updated requirements.txt with all dependencies
- Updated CHANGELOG.md with version 3.3.0"
```

### Step 5: Check Remote Repository

```bash
# Check if remote is set
git remote -v
```

If you see the repository URL, you're good. If not, add it:

```bash
git remote add origin https://github.com/debu-devesh/EVI-SCAN.git
```

### Step 6: Push to GitHub

```bash
# Push to main branch
git push origin main

# OR if your default branch is master
git push origin master

# OR if you need to set upstream for the first time
git push -u origin main
```

## If You Encounter Issues

### Issue: "Repository not found" or "Permission denied"

**Solution:**
1. Make sure you're logged into GitHub
2. Check if you have write access to the repository
3. Try using SSH instead of HTTPS:
   ```bash
   git remote set-url origin git@github.com:debu-devesh/EVI-SCAN.git
   ```

### Issue: "Updates were rejected because the remote contains work"

**Solution:**
1. Pull the latest changes first:
   ```bash
   git pull origin main --rebase
   ```
2. Resolve any conflicts if they occur
3. Then push again:
   ```bash
   git push origin main
   ```

### Issue: "Large files" warning

**Solution:**
- The `.gitignore` file should already exclude large files
- If you see warnings about large files, they might be in the repository already
- Check `.gitignore` to ensure it's properly configured

## Quick Push Script (Windows)

Create a file `push.bat` in the EVI-SCAN directory:

```batch
@echo off
echo ========================================
echo EVI-SCAN - Push to GitHub
echo ========================================
echo.

cd /d "%~dp0"

echo Checking git status...
git status

echo.
echo Adding all changes...
git add .

echo.
echo Committing changes...
git commit -m "Update: Enhanced features and bug fixes - v3.3.0"

echo.
echo Pushing to GitHub...
git push origin main

echo.
echo Done!
pause
```

Then just double-click `push.bat` to push!

## Quick Push Script (Mac/Linux)

Create a file `push.sh` in the EVI-SCAN directory:

```bash
#!/bin/bash

echo "========================================"
echo "EVI-SCAN - Push to GitHub"
echo "========================================"
echo ""

cd "$(dirname "$0")"

echo "Checking git status..."
git status

echo ""
echo "Adding all changes..."
git add .

echo ""
echo "Committing changes..."
git commit -m "Update: Enhanced features and bug fixes - v3.3.0"

echo ""
echo "Pushing to GitHub..."
git push origin main

echo ""
echo "Done!"
```

Make it executable:
```bash
chmod +x push.sh
```

Then run:
```bash
./push.sh
```

## What Was Updated

The following files have been updated and are ready to push:

1. **README.md** - Added Image Model features, enhanced descriptions
2. **CHANGELOG.md** - Added version 3.3.0 with all recent changes
3. **requirements.txt** - Complete requirements for all modules
4. **FORENSIC/web_interface.py** - Contact resolution in Smart Analysis
5. **FORENSIC/templates/enhanced_index.html** - Enhanced UI for contact names
6. **database/code/session_db.py** - Fixed case update bug
7. **Image Model/** - Complete image analysis system
8. All other modified files from recent enhancements

## Verification

After pushing, verify on GitHub:
1. Go to https://github.com/debu-devesh/EVI-SCAN
2. Check that all files are updated
3. Verify README.md shows the new features
4. Check CHANGELOG.md has version 3.3.0

---

**Note:** Make sure to review the changes before pushing using `git status` and `git diff` if needed.

