# GitHub Setup Guide

This guide will help you prepare and push EVI-SCAN to GitHub.

## Pre-Push Checklist

### ✅ 1. Environment Setup
- [x] `.env.example` file created (template for environment variables)
- [x] `.gitignore` updated (excludes sensitive files)
- [x] Database files excluded (`.db` files)
- [x] Large data files excluded (ZIP, media files)

### ✅ 2. Documentation
- [x] README.md updated with GitHub instructions
- [x] CONTRIBUTING.md exists
- [x] LICENSE file present (MIT)
- [x] GitHub issue templates created
- [x] Pull request template created

### ✅ 3. Code Cleanup
- [x] No hardcoded paths
- [x] No sensitive data in code
- [x] Secret keys use environment variables
- [x] Database files excluded from git

## Steps to Push to GitHub

### Step 1: Initialize Git Repository (if not already done)

```bash
# Navigate to project root
cd EVI-SCAN

# Initialize git (if not already initialized)
git init

# Check status
git status
```

### Step 2: Add Files to Git

```bash
# Add all files (respects .gitignore)
git add .

# Check what will be committed
git status
```

**Important:** Verify that these files are NOT being tracked:
- `*.db` files (sessions.db, evi_scan.db)
- `.env` file
- `__pycache__/` directories
- Large ZIP/media files

### Step 3: Create Initial Commit

```bash
# Create initial commit
git commit -m "Initial commit: EVI-SCAN Forensic Analysis Tool

- Complete UFDR analysis system
- AI-powered chat assistant
- Case management and session persistence
- PDF export functionality
- Authentication system
- Adaptive response system"

# Or use a shorter message:
git commit -m "Initial commit: EVI-SCAN v3.0.0"
```

### Step 4: Create GitHub Repository

1. Go to GitHub.com
2. Click "New repository"
3. Repository name: `EVI-SCAN`
4. Description: "AI-Powered Digital Forensics Tool for UFDR Analysis"
5. Choose Public or Private
6. **DO NOT** initialize with README, .gitignore, or license (we already have these)
7. Click "Create repository"

### Step 5: Connect Local Repository to GitHub

```bash
# Add remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/EVI-SCAN.git

# Verify remote was added
git remote -v
```

### Step 6: Push to GitHub

```bash
# Push to main branch
git branch -M main
git push -u origin main

# If you get authentication errors, use:
# git push -u origin main --force
# (Only use --force if you're sure, as it overwrites remote history)
```

### Step 7: Verify Upload

1. Go to your GitHub repository
2. Verify all files are present
3. Check that `.db` files are NOT visible
4. Verify `.env` file is NOT visible
5. Check README displays correctly

## Post-Push Setup

### 1. Update README with Your Repository URL

Edit `README.md` and replace:
- `YOUR_USERNAME` with your actual GitHub username
- Update clone URL in installation instructions

### 2. Set Up GitHub Pages (Optional)

If you want to host documentation:
1. Go to repository Settings
2. Navigate to Pages
3. Select source branch (usually `main`)
4. Select `/docs` folder if you have one

### 3. Add Repository Topics

Add topics to help others find your project:
- `forensics`
- `digital-forensics`
- `ufdr`
- `ai`
- `python`
- `flask`
- `forensic-analysis`

### 4. Create Release (Optional)

```bash
# Tag the current version
git tag -a v3.0.0 -m "EVI-SCAN v3.0.0 - Adaptive Response System and Enhanced Documentation"

# Push tags
git push origin v3.0.0
```

Then create a release on GitHub with release notes.

## Troubleshooting

### Issue: "Repository not found"
- Check that you've added the correct remote URL
- Verify your GitHub username is correct
- Ensure you have push access to the repository

### Issue: "Authentication failed"
- Use GitHub Personal Access Token instead of password
- Or set up SSH keys for authentication

### Issue: Large files rejected
- Check `.gitignore` includes large file patterns
- Use Git LFS for large files if needed: `git lfs track "*.zip"`

### Issue: Sensitive data in history
- If you accidentally committed sensitive data, use `git filter-branch` or BFG Repo-Cleaner
- Consider creating a new repository if history is too compromised

## Security Reminders

- ✅ Never commit `.env` files
- ✅ Never commit database files (`.db`)
- ✅ Never commit API keys or secrets
- ✅ Use environment variables for sensitive data
- ✅ Review `.gitignore` before each commit

## Next Steps

After pushing to GitHub:
1. Add collaborators (if needed)
2. Set up branch protection rules
3. Enable GitHub Actions (if using CI/CD)
4. Add project description and topics
5. Create initial issues for known bugs/features

---

**Need Help?** Open an issue on GitHub or check the [CONTRIBUTING.md](CONTRIBUTING.md) guide.

