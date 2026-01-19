# repo_manager.py
import os
import shutil
import subprocess
import hashlib

def clone_repo(repo_url, target_dir):
    """
    Clones a repository to the target directory.
    Uses shallow clone (--depth 1) for speed.
    """
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

def delete_repo(target_dir):
    """
    Deletes the cloned repository directory.
    """
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)

def walk_repo_files(target_dir):
    """
    Generator that yields file information for ALL files in the directory.
    Skips .git directory.
    
    Yields:
        (file_path, is_binary, content_or_hash)
        - If text: is_binary=False, content=string
        - If binary: is_binary=True, content=sha256_hash_string
    """
    for root, dirs, files in os.walk(target_dir):
        if ".git" in dirs:
            dirs.remove(".git")  # Don't visit .git directories
            
        for file in files:
            file_path = os.path.join(root, file)
            
            # Try to read as text first
            try:
                with open(file_path, "r", encoding="utf-8", errors="strict") as f:
                    content = f.read()
                    # Basic null byte check to avoid binary files misidentified as text
                    if "\0" in content:
                        raise UnicodeDecodeError("null bytes", b"", 0, 1, "")
                    
                    yield file_path, False, content
                    
            except (UnicodeDecodeError, OSError):
                # Fallback to binary handling: Calculate Hash
                
                # Only check exe files for binaries
                if not file_path.lower().endswith(".exe"):
                    continue

                try:
                    sha256_hash = hashlib.sha256()
                    with open(file_path, "rb") as f:
                        # Read in chunks to avoid memory issues with large files
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    
                    yield file_path, True, sha256_hash.hexdigest()
                    
                except OSError:
                    continue
