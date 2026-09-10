use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Files larger than this are skipped — secrets/misconfigs live in source and config files,
/// never in multi-megabyte blobs, and reading huge files whole would waste time and memory.
const MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024;

const SKIPPED_DIRS: &[&str] = &[".git"];

/// Walks `root` and yields (path, content) for every readable, UTF-8, size-bounded file.
/// Unreadable, binary, or oversized files are silently skipped rather than failing the scan.
pub fn walk_files(root: &Path) -> impl Iterator<Item = (PathBuf, String)> + '_ {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            if entry.file_type().is_dir() {
                let name = entry.file_name().to_string_lossy();
                return !SKIPPED_DIRS.contains(&name.as_ref());
            }
            true
        })
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let path = entry.path().to_path_buf();
            let metadata = fs::metadata(&path).ok()?;
            if metadata.len() > MAX_FILE_SIZE_BYTES {
                return None;
            }
            let content = fs::read_to_string(&path).ok()?;
            Some((path, content))
        })
}
