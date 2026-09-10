package scanner

import (
	"os"
	"path/filepath"
	"unicode/utf8"
)

// maxFileSize skips files larger than this. Secrets/misconfigs live in source and
// config files, never multi-megabyte blobs, so reading huge files whole would waste
// time and memory for no benefit.
const maxFileSize = 5 * 1024 * 1024

var skippedDirs = map[string]bool{".git": true}

type fileContent struct {
	Path    string
	Content string
}

// walkFiles walks root and returns (path, content) for every readable, UTF-8,
// size-bounded file. Unreadable, binary, or oversized files are silently skipped
// rather than failing the whole scan.
func walkFiles(root string) ([]fileContent, error) {
	var files []fileContent

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Can't stat this entry (e.g. permission denied) — skip it, keep walking.
			return nil
		}
		if info.IsDir() {
			if skippedDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if !utf8.Valid(data) {
			return nil
		}

		files = append(files, fileContent{Path: path, Content: string(data)})
		return nil
	})

	return files, err
}
