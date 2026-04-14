package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

var supportedAlgorithms = []string{
	"BLAKE2", "BLAKE3", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
}

type checkParams struct {
	sumfile  string
	quiet    bool
	imissing bool
}

func main() {
	var algo string
	chkparams := checkParams{}
	flag.StringVar(&algo, "d", "SHA256", "MD5, SHA1, SHA224, SHA256, SHA384, SHA512, BLAKE2, BLAKE3")
	flag.StringVar(&chkparams.sumfile, "c", "", "read sums from the FILEs and check them")
	flag.BoolVar(
		&chkparams.quiet,
		"quiet",
		false,
		"don't print OK for each successfully verified file",
	)
	flag.BoolVar(
		&chkparams.imissing,
		"ignore-missing",
		false,
		"don't fail or report status for missing files",
	)
	flag.Parse()
	args := flag.Args()
	algo = strings.ToUpper(algo)

	if !slices.Contains(supportedAlgorithms, algo) {
		fmt.Fprintln(os.Stderr, "invalid hash algorithm")
		os.Exit(1)
	}

	if chkparams.sumfile != "" {
		chkparams.compareSums(algo)
		return
	}

	if len(args) == 0 {
		return
	}

	for _, file := range args {
		if err := walkAllFilesInDir(file, algo); err != nil {
			fmt.Fprintf(os.Stderr, "gensum: %s: %v\n", file, err)
		}
	}
}

func (c *checkParams) compareSums(algo string) {
	file, err := os.Open(c.sumfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gensum: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	failCount := 0
	failRead := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		hashPath := strings.SplitN(line, "  ", 2)
		if len(hashPath) != 2 {
			fmt.Fprintf(os.Stderr, "gensum: %s: improperly formatted checksum line\n", c.sumfile)
			continue
		}

		expectedHash := hashPath[0]
		path := hashPath[1]
		actualHash, err := calcsum(path, algo)

		if err != nil {
			failRead++
			failCount++
			if !c.imissing {
				fmt.Fprintf(os.Stderr, "gensum: %s: %v\n", path, err)
				fmt.Printf("%s: FAILED open or read\n", path)
			}
			continue
		}

		if expectedHash == actualHash {
			if !c.quiet {
				fmt.Printf("%s: OK\n", path)
			}
		} else {
			fmt.Printf("%s: FAILED\n", path)
			failCount++
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "gensum: error reading %s: %v\n", c.sumfile, err)
	}

	if failRead > 0 && !c.imissing {
		fmt.Fprintf(os.Stderr, "gensum: WARNING: %d listed file could not be read\n", failRead)
	}
	if failCount > 0 {
		fmt.Fprintf(os.Stderr, "gensum: WARNING: %d computed checksums did NOT match\n", failCount)
	}
}

func walkAllFilesInDir(dir string, algo string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		h, err := calcsum(path, algo)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("%s  %s\n", h, path)
		return nil
	})
}

func calcsum(path string, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher, err := newHasher(algo)
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func newHasher(algo string) (hash.Hash, error) {
	switch algo {
	case "MD5":
		return md5.New(), nil
	case "SHA1":
		return sha1.New(), nil
	case "SHA224":
		return sha256.New224(), nil
	case "SHA256":
		return sha256.New(), nil
	case "SHA384":
		return sha512.New384(), nil
	case "SHA512":
		return sha512.New(), nil
	case "BLAKE2":
		return blake2b.New512(nil)
	case "BLAKE3":
		return blake3.New(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
