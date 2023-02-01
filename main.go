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
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type CheckParams struct {
	sumfile  string
	quiet    bool
	imissing bool
}

func main() {
	var algo string
	var chkparams = CheckParams{}
	flag.StringVar(&algo, "d", "SHA256", "MD5, SHA1, SHA224, SHA256, SHA384, SHA512, BLAKE2")
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
	// fmt.Println(args)

	if !contains([]string{"BLAKE2", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}, algo) {
		fmt.Println("invalid hash algorithm")
		os.Exit(0)
	}

	if chkparams.sumfile != "" && algo != "" {
		chkparams.compareSums(algo)
		os.Exit(0)
	}

	if len(args) == 0 {
		os.Exit(0)
	}

	for _, file := range args {
		WalkAllFilesInDir(file, algo)
	}
}

func contains[K comparable](s []K, e K) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (c *CheckParams) compareSums(algo string) {
	file, err := os.Open(c.sumfile)
	if err != nil {
		fmt.Println("error opening sum file")
		return
	}
	defer file.Close()

	failCount := 0
	failRead := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		hashPath := strings.Split(line, "  ")
		path := strings.Join(hashPath[1:], "  ")
		hash := calcsum(path, algo)

		if hashPath[0] == hash {
			if !c.quiet {
				fmt.Printf("%s: OK\n", path)
			}
		} else {
			errMessage := ""
			if hash == "" {
				errMessage = " open or read"
				failRead++
			}
			if hash == "" {
				if !c.imissing {
					fmt.Printf("%s: FAILED%s\n", path, errMessage)
				}
			} else {
				fmt.Printf("%s: FAILED\n", path)
			}
			failCount++
		}
	}
	if failRead > 0 && !c.imissing {
		fmt.Println("gensum: WARNING:", failRead, "listed file could not be read")
	}
	if failCount > 0 {
		fmt.Println("gensum: WARNING:", failCount, "computed checksums did NOT match")
	}
}

func WalkAllFilesInDir(dir string, algo string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// check if it is a regular file (not dir)
		if !d.IsDir() {
			fmt.Printf("%s  %s\n", calcsum(path, algo), path)
		}
		return nil
	})
}

func calcsum(path string, algo string) (encodedHex string) {
	f, err := os.Open(path)
	if err != nil {
		return encodedHex
	}
	defer f.Close()

	var hasher hash.Hash

	switch algo {
	case "MD5":
		hasher = md5.New()
	case "SHA1":
		hasher = sha1.New()
	case "SHA224":
		hasher = sha256.New224()
	case "SHA256":
		hasher = sha256.New()
	case "SHA384":
		hasher = sha512.New384()
	case "SHA512":
		hasher = sha512.New()
	case "BLAKE2":
		hasher, err = blake2b.New512(nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	default:
		hasher = md5.New()
	}

	if _, err := io.Copy(hasher, f); err != nil {
		log.Fatal(err)
	}
	hash := hasher.Sum(nil)
	encodedHex = hex.EncodeToString(hash[:])

	return
}
