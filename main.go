package main

import (
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

func main() {
	var checkSums, algo string
	flag.StringVar(&algo, "d", "MD5", "MD5, SHA1, SHA224, SHA256, SHA384, SHA512, BLAKE2")
	flag.StringVar(&checkSums, "c", "", "read sums from the FILEs and check them")
	flag.Parse()
	args := flag.Args()
	algo = strings.ToUpper(algo)
	// fmt.Println(args)

	if checkSums != "" {
		compareSums()
		os.Exit(0)
	}

	if len(args) == 0 {
		os.Exit(0)
	}

	if !contains([]string{"BLAKE2", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}, algo) {
		fmt.Println("invalid hash algorithm")
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

func compareSums() {
	fmt.Println("compareSums")

	// > b2sum -c check_ver.b2sum
	// go.mod: OK
	// go.sum: OK
	// LICENSE: OK
	// main.go: OK
	// README.md: OK

	// > b2sum -c check_ver.b2sum
	// check.b2sum: OK
	// check_ver.b2sum: FAILED
	// go.mod: OK
	// go.sum: OK
	// LICENSE: OK
	// main.go: OK
	// README.md: OK
	// b2sum: WARNING: 1 computed checksum did NOT match
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
		log.Fatal(err)
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
