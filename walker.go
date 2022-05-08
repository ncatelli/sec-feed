package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ErrEmptyFilterFile struct {
	file string
}

func (e *ErrEmptyFilterFile) Error() string {
	return fmt.Sprintf("file %s is empty", e.file)
}

func firstNonEmptyLine(path string) (string, error) {
	firstLine := ""

	readFile, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer readFile.Close()

	scanner := bufio.NewScanner(readFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lineText := scanner.Text()
		if strings.TrimSpace(lineText) == "" {
			continue
		} else {
			firstLine = lineText
			break
		}
	}

	if firstLine == "" {
		return "", &ErrEmptyFilterFile{
			file: path,
		}
	}

	return firstLine, nil

}

func WalkAllFilesInFilterDir(dir string) (map[string]string, error) {
	filters := make(map[string]string)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		} else if !d.Type().IsRegular() {
			return nil
		}

		name := d.Name()
		filter, err := firstNonEmptyLine(path)
		if err != nil || len(filter) == 0 {
			return err
		}

		filters[name] = filter
		return nil
	})

	if err != nil {
		return nil, err
	}

	return filters, nil
}
