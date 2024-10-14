// +build !linux,!darwin

package main

func hasEnoughSpace(path string, fileSize int64) error {
    // No-op for platforms that don't support Statfs
    return nil
}
