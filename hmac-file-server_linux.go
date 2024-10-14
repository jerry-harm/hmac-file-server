// +build linux darwin

package main

import (
    "fmt"
    "syscall"
)

func hasEnoughSpace(path string, fileSize int64) error {
    var stat syscall.Statfs_t

    // Get filesystem stats
    if err := syscall.Statfs(path, &stat); err != nil {
        return fmt.Errorf("failed to get filesystem stats: %v", err)
    }

    freeSpace := stat.Bavail * uint64(stat.Bsize)
    if int64(freeSpace) < fileSize {
        return fmt.Errorf("not enough space to upload file")
    }
    if int64(freeSpace) < minFreeSpaceThreshold {
        return fmt.Errorf("disk space is below minimum free space threshold")
    }

    return nil
}
