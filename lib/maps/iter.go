package maps

// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

type Seq2[K comparable, V any] func(yield func(K, V) bool)
type Seq[K any] func(yield func(K) bool)

func All[Map ~map[K]V, K comparable, V any](m Map) Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// All returns an iterator over key-value pairs from m.
// The iteration order is not specified and is not guaranteed
// to be the same from one call to the next.

func Insert[Map ~map[K]V, K comparable, V any](m Map, seq Seq2[K, V]) {
	seq(func(k K, v V) bool {
		m[k] = v
		return true
	})
}

// Insert adds the key-value pairs from seq to m.
// If a key in seq already exists in m, its value will be overwritten.

func Collect[K comparable, V any](seq Seq2[K, V]) map[K]V {
	m := make(map[K]V)
	Insert(m, seq)
	return m
}

// Collect collects key-value pairs from seq into a new map
// and returns it.

func Keys[Map ~map[K]V, K comparable, V any](m Map) Seq[K] {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// Keys returns an iterator over keys in m.
// The iteration order is not specified and is not guaranteed
// to be the same from one call to the next.

func Values[Map ~map[K]V, K comparable, V any](m Map) Seq[V] {
	return func(yield func(V) bool) {
		for _, v := range m {
			if !yield(v) {
				return
			}
		}
	}
}

// Values returns an iterator over values in m.
// The iteration order is not specified and is not guaranteed
// to be the same from one call to the next.
