// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package main

// raceEnabled is whether the tests run with -race, which makes the large
// pipeline tests in scale_test.go too slow for every CI run (#838).
const raceEnabled = false
