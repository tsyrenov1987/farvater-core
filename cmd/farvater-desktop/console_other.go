//go:build !windows

package main

func holdConsole() func() { return func() {} }

func startByDoubleClick() []string { return nil }
