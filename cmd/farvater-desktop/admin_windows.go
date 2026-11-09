package main

import "golang.org/x/sys/windows"

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }
