package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/tsyrenov1987/farvater-core/switchboard"
)

// holdConsole turns off the console's selection mode (QuickEdit) while the
// program runs: a stray click in the window would freeze every write to it,
// the tunnel's logging included. The returned func puts the mode back.
func holdConsole() func() {
	h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return func() {}
	}
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	if windows.SetConsoleMode(h, mode&^windows.ENABLE_QUICK_EDIT_MODE|windows.ENABLE_EXTENDED_FLAGS) != nil {
		return func() {}
	}
	// ENABLE_EXTENDED_FLAGS: without it the console ignores the QuickEdit bit.
	return func() { _ = windows.SetConsoleMode(h, mode|windows.ENABLE_EXTENDED_FLAGS) }
}

func waitEnter() {
	fmt.Print("\nНажмите Enter, чтобы закрыть окно.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func stop(msg string) {
	fmt.Println(msg)
	waitEnter()
	os.Exit(1)
}

// elevate starts this program again as Administrator, in a window of its own.
func elevate(exe string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, dir, windows.SW_NORMAL)
}

// savedCodeFile keeps the code in the user's profile, closed to other users.
func savedCodeFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "Farvater", "code.txt")
}

// startByDoubleClick handles a run with no arguments: it gets Administrator
// (the UAC question), asks for the access code and returns connect's
// arguments. It leaves the selection mode on while asking: right-click paste
// needs it.
func startByDoubleClick() []string {
	pauseOnError = waitEnter
	connectedNote = "Подключено. Окно не закрывайте: когда оно закроется, Farvater отключится."
	exe, err := os.Executable()
	if err != nil {
		stop("Не удалось найти файл программы: " + err.Error())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll")); err != nil {
		stop("Рядом с программой нет файла wintun.dll. Распакуйте архив целиком в обычную папку и запустите программу оттуда.")
	}
	if !isAdmin() {
		if err := elevate(exe); err != nil {
			stop("Без прав администратора программа не подключит компьютер. Запустите её снова и нажмите «Да».")
		}
		os.Exit(0)
	}
	file := savedCodeFile()
	saved := ""
	if b, err := os.ReadFile(file); err == nil {
		saved = strings.TrimSpace(string(b))
	}
	fmt.Printf("Farvater %s\nКод доступа лежит в кабинете: myorden.ru/cabinet\n", switchboard.Version)
	if saved != "" {
		fmt.Println("Enter подключит с прошлым кодом. Другой код можно вставить правым щелчком.")
	}
	in := bufio.NewReader(os.Stdin)
	for {
		if saved != "" {
			fmt.Printf("Код [%s]: ", saved)
		} else {
			fmt.Print("Код: ")
		}
		line, rerr := in.ReadString('\n')
		code := strings.TrimSpace(line)
		if code == "" {
			code = saved
		}
		if code != "" {
			if _, err := catalogueURLs(code); err == nil {
				if file != "" {
					_ = os.MkdirAll(filepath.Dir(file), 0o700)
					_ = os.WriteFile(file, []byte(code), 0o600)
				}
				return []string{code}
			}
			fmt.Println("Код выглядит так: ORDEN-XXXXX-XXXXX.")
		}
		if rerr != nil {
			stop("Код не введён.")
		}
	}
}
