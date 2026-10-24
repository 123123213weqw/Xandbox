//go:build !linux

package serviceready

func Run(string) error { return &failure{stage: "platform"} }
