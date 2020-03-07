package common

import ()

type SandboxDomain struct {
	Id   string
	Sys  SyscallMask
	Pkgs []*Package
}

type Package struct {
	Name  string
	Id    int
	Sects []Section
}

type Section struct {
	Addr uint64
	Size uint64
	Prot uint8
}
