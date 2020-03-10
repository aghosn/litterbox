package litterbox

import ()

type Domain struct {
	config *SandboxDomain
	SView  map[*Package]uint8
	SPkgs  []*Package
}

type SandboxDomain struct {
	Id   string
	Func string
	Sys  SyscallMask
	View map[string]uint8
	Pkgs []string
}

type Package struct {
	Name    string
	Id      int
	Sects   []Section
	Dynamic []Section
}

type Section struct {
	Addr uint64
	Size uint64
	Prot uint8
}

func ParseSyscalls(s string) (SyscallMask, error) {
	//TODO(aghosn) implement.
	return 0, nil
}
