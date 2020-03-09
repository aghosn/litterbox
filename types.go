package litterbox

import ()

type SandboxDomain struct {
	Id   string
	Func string
	Sys  SyscallMask
	View map[*Package]uint8
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

func ParseSyscalls(s string) (SyscallMask, error) {
	//TODO(aghosn) implement.
	return 0, nil
}
