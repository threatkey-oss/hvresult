// Code generated by "stringer -type Mutation"; DO NOT EDIT.

package gitops

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Add-0]
	_ = x[Delete-1]
	_ = x[Change-2]
}

const _Mutation_name = "AddDeleteChange"

var _Mutation_index = [...]uint8{0, 3, 9, 15}

func (i Mutation) String() string {
	if i < 0 || i >= Mutation(len(_Mutation_index)-1) {
		return "Mutation(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Mutation_name[_Mutation_index[i]:_Mutation_index[i+1]]
}
