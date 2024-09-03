package descriptor

type Key struct {
	Hex string
}

type TaprootDescriptor struct {
	InternalKey Key
	ScriptTree  []Expression
}
