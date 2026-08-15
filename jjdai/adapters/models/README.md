# Model-family profiles

One declarative document per model FAMILY, not per checkpoint. A profile
describes what a family needs in order to run correctly — tokenizer, chat
template, architecture id, attention type, MoE routing, supported precisions,
required operators — and nothing about where a particular set of weights came
from. That belongs in the ModelArtifactManifest, which is signed.

Adding a family must not touch the witness contour, the daemon or the
BeingRuntime. If it does, the seam has leaked and the change is a bug in the
adapter layer rather than a new profile.

Validation is strict, and unknown keys are refused: a field this build
ignores is a claim nobody checks, and the manifest would sign the
disagreement.

JSON rather than YAML deliberately — the core stays stdlib-only, and the
document is canonicalized (JCS) before it is hashed, so formatting can never
change its identity.
