# Non-deployable receiver comparison

`NaiveReceiver` intentionally performs no signature verification, duplicate suppression or
version guard. Every syntactically valid arrival overwrites the stored snapshot. This arm
exists only to compare delivery effects with signature-only and durable reference arms.
Never expose it as a real endpoint. Product package metadata must exclude this namespace;
product code must never import it. No receiver runtime, crash or interoperability checks
have run during Dirty Mode construction.
