# What model intake checks cannot show (MG-G4)

`horizon.weights.intake` proves **metadata authenticity**: the bytes on disk, the source revision, the signer, the loader format and the runtime image match a manifest that a trusted key signed. It proves nothing about what the weights *do*.

- A correctly signed, correctly hashed model can still contain a dormant or conditional behaviour (a trigger-dependent backdoor, data poisoning, an unsafe default). A digest match means the model is the one that was approved, not that the approved model is safe.
- `behavioral_trust` is therefore always reported as `UNASSESSED` by intake. It can only be raised by behavioural evidence (P32), and even that evidence is sampling: finite tests with zero observed events bound the rate (P32-13), they do not prove absence.
- Trigger discovery is open-ended: the space of possible triggers (strings, contexts, dates, tool combinations, personas) is not enumerable. Leave-trigger-family-out evaluation (P32-11) measures generalisation to *unseen families in our fixtures*, not to real-world triggers.
- Passing intake does not defend against a malicious or compromised **signer**: the approved key registry is the trust root, and its custody is out of scope for this repository.
- Revocation/quarantine are only as timely as the operator's feed; a model admitted yesterday keeps running until something revokes it.

No report produced by this project may state or imply that an admitted model is free of backdoors.
