//! Klient libpod v6 po unix sockecie (hyper + hyper-util, tokio). **Własność: sesja a.**
//! Implementuje `weglarka_core::podman::PodmanClient`. Modele wire: serde z `#[serde(default)]`,
//! ignorowanie nieznanych pól, tylko używane pola. Testy integracyjne: `tests/` (patrz CLAUDE.md).
