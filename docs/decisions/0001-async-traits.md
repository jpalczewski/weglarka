# 0001 — Async w traitach: natywne `async fn` + generyki

Status: przyjęta (fundament, 2026-10-23).

**Decyzja.** Traity z I/O (`PodmanClient`, `Platform`) używają natywnych async w traitach,
zapisanych jako `fn … -> impl Future<Output = …> + Send` (strumienie: `impl Stream + Send`), a kod
je konsumujący jest generyczny (`struct Reconciler<P: PodmanClient>`). Bez `async-trait`, bez `dyn`.

**Dlaczego.** Zero alokacji na wywołanie (priorytet: RAM), brak zależności od makra, `Send` jawnie
w sygnaturze, więc `tokio::spawn` działa. Jest jedna implementacja produkcyjna per trait w danym
procesie (wybór platformy/klienta przy starcie), więc dyspozycja statyczna nic nie kosztuje.
Implementacje mogą pisać zwykłe `async fn` (kompilator sprawdza zgodność z `+ Send`).

**Wyjątek.** Traity, które muszą być kolekcją heterogeniczną (`WebhookSource`: GitHub, później
Forgejo) i `SecretStore` są **synchroniczne i dyn-compatible**: operują na już wczytanych danych
(nagłówki+ciało; mały plik), więc async nie jest potrzebny. `SecretStore` wołany z async przez
`spawn_blocking`.

**Konsekwencje.** Nie da się `Box<dyn PodmanClient>`; testy używają `FakePodman` jako parametru
generycznego. Gdyby kiedyś potrzebny był `dyn`, dokłada się wąski adapter z `async-trait`, bez zmiany traitów.
