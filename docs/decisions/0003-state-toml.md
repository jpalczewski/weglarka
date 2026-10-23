# 0003 — Stan runtime w osobnym `state.toml`

Status: przyjęta (sesja b, 2026-10-23).

**Decyzja.** `apps.toml` zawiera wyłącznie stan *pożądany* (zmieniany z API), a stan *runtime*
(przypięty `current` i `previous` digest, `generation`, `spec_hash`, ostatni nieudany deploy)
żyje w `state.toml` obok. Oba pliki pisze tylko demon, atomowo (tmp w tym samym katalogu +
`fsync` + `rename` + `fsync` katalogu), oba czytane z `deny_unknown_fields` i walidacją
niezmienników (np. `spec_hash` wymaga `current`, `previous != current`).

**Dlaczego.** Deploy zmienia stan co kilka minut; mieszanie tego z deklaracją użytkownika
brudziłoby `apps.toml` (diffy, backup, ewentualny przyszły edytor ręczny) i groziło wyścigiem
„API zapisuje spec” vs „deploy przesuwa digest”. Reconcile zbiega do `apps.toml` + `state.toml`;
usunięcie `state.toml` jest bezpieczne (instancje dostaną świeży deploy z pullem).

**Inne ustalenia.**
- Nazwa kontenera = nazwa instancji, sieć per apka = `net-<instancja>` (`labels::container_name/network_name`).
- Zmiana wartości sekretu: odcisk wchodzi do `spec-hash` (`SecretChangePolicy::Immediate`) albo nie
  (`NextDeploy`) — wybór w `ReconcilerOptions`.
- Nieudany deploy zapisuje `failed = { digest, reason }`: webhook nie ponawia znanego złego digestu,
  a nieudany *pierwszy* deploy czeka na ręczne `deploy` (bez pętli ponowień).
- Wszystkie operacje mutujące silnika są serializowane jednym `tokio::sync::Mutex` (prostota,
  brak wyścigów na plikach); bramka zdrowia blokuje inne deploye na czas okna.
