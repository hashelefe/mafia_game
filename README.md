# Mafia: losowanie ról

Dwa tryby gry:

- `index.html` – jeden telefon. Wpisujecie imiona, losujecie role i podajecie telefon po kolei.
- `online.html` – każdy na swoim telefonie. Mistrz gry zakłada lobby i podaje 4-literowy kod, gracze dołączają ze swoich telefonów. Mistrz gry nie dostaje roli: ustawia grę, widzi role wszystkich i dostaje powiadomienie, gdy ktoś użyje karty mocy.

Role: mafia, medyk, szeryf. Pozostali gracze są mieszkańcami. Mafia widzi swoich wspólników.

Karty mocy (opcjonalne): każdy gracz dostaje jedną losową kartę z włączonych. Każda karta działa raz na grę.

Backstory (opcjonalne): każdy gracz losuje jedną ze 120 historii i opowiada ją reszcie pierwszego dnia.

## Pliki

- `shared.js` – role, karty mocy, historie, losowanie i wspólne widoki ustawień.
- `style.css` – wygląd obu trybów.

## Tryb online

Telefon mistrza gry trzyma stan lobby i losuje role. Wiadomości między telefonami idą przez dwa publiczne brokery MQTT naraz (`broker.emqx.io`, `broker.hivemq.com`) po WebSocket na https. Telefony nie łączą się ze sobą bezpośrednio, więc działają w dowolnych sieciach: Wi-Fi, LTE, różni operatorzy.

Broker jest publiczny, dlatego wiadomości są szyfrowane (ECDH P-256 + AES-GCM). Każdy gracz dostaje tylko swoją rolę i nikt podsłuchujący brokera jej nie odczyta. Mistrz gry przypina klucz gracza przy pierwszym dołączeniu, więc nie da się podszyć pod gracza.

Po odświeżeniu strony gracz wraca do gry z tą samą rolą, a mistrz gry do swojego lobby.

Strona musi być dostępna pod adresem https, na przykład przez GitHub Pages: Settings → Pages → Deploy from a branch → wybierz gałąź i katalog `/ (root)`.

Do testów lokalnych można wskazać własny broker: `online.html?broker=ws://127.0.0.1:8888`.
