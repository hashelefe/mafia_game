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

Telefon mistrza gry pełni rolę serwera i musi mieć stronę otwartą przez całą grę. Telefony łączą się bezpośrednio (WebRTC, biblioteka PeerJS z publicznym brokerem `0.peerjs.com`). Każdy gracz dostaje tylko swoją rolę, więc nie da się podejrzeć cudzych.

Po odświeżeniu strony gracz wraca do gry z tą samą rolą, a mistrz gry do swojego lobby.

Strona musi być dostępna pod adresem https, na przykład przez GitHub Pages: Settings → Pages → Deploy from a branch → wybierz gałąź i katalog `/ (root)`.

Do testów lokalnych można wskazać własny serwer PeerJS: `online.html?peerserver=127.0.0.1:9000`.
