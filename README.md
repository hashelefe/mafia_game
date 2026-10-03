# Mafia: losowanie ról

Dwa tryby gry:

- `index.html` – jeden telefon. Wpisujecie imiona, losujecie role i podajecie telefon po kolei.
- `online.html` – każdy na swoim telefonie. Mistrz gry zakłada lobby i podaje 4-literowy kod, gracze dołączają ze swoich telefonów. Mistrz gry nie dostaje roli: ustawia grę, widzi role wszystkich i dostaje powiadomienie, gdy ktoś użyje karty mocy.

Role: mafia, medyk, szeryf. Pozostali gracze są mieszkańcami. Mafia widzi swoich wspólników.

Karty mocy (opcjonalne): każdy gracz dostaje jedną losową kartę z włączonych. Każda karta działa raz na grę.

Backstory (opcjonalne): każdy gracz losuje jedną ze 120 historii i opowiada ją reszcie pierwszego dnia.

## Pliki

- `shared.js` – role, karty mocy, historie, losowanie i wspólne widoki ustawień.
- `single.js` – tryb jednego telefonu.
- `online.js` – tryb online.
- `style.css` – wygląd obu trybów.

## Tryb online

Telefon mistrza gry trzyma stan lobby i losuje role. Wiadomości idą przez dwa publiczne brokery MQTT naraz (`broker.emqx.io`, `broker.hivemq.com`) po WebSocket z TLS, więc telefony nie łączą się ze sobą bezpośrednio i działają w dowolnych sieciach.

Po odświeżeniu strony gracz wraca do gry z tą samą rolą, a mistrz gry do swojego lobby.

### Bezpieczeństwo

Broker jest publiczny, więc protokół zakłada, że każdy może podsłuchiwać i wysyłać wiadomości.

- **Szyfrowanie end-to-end.** Każda wiadomość (także imię przy dołączaniu) jest szyfrowana AES-GCM kluczem z ECDH P-256 między mistrzem gry a graczem. Broker widzi tylko szyfrogramy.
- **Uwierzytelnienie mistrza gry.** Kod lobby to skrót klucza publicznego mistrza gry, a link zawiera pełny odcisk SHA-256. Gracz przyjmuje tylko pasujący klucz i przypina go na stałe. Drugi pasujący klucz zatrzymuje grę z ostrzeżeniem. Link jest bezpieczniejszy niż ręcznie wpisany kod.
- **Uwierzytelnienie gracza.** Mistrz gry przypina klucz gracza przy pierwszym dołączeniu. Wiadomość z innym kluczem dla tego gracza jest odrzucana.
- **Ochrona przed powtórkami.** Każda wiadomość ma rosnący licznik zapamiętywany po obu stronach (także po odświeżeniu).
- **Walidacja i XSS.** Wszystko z sieci jest sprawdzane co do typu i formatu, tekst trafia na ekran tylko przez `esc()`, z imion usuwane są znaki sterujące.
- **Limity.** Rozmiar wiadomości, liczba wiadomości na sekundę, liczba kosztownych operacji kryptograficznych dla nieznanych nadawców, maksymalnie 30 graczy.
- **Strona.** Content Security Policy bez skryptów inline, Subresource Integrity dla biblioteki MQTT, blokada osadzania w ramce, brak nagłówka Referer.

Do testów lokalnych można wskazać własny broker (tylko na localhost): `online.html?broker=ws://127.0.0.1:8888`.
