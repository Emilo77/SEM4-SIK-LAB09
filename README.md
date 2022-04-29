# Scenariusz 9 - gniazda surowe
## 1. Wprowadzenie

Do tej pory używaliśmy gniazd, które wykorzystywały do komunikacji protokoły TCP i UDP. Tego samego API można używać do programowania protokołów sieciowych niższych warstw. Dzisiejszy scenariusz opisuje komunikację wykorzystującą protokół IP w warstwie sieci: rodziną protokołów ciągle jest `AF_INET`, natomiast typem gniazda jest `SOCK_RAW` (a nie `SOCK_STREAM` czy `SOCK_DGRAM`).

Można również pominąć warstwę sieci, otwierając gniazdo w rodzinie `AF_PACKET`(man packet). Daje to nam bezpośredni dostęp do warstwy łącza, czyli np. możliwość tworzenia pakietów protokołu ARP, ale nie będziemy się zajmować tego typu gniazdami.

Jedynie administrator może otworzyć gniazdo w trybie `SOCK_RAW` (można też kontrolować prawa dostępu bardziej finezyjnie, używając SELinux). Dlatego (umiejętnie wykorzystane) błędy w programach korzystających z `SOCK_RAW` mają zwykle przykre konsekwencje dla systemu.

Gniazda `SOCK_RAW` używa się w dwóch podstawowych trybach. Standardowo system operacyjny tworzy nagłówek IP (dla gniazda stworzonego przez `socket(AF_INET, SOCK_RAW, xxx)` dla `0 < xxx < 255`). Alternatywnie, proces może dostarczać nagłówek IP wraz z danymi do przesłania `(socket(AF_INET, SOCK_RAW, IPPROTO_RAW)`).

## 2. System tworzy nagłówek IP

Napiszemy własną implementację usługi `ping` protokołu ICMP. ICMP korzysta z IP w warstwie sieci, dlatego też będziemy korzystać z nagłówka IP dostarczonego przez system.

### 2.1 Otwieranie gniazda

```c
sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
```

- Proces musi działać z prawami administratora (albo mieć pozwolenie na otwarcie `SOCK_RAW` np. w SELinux).

- Ostatni argument określa protokół; liczba ta będzie wpisywana w tworzonym przez system nagłówku IP w polu`protokół`.

- Po otwarciu gniazda warto zmniejszyć prawa wykonywania (ogranicza to konsekwencje błędów w kodzie). Funkcja `drop_to_nobody()` (`dropnobody.c`) ustawia uid na użytkownika nobody oraz `gid` na grupę główną użytkownika `nobody`, a następnie sprawdza, czy może zmienić `uid` z powrotem na 0, co nie powinno się udać.

### 2.2 Przygotowywanie komunikatu ICMP

Korzystamy z definicji nagłówka ICMP jako `struct icmp (#include <netinet/ip_icmp.h>`).

```c
memset(send_buffer, 0, sizeof(send_buffer));
icmp = (struct icmp *) send_buffer;
icmp->icmp_type = ICMP_ECHO;
icmp->icmp_code = 0;
icmp->icmp_id = htons(getpid() % (1<<16); // process identified by "PID % 2^16"
icmp->icmp_seq = htons(0);              // sequential number
data_len = snprintf(((char*) send_buffer+ICMP_HEADER_LEN),
                    sizeof(send_buffer)-ICMP_HEADER_LEN, "BASIC PING!");
if (data_len < 1)
  syserr("snprintf");
icmp_len = data_len + ICMP_HEADER_LEN; // packet is filled with 0
icmp->icmp_cksum = 0;                  // checksum computed over whole ICMP package
icmp->icmp_cksum = in_cksum((unsigned short*) icmp, icmp_len);
```

- Komunikat jest typu ICMP_ECHO.

- Dane przesyłane w komunikacie to `BASIC PING`!

- Specyfikacja ICMP wymaga obliczenia (internetowej) sumy kontrolnej z całego pakietu (łącznie z danymi). Sumę kontrolną oblicza funkcja `in_cksum()` (`in_cksum.c`).

### 2.3 Wysyłanie komunikatu

- Korzystamy ze standardowej funkcji `sendto()`.

- W adresie celu numer portu ustawiony jest na 0 (nie ma znaczenia).

### 2.4 Odbieranie odpowiedzi

- Korzystamy ze standardowej funkcji `recvfrom()`.

- System dostarcza do procesu kopie wszystkich komunikatów protokołu ICMP.

- Dostarczone pakiety zawierają również nagłówek IP. Nagłówek ten parsujemy, korzystając ze struktury `struct ip`:

```c
ip = (struct ip*) rcv_buffer;
ip_header_len = ip->ip_hl << 2; // IP header len is in 4-byte words
icmp = (struct icmp*) (rcv_buffer + ip_header_len); // ICMP header follows IP
```

### 2.5 Ćwiczenia

- Uruchom program `wireshark` i zaobserwuj działanie `rawping 8.8.8.8` oraz `rawping 127.0.0.1`.
- Dlaczego `rawping 127.0.0.1` odbiera 2 pakiety ICMP? Uruchom `ping 127.0.0.1`.

## 3. Proces dostarcza nagłówek IP

Niektóre programy sieciowe modyfikują pola nagłówka IP, np. `traceroute` zmienia `TTL`. My napiszemy wersję `ping`, która podmienia adres IP źródła (IP spoofing) w wysyłanych pakietach.

## 3.1 Otwieranie gniazda
```c
sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
```
- `IPPROTO_RAW` ustawia dla gniazda sock opcję `IP_HDRINCL`.

- Dane pisane do gniazda `IP_HDRINCL` muszą zawierać nagłówek IP.

### 3.2 Konstrukcja nagłówka IP

Korzystamy z `struct iphdr` (`<netinet/ip.h>`).

```c
ip = (struct iphdr *) send_buffer;
ip->ihl = IP_HEADER_LEN >> 2; // ihl is in 32-byte words
ip->version = 4;              // IPv4
ip->tos = 0;                  // no type of service
ip->frag_off = 0;             // no fragmentation
ip->ttl = 64;                 // standard TTL
ip->protocol = IPPROTO_ICMP;  // carries ICMP
ip->check = 0;                // will be filled up by the system
ip->saddr = spoof_addr.sin_addr.s_addr;
ip->daddr = dst_addr.sin_addr.s_addr;
/* some code omitted */
ip->tot_len = htons(IP_HEADER_LEN + ICMP_HEADER_LEN + data_len);
```

- Nagłówek ma standardową długość 20 bajtów (5 słów), bo nie zawiera opcji.

- Suma kontrolna nagłówka (`ip->check`) zostanie wypełniona przez system operacyjny.

- System nie ingeruje w pola `ip->saddr` i `ip->daddr`.

### 3.3 Ćwiczenia dla chętnych

- Zaobserwuj odpowiedź (pakiet ICMP echo reply) w `wireshark` na twoim komputerze przy wywołaniu `spoofping <twoj_ip> <nieistniejący_ip>`

- Zaobserwuj odpowiedź w `wireshark` na komputerze z adresem `ip2` przy wywołaniu `spoofping <ip1> <ip2>`. Przetestuj `ip2` innego komputera w pracowni oraz komputera spoza sieci MIM UW.

- Zaimplementuj `traceroute`. Program `traceroute` wysyła pakiety ICMP echo request, zwiększając `TTL` od 1 do wartości, dla której otrzymuje odpowiedź ICMP echo reply. Dla każdego `TTL` nasłuchuj odpowiedzi rutera (ICMP Time Exceeded) bądź celu (ICMP echo reply). Wypisz źródłowe adresy IP otrzymywanych odpowiedzi.

- Zaimplementuj podstawową wersję ataku SYN flood. Atak SYN flood polega na wysłaniu wielu pakietów TCP z ustawioną flagą `SYN` i podmienionym adresem źródła. W tym celu musisz skonstruować nagłówek IP oraz nagłówek TCP (`struct tcphdr z <netinet/tcp.h>`). Testując program, pamiętaj, że `SYN flood` na obcy serwer jest działaniem wrogim, łatwo wykrywalnym na ruterach sieci, z której rozpoczynasz atak i, zazwyczaj, nieskutecznym (`SYN cookies`).

- Napisz ping w wersji IPv6. Definicje nagłówka ICMPv6 znajdziesz w `<netinet/icmp6.h>`. Pamiętaj o zmianie stałych.

## 4. Materiały

- W. R. Stevens, "UNIX: Programowanie usług sieciowych", tom 1, rozdział 25.

- http://sock-raw.org/papers/sock_raw

Autorem scenariusza jest Krzysztof Rządca.

## 5. Ćwiczenie punktowane (1 pkt)

W oparciu o program `rawping` napisz program `myping`, w taki sposób, aby działał podobnie do standardowego programu `ping` uruchomionego bez opcji.
- Zadbaj, aby nie kończył się po pierwszej poprawnej odpowiedzi, ale po otrzymaniu sygnału `SIGINT`.

- Dodaj do programu wypisywanie pola `TTL` w odebranych pakietach.

- Dodaj pomiar czasu RTT (ang. round trip time). Wskazówka: tworząc pakiet, w danych wewnątrz pakietu zapisz aktualny czas (skorzystaj z `gettimeofday()`). Odbierając pakiet, zanotuj czas odbioru i oblicz RTT. RTT należy podać w milisekundach z dokładnością do 3 miejsc po przecinku.

Przykładowy wynik:

```c
sudo ./myping 193.0.96.129
36 bytes from 193.0.96.129 icmp_seq=1 ttl=55 time=167.592 ms
36 bytes from 193.0.96.129 icmp_seq=2 ttl=55 time=115.733 ms
36 bytes from 193.0.96.129 icmp_seq=3 ttl=55 time=16.261 ms
36 bytes from 193.0.96.129 icmp_seq=4 ttl=55 time=16.733 ms
^C
```

Porównaj działanie swojego programu z `ping`. Ilość przesłanych/odebranych danych może być dowolna (nie musi to być 64). Nie trzeba wypisywać statystyk po zakończeniu.

Rozwiązania można prezentować w trakcie zajęć nr 9 lub 10.
